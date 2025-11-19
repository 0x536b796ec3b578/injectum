use std::ffi::c_void;
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_ALL_AMD64;
#[cfg(target_arch = "arm")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_ALL_ARM;
#[cfg(target_arch = "aarch64")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_ALL_ARM64;
#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_ALL_X86;
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Diagnostics::Debug::{
                CONTEXT, CONTEXT_FLAGS, GetThreadContext, SetThreadContext, WriteProcessMemory,
            },
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc},
            Threading::{
                CREATE_SUSPENDED, CreateThread, GetCurrentProcess, INFINITE, ResumeThread, Sleep,
                THREAD_CREATION_FLAGS, WaitForSingleObject,
            },
        },
    },
    core::Result,
};

#[cfg(target_arch = "x86_64")]
const CONTEXT_ALL: CONTEXT_FLAGS = CONTEXT_ALL_AMD64;
#[cfg(target_arch = "x86")]
const CONTEXT_ALL: CONTEXT_FLAGS = CONTEXT_ALL_X86;
#[cfg(target_arch = "arm")]
const CONTEXT_ALL: CONTEXT_FLAGS = CONTEXT_ALL_ARM;
#[cfg(target_arch = "aarch64")]
const CONTEXT_ALL: CONTEXT_FLAGS = CONTEXT_ALL_ARM64;

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_invalid() {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn main() -> Result<()> {
    let shellcode: [u8; 460] = [0x00; 460];

    let h_memory = unsafe {
        VirtualAlloc(
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if h_memory.is_null() {
        return Ok(());
    }

    let mut bytes_written = 0usize;

    unsafe {
        WriteProcessMemory(
            GetCurrentProcess(),
            h_memory,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            Some(&mut bytes_written),
        )?
    }

    let mut thread_id = 0u32;

    let h_thread = HandleGuard(unsafe {
        CreateThread(
            None,
            0,
            Some(dummy),
            None,
            THREAD_CREATION_FLAGS(CREATE_SUSPENDED.0),
            Some(&mut thread_id),
        )?
    });

    unsafe { Sleep(5_000) }

    let mut ctx = CONTEXT {
        ContextFlags: CONTEXT_ALL,
        ..Default::default()
    };

    unsafe { GetThreadContext(h_thread.0, &mut ctx)? }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        ctx.Rip = h_memory as u64;
    }

    #[cfg(target_arch = "x86")]
    {
        ctx.Eip = h_memory as u32;
    }

    #[cfg(target_arch = "arm")]
    {
        ctx.Pc = h_memory as u32;
    }

    unsafe {
        SetThreadContext(h_thread.0, &ctx)?;
        ResumeThread(h_thread.0);
        WaitForSingleObject(h_thread.0, INFINITE);
    }

    Ok(())
}

extern "system" fn dummy(_param: *mut c_void) -> u32 {
    0
}
