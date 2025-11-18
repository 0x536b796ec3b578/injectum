use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId, SleepEx};

fn main() {
    unsafe {
        let pid = GetCurrentProcessId();
        let tid = GetCurrentThreadId();

        println!("PID: {}", pid);
        println!("Thread ID: {}", tid);
        println!("Entering alertable sleep loop…");

        loop {
            SleepEx(1000, true);
        }
    }
}
