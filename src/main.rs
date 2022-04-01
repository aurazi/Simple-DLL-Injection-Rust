mod needle;
mod path;
mod process;

use anyhow::Result;
use std::io;
use std::thread;
use std::time;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;

use needle::{InjectionMethod, Needle};
use path::CPath;
use process::{Process, __GetFullPathNameW};

/*
Sources Used:

https://stackoverflow.com/questions/865152/how-can-i-get-a-process-handle-by-its-name-in-c
https://en.wikipedia.org/wiki/DLL_injection

*/

fn main() -> Result<()> {
    println!("Input process name, along with extension:");
    let mut process_target = String::new();
    io::stdin().read_line(&mut process_target)?;

    let process =
        Process::open_from_process_name(PROCESS_ALL_ACCESS, process_target.trim().to_string())?;

    let cpath = CPath::new(__GetFullPathNameW("64_bit.dll")?);

    let needle = Needle::from_process(process);
    needle.inject(InjectionMethod::LoadLibrary, cpath)?;

    println!("\nFinished injection and closed handles.");
    thread::sleep(time::Duration::from_secs(3));

    Ok(())
}
