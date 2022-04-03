#![feature(bench_black_box)]

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

fn main() -> Result<()> {
    println!("Input process name, along with extension:");
    let mut process_target = String::new();
    io::stdin().read_line(&mut process_target)?;
    let process =
        Process::open_from_process_name(PROCESS_ALL_ACCESS, process_target.trim().to_string())?;

    println!(
        "\nSelected process: {}\nPID: {}\n",
        process_target.trim(),
        process.pid
    );

    println!("Choose injection method (x64 only):\n[a] LoadLibrary\n[b] ThreadHijacking");
    let injection_method;
    loop {
        process_target.clear();
        io::stdin().read_line(&mut process_target)?;
        process_target = process_target.trim().to_lowercase();
        match &process_target[..] {
            "a" => {
                println!("[LoadLibrary] injection method selected\n");
                injection_method = InjectionMethod::LoadLibrary;
                break;
            }
            "b" => {
                println!("[ThreadHijacking] injection method selected\n");
                injection_method = InjectionMethod::x64ThreadHijacking;
                break;
            }
            _ => {
                println!("Please check your input and try again");
                continue;
            }
        }
    }

    let cpath = CPath::new(__GetFullPathNameW("64_bit.dll")?);

    let needle = Needle::from_process(process);
    needle.inject(injection_method, Some(cpath))?;

    println!("\nFinished injection and closed handles.");
    thread::sleep(time::Duration::from_secs(3));

    Ok(())
}
