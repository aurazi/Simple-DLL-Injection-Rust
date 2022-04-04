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

#[cfg(target_arch = "x86_64")]
const INJECTION_METHODS_CFG: [InjectionMethod; 3] = [
    InjectionMethod::LoadLibrary,
    InjectionMethod::x64ThreadHijacking,
    InjectionMethod::NtCreateThreadEx,
];

#[cfg(not(target_arch = "x86_64"))]
const INJECTION_METHODS_CFG: [InjectionMethod; 2] = [
    InjectionMethod::LoadLibrary,
    InjectionMethod::x86ThreadHijacking,
];

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

    if cfg!(target_arch = "x86_64") {
        println!(
            "Choose injection method:\n[a] LoadLibrary\n[b] ThreadHijacking\n[c] NtCreateThreadEx"
        );
    } else {
        println!("Choose injection method:\n[a] LoadLibrary\n[b] ThreadHijacking");
    }
    let injection_method;
    loop {
        process_target.clear();
        io::stdin().read_line(&mut process_target)?;
        process_target = process_target.trim().to_lowercase();
        match &process_target[..] {
            "a" => {
                println!("[LoadLibrary] injection method selected\n");
                injection_method = INJECTION_METHODS_CFG[0];
                break;
            }
            "b" => {
                println!("[ThreadHijacking] injection method selected\n");
                injection_method = INJECTION_METHODS_CFG[1];
                break;
            }
            #[cfg(target_arch = "x86_64")]
            "c" => {
                println!("[NtCreateThreadEx] injection method selected\n");
                injection_method = INJECTION_METHODS_CFG[2];
                break;
            }
            _ => {
                println!("Please check your input and try again");
                continue;
            }
        }
    }
    println!("Input DLL name with extension");
    process_target.clear();
    io::stdin().read_line(&mut process_target)?;
    let dll = process_target.trim().to_string();

    let cpath = CPath::new(__GetFullPathNameW(dll)?);

    let needle = Needle::from_process(process);
    needle.inject(injection_method, Some(cpath))?;

    println!("\nFinished injection and closed handles.");
    thread::sleep(time::Duration::from_secs(3));

    Ok(())
}
