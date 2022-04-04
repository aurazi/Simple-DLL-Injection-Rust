#![allow(non_camel_case_types)]

use anyhow::Result;
use std::ffi::c_void;
use std::fmt::{Debug, Display};
use std::hint::black_box;
use std::mem;
use std::ptr::copy_nonoverlapping;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use windows::core::PCSTR;

#[cfg(not(target_arch = "x86_64"))]
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, BOOL, HANDLE, LPARAM, WPARAM},
    System::{
        Diagnostics::Debug::{
            ReadProcessMemory, Wow64GetThreadContext, Wow64SetThreadContext, WriteProcessMemory,
            WOW64_CONTEXT,
        },
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{
            VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
            PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
        },
        Threading::{
            CreateRemoteThread, OpenThread, ResumeThread, SuspendThread, WaitForSingleObject,
            THREAD_ALL_ACCESS,
        },
        WindowsProgramming::INFINITE,
    },
    UI::WindowsAndMessaging::PostThreadMessageA,
};

#[cfg(target_arch = "x86_64")]
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, BOOL, HANDLE, LPARAM, WPARAM},
    System::{
        Diagnostics::Debug::{
            GetThreadContext, ReadProcessMemory, SetThreadContext, WriteProcessMemory, CONTEXT,
        },
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{
            VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
            PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
        },
        Threading::{
            CreateRemoteThread, OpenThread, ResumeThread, SuspendThread, WaitForSingleObject,
            THREAD_ALL_ACCESS,
        },
        WindowsProgramming::INFINITE,
    },
    UI::WindowsAndMessaging::PostThreadMessageA,
};

use crate::path::CPath;
use crate::process::{get_thread_id_off_process_id, Process};

const CONTEXT_FULL: u32 = 1_048_587;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum InjectionErrors {
    #[error("Failed to virtual allocate, Last OS Error: {0}")]
    VirtualAllocExError(u32),
    #[error("Failed to write process memory, Last OS Error: {0}")]
    WriteProcessMemoryError(u32),
    #[error("Failed to read process memory, Last OS Error: {0}")]
    ReadProcessMemoryError(u32),
    #[error("Failed to get module handle, Last OS Error: {0}")]
    GetModuleHandleAError(u32),
    #[error("Failed to create remote thread, Last OS Error: {0}")]
    RemoteThreadCreationError(u32),
    #[error("Provided path does not exist")]
    PathDoesNotExistError,
    #[error("Failed to find an available thread")]
    NoThread,
    #[error("Failed to open thread id, {0}, Last OS Error: {1}")]
    OpenThreadError(u32, u32),
    #[error("Failed to suspend thread id, {0}, Last OS Error: {1}")]
    SuspendThreadError(u32, u32),
    #[error("Failed to get thread context of thread id, {0}, Last OS Error: {1}")]
    GetThreadContextError(u32, u32),
    #[error("Failed to set thread context of thread id, {0}, Last OS Error: {1}")]
    SetThreadContextError(u32, u32),
    #[error("Failed to find base address")]
    FailedToFindBaseAddress,
    #[error("Injection Timed Out")]
    TimeOutError,
    #[error("InvalidPlatform - You may have built this on the wrong architecture or suppported architecture")]
    InvalidPlatform,
    #[error("Undocumented error for NtCreateThreadEx, Last OS Error: {0}")]
    NtCreateThreadExError(u32),
}

pub struct Needle<T>(pub Process<T>);

#[derive(Copy, Clone)]
pub enum InjectionMethod<'a> {
    CreateRemoteThreadInject,
    NtCreateThreadEx,
    x64ShellCode(&'a [u8]),
    x64ThreadHijacking,
    x86ShellCode(&'a [u8]),
    x86ThreadHijacking,
}
impl<'a> InjectionMethod<'a> {
    fn is_x64(&self) -> bool {
        use InjectionMethod::*;
        match self {
            x64ShellCode(_) => true,
            x64ThreadHijacking => true,
            _ => false,
        }
    }
}

impl<T> Needle<T>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    pub fn from_process(process: Process<T>) -> Self {
        Self(process)
    }
    pub fn inject(
        &self,
        mut injection_method: InjectionMethod,
        cpath: Option<CPath>,
    ) -> Result<()> {
        if let Some(ref cpath) = cpath {
            if !cpath.path_exists() {
                return Err(InjectionErrors::PathDoesNotExistError.into());
            }
        }
        use InjectionMethod::*;

        // idk, a check ig.
        if !self.0.is_system_x64() && injection_method.is_x64() {
            println!("[Warning]: Architecture is not x64 compatible!\nInjection methods that only support x64 will be automatically set to a x86 version.");
            match injection_method {
                x64ShellCode(shellcode) => injection_method = x86ShellCode(shellcode),
                x64ThreadHijacking => injection_method = x86ThreadHijacking,
                _ => {}
            }
        }

        match injection_method {
            NtCreateThreadEx => unsafe {
                return ntcreatethreadex(&self.0, cpath);
            },
            x86ThreadHijacking => unsafe {
                return x86_threadhijack(&self.0, cpath);
            },
            x86ShellCode(payload) => unsafe {
                return x86_shellcode(&self.0, payload);
            },
            x64ThreadHijacking => unsafe {
                return x64_threadhijack(&self.0, cpath);
            },
            x64ShellCode(payload) => unsafe {
                return x64_shellcode(&self.0, payload);
            },
            CreateRemoteThreadInject => unsafe {
                return load_library(&self.0, cpath);
            },
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn x86_threadhijack<T>(_: &Process<T>, _: Option<CPath>) -> Result<()>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    return Err(InjectionErrors::InvalidPlatform.into());
}

#[cfg(target_arch = "x86_64")]
unsafe fn x86_shellcode<T>(_: &Process<T>, _: &[u8]) -> Result<()>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    return Err(InjectionErrors::InvalidPlatform.into());
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn ntcreatethreadex<T>(_: &Process<T>, _: Option<CPath>) -> Result<()>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    return Err(InjectionErrors::InvalidPlatform.into());
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn x64_shellcode<T>(_: &Process<T>, _: &[u8]) -> Result<()>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    return Err(InjectionErrors::InvalidPlatform.into());
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn x64_threadhijack<T>(_: &Process<T>, _: Option<CPath>) -> Result<()>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    return Err(InjectionErrors::InvalidPlatform.into());
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn x86_threadhijack<T>(process: &Process<T>, cpath: Option<CPath>) -> Result<()>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    let cpath = cpath.unwrap();
    let thread_id = get_thread_id_off_process_id(process.pid);
    if thread_id == 0 {
        return Err(InjectionErrors::NoThread.into());
    }
    let thread_handle = OpenThread(THREAD_ALL_ACCESS, false, thread_id);
    if thread_handle.is_invalid() {
        return Err(InjectionErrors::OpenThreadError(thread_id, GetLastError().0).into());
    }
    if SuspendThread(thread_handle) == u32::MAX {
        // windows returns -1 but windows-rs returns a u32.
        CloseHandle(thread_handle);
        return Err(InjectionErrors::SuspendThreadError(thread_id, GetLastError().0).into());
    }
    let _align_16_start_ = black_box([0xFFFFu16; 1]);
    let mut tcontext: WOW64_CONTEXT = mem::zeroed();
    tcontext.ContextFlags = CONTEXT_FULL;
    if !Wow64GetThreadContext(thread_handle, &mut tcontext).as_bool() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        return Err(InjectionErrors::GetThreadContextError(thread_id, GetLastError().0).into());
    }
    let _align_16_end_ = black_box(&_align_16_start_);
    let dllpath_addr = VirtualAllocEx(
        process.handle,
        core::ptr::null_mut(),
        cpath.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if dllpath_addr.is_null() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        return Err(InjectionErrors::VirtualAllocExError(GetLastError().0).into());
    }
    if WriteProcessMemory(
        process.handle,
        dllpath_addr,
        cpath.as_ptr(),
        cpath.len(),
        core::ptr::null_mut(),
    )
    .0 == 0
    {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::WriteProcessMemoryError(GetLastError().0).into());
    }
    let kernel_module = GetModuleHandleA(PCSTR("kernel32.dll\0".as_ptr()));
    if kernel_module.is_invalid() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::GetModuleHandleAError(GetLastError().0).into());
    }
    let loadlib_addr = GetProcAddress(kernel_module, PCSTR("LoadLibraryW\0".as_ptr()));
    let mut payload = [
        0x00, 0x00, 0x00,
        0x00, // - 0x04 (pCodecave)	-> returned value							;buffer to store returned value (eax)
        0x83, 0xEC, 0x04, // + 0x00				-> sub esp, 0x04							;prepare stack for ret
        0xC7, 0x04, 0x24, 0x00, 0x00, 0x00,
        0x00, // + 0x03 (+ 0x06)		-> mov [esp], OldEip						;store old eip as return address
        0x50, 0x51, 0x52, // + 0x0A				-> psuh e(a/c/d)							;save e(a/c/d)x
        0x9C, // + 0x0D				-> pushfd									;save flags register
        0xB9, 0x00, 0x00, 0x00,
        0x00, // + 0x0E (+ 0x0F)		-> mov ecx, pArg							;load pArg into ecx
        0xB8, 0x00, 0x00, 0x00, 0x00, // + 0x13 (+ 0x14)		-> mov eax, pRoutine
        0x51, // + 0x18				-> push ecx									;push pArg
        0xFF, 0xD0, // + 0x19				-> call eax									;call target function
        0xA3, 0x00, 0x00, 0x00,
        0x00, // + 0x1B (+ 0x1C)		-> mov dword ptr[pCodecave], eax			;store returned value
        0x9D, // + 0x20				-> popfd									;restore flags register
        0x5A, 0x59, 0x58, // + 0x21				-> pop e(d/c/a)								;restore e(d/c/a)x
        0xC6, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x00, // + 0x24 (+ 0x26)		-> mov byte ptr[pCodecave + 0x06], 0x00		;set checkbyte to 0
        0xC3u8,
    ];
    let mut payload_pointer;
    let code_cave = VirtualAllocEx(
        process.handle,
        core::ptr::null_mut(),
        payload.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if code_cave.is_null() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::VirtualAllocExError(GetLastError().0).into());
    }

    // set up shellcode
    let dissected_address;
    let dissected_dllpath_addr;
    let dissected_loadlib_addr;
    let dissected_code_cave_addr;
    let dissected_byte_offset_addr;

    if cfg!(target_endian = "big") {
        dissected_byte_offset_addr = (code_cave as u32 + 0x06).to_be_bytes();
        dissected_code_cave_addr = (code_cave as u32).to_be_bytes();
        dissected_address = tcontext.Eip.to_be_bytes();
        dissected_dllpath_addr = (dllpath_addr as u32).to_be_bytes();
        dissected_loadlib_addr =
            (mem::transmute::<_, *const u32>(loadlib_addr) as u32).to_be_bytes();
    } else {
        dissected_byte_offset_addr = (code_cave as u32 + 0x06).to_le_bytes();
        dissected_code_cave_addr = (code_cave as u32).to_le_bytes();
        dissected_address = tcontext.Eip.to_le_bytes();
        dissected_dllpath_addr = (dllpath_addr as u32).to_le_bytes();
        dissected_loadlib_addr =
            (mem::transmute::<_, *const u32>(loadlib_addr) as u32).to_le_bytes();
    }
    payload_pointer = payload.as_mut_ptr().add(10); // ret
    copy_nonoverlapping(dissected_address.as_ptr(), payload_pointer, 4);
    payload_pointer = payload.as_mut_ptr().add(19); // arg for LoadLibraryW
    copy_nonoverlapping(dissected_dllpath_addr.as_ptr(), payload_pointer, 4);
    payload_pointer = payload.as_mut_ptr().add(24); // LoadLibraryW address
    copy_nonoverlapping(dissected_loadlib_addr.as_ptr(), payload_pointer, 4);
    payload_pointer = payload.as_mut_ptr().add(32); // code cave address
    copy_nonoverlapping(dissected_code_cave_addr.as_ptr(), payload_pointer, 4);
    payload_pointer = payload.as_mut_ptr().add(42); // code cave address + byte offset thing
    copy_nonoverlapping(dissected_byte_offset_addr.as_ptr(), payload_pointer, 4);
    // end of setting up shellcode

    tcontext.Eip = code_cave as u32 + 0x04;
    if WriteProcessMemory(
        process.handle,
        code_cave,
        payload.as_ptr() as *const _,
        payload.len(),
        core::ptr::null_mut(),
    )
    .0 == 0
    {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        VirtualFreeEx(process.handle, code_cave, 0, MEM_RELEASE);
        return Err(InjectionErrors::WriteProcessMemoryError(GetLastError().0).into());
    }

    if !Wow64SetThreadContext(thread_handle, &tcontext).as_bool() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        VirtualFreeEx(process.handle, code_cave, 0, MEM_RELEASE);
        return Err(InjectionErrors::SetThreadContextError(thread_id, GetLastError().0).into());
    }

    PostThreadMessageA(thread_id, 0, WPARAM(0), LPARAM(0));
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);

    let _initial_instant = Instant::now();
    let mut check_byte = 1u8;
    while check_byte != 0 {
        if !ReadProcessMemory(
            process.handle,
            (code_cave as u64 + 0x06) as *mut _,
            &mut check_byte as *mut u8 as *mut _,
            1,
            core::ptr::null_mut(),
        )
        .as_bool()
        {
            return Err(InjectionErrors::ReadProcessMemoryError(GetLastError().0).into());
        }
        if _initial_instant.elapsed().as_millis() > 10000 {
            return Err(InjectionErrors::TimeOutError.into());
        }
        thread::sleep(Duration::from_millis(200));
    }
    VirtualFreeEx(process.handle, code_cave, 0, MEM_RELEASE);
    VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn x86_shellcode<T>(process: &Process<T>, payload: &[u8]) -> Result<()>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    let payload_len = payload.len(); // in bytes
    let codecave = VirtualAllocEx(
        process.handle,
        core::ptr::null_mut(),
        payload_len,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    );
    if codecave.is_null() {
        return Err(InjectionErrors::VirtualAllocExError(GetLastError().0).into());
    }
    if WriteProcessMemory(
        process.handle,
        codecave,
        payload.as_ptr() as *const _,
        payload_len,
        core::ptr::null_mut(),
    )
    .0 == 0
    {
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        return Err(InjectionErrors::WriteProcessMemoryError(GetLastError().0).into());
    }
    let thread_id = get_thread_id_off_process_id(process.pid);
    if thread_id == 0 {
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        return Err(InjectionErrors::NoThread.into());
    }
    let thread_handle = OpenThread(THREAD_ALL_ACCESS, false, thread_id);
    if thread_handle.is_invalid() {
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        return Err(InjectionErrors::OpenThreadError(thread_id, GetLastError().0).into());
    }
    if SuspendThread(thread_handle) == u32::MAX {
        // windows returns -1 but windows-rs returns a u32.
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        CloseHandle(thread_handle);
        return Err(InjectionErrors::SuspendThreadError(thread_id, GetLastError().0).into());
    }
    let mut tcontext: WOW64_CONTEXT = mem::zeroed();
    tcontext.ContextFlags = CONTEXT_FULL;
    if !Wow64GetThreadContext(thread_handle, &mut tcontext).as_bool() {
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        return Err(InjectionErrors::GetThreadContextError(thread_id, GetLastError().0).into());
    }
    tcontext.Eip = codecave as u32;
    if !Wow64SetThreadContext(thread_handle, &tcontext).as_bool() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        return Err(InjectionErrors::SetThreadContextError(thread_id, GetLastError().0).into());
    }

    PostThreadMessageA(thread_id, 0x0018, WPARAM(0), LPARAM(0));
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
unsafe fn x64_shellcode<T>(process: &Process<T>, payload: &[u8]) -> Result<()>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    let payload_len = payload.len(); // in bytes
    let codecave = VirtualAllocEx(
        process.handle,
        core::ptr::null_mut(),
        payload_len,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    );
    if codecave.is_null() {
        return Err(InjectionErrors::VirtualAllocExError(GetLastError().0).into());
    }
    if WriteProcessMemory(
        process.handle,
        codecave,
        payload.as_ptr() as *const _,
        payload_len,
        core::ptr::null_mut(),
    )
    .0 == 0
    {
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        return Err(InjectionErrors::WriteProcessMemoryError(GetLastError().0).into());
    }
    let thread_id = get_thread_id_off_process_id(process.pid);
    if thread_id == 0 {
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        return Err(InjectionErrors::NoThread.into());
    }
    let thread_handle = OpenThread(THREAD_ALL_ACCESS, false, thread_id);
    if thread_handle.is_invalid() {
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        return Err(InjectionErrors::OpenThreadError(thread_id, GetLastError().0).into());
    }
    if SuspendThread(thread_handle) == u32::MAX {
        // windows returns -1 but windows-rs returns a u32.
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        CloseHandle(thread_handle);
        return Err(InjectionErrors::SuspendThreadError(thread_id, GetLastError().0).into());
    }
    let mut tcontext: CONTEXT = mem::zeroed();
    tcontext.ContextFlags = CONTEXT_FULL;
    if !GetThreadContext(thread_handle, &mut tcontext).as_bool() {
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        return Err(InjectionErrors::GetThreadContextError(thread_id, GetLastError().0).into());
    }
    tcontext.Rip = codecave as u64;
    if !SetThreadContext(thread_handle, &tcontext).as_bool() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, codecave, 0, MEM_RELEASE);
        return Err(InjectionErrors::SetThreadContextError(thread_id, GetLastError().0).into());
    }

    PostThreadMessageA(thread_id, 0x0018, WPARAM(0), LPARAM(0));
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
unsafe fn x64_threadhijack<T>(process: &Process<T>, cpath: Option<CPath>) -> Result<()>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    let cpath = cpath.unwrap();
    let thread_id = get_thread_id_off_process_id(process.pid);
    if thread_id == 0 {
        return Err(InjectionErrors::NoThread.into());
    }
    let thread_handle = OpenThread(THREAD_ALL_ACCESS, false, thread_id);
    if thread_handle.is_invalid() {
        return Err(InjectionErrors::OpenThreadError(thread_id, GetLastError().0).into());
    }
    if SuspendThread(thread_handle) == u32::MAX {
        // windows returns -1 but windows-rs returns a u32.
        CloseHandle(thread_handle);
        return Err(InjectionErrors::SuspendThreadError(thread_id, GetLastError().0).into());
    }
    let _align_16_start_ = black_box([0xFFFFu16; 1]);
    let mut tcontext: CONTEXT = mem::zeroed();
    tcontext.ContextFlags = CONTEXT_FULL;
    if !GetThreadContext(thread_handle, &mut tcontext).as_bool() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        return Err(InjectionErrors::GetThreadContextError(thread_id, GetLastError().0).into());
    }
    let _align_16_end_ = black_box(&_align_16_start_);
    let dllpath_addr = VirtualAllocEx(
        process.handle,
        core::ptr::null_mut(),
        cpath.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if dllpath_addr.is_null() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        return Err(InjectionErrors::VirtualAllocExError(GetLastError().0).into());
    }
    if WriteProcessMemory(
        process.handle,
        dllpath_addr,
        cpath.as_ptr(),
        cpath.len(),
        core::ptr::null_mut(),
    )
    .0 == 0
    {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::WriteProcessMemoryError(GetLastError().0).into());
    }
    let kernel_module = GetModuleHandleA(PCSTR("kernel32.dll\0".as_ptr()));
    if kernel_module.is_invalid() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::GetModuleHandleAError(GetLastError().0).into());
    }
    let loadlib_addr = GetProcAddress(kernel_module, PCSTR("LoadLibraryW\0".as_ptr()));
    let mut payload = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // - 0x08			-> returned value
        0x48, 0x83, 0xEC, 0x08, // + 0x00			-> sub rsp, 0x08
        0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, // + 0x04 (+ 0x07)	-> mov [rsp], RipLowPart
        0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00,
        0x00, // + 0x0B (+ 0x0F)	-> mov [rsp + 0x04], RipHighPart
        0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41,
        0x53, // + 0x13			-> push r(a/c/d)x / r (8 - 11)
        0x9C, // + 0x1E			-> pushfq
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // + 0x1F (+ 0x21)	-> mov rax, pRoutine
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // + 0x29 (+ 0x2B)	-> mov rcx, pArg
        0x48, 0x83, 0xEC, 0x20, // + 0x33			-> sub rsp, 0x20
        0xFF, 0xD0, // + 0x37			-> call rax
        0x48, 0x83, 0xC4, 0x20, // + 0x39			-> add rsp, 0x20
        0x48, 0x8D, 0x0D, 0xB4, 0xFF, 0xFF, 0xFF, // + 0x3D			-> lea rcx, [pCodecave]
        0x48, 0x89, 0x01, // + 0x44			-> mov [rcx], rax
        0x9D, // + 0x47			-> popfq
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59,
        0x58, // + 0x48			-> pop r(11-8) / r(d/c/a)x
        0xC6, 0x05, 0xA9, 0xFF, 0xFF, 0xFF, 0x00, // + 0x53			-> mov byte ptr[$ - 0x57], 0
        0xC3u8,
    ];
    let mut payload_pointer;
    let code_cave = VirtualAllocEx(
        process.handle,
        core::ptr::null_mut(),
        payload.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if code_cave.is_null() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::VirtualAllocExError(GetLastError().0).into());
    }

    // set up shellcode
    let high = tcontext.Rip & 0xffffffff;
    let low = (tcontext.Rip >> 0x20) & 0xffffffff;
    let dissected_high;
    let dissected_low;
    let dissected_dllpath_addr;
    let dissected_loadlib_addr;

    if cfg!(target_endian = "big") {
        dissected_high = high.to_be_bytes();
        dissected_low = low.to_be_bytes();
        dissected_dllpath_addr = (dllpath_addr as usize).to_be_bytes();
        dissected_loadlib_addr =
            (mem::transmute::<_, *const usize>(loadlib_addr) as usize).to_be_bytes();
    } else {
        dissected_high = high.to_le_bytes();
        dissected_low = low.to_le_bytes();

        dissected_dllpath_addr = (dllpath_addr as usize).to_le_bytes();
        dissected_loadlib_addr =
            (mem::transmute::<_, *const usize>(loadlib_addr) as usize).to_le_bytes();
    }
    payload_pointer = payload.as_mut_ptr().add(23); // low ret
    copy_nonoverlapping(dissected_low.as_ptr(), payload_pointer, 4);
    payload_pointer = payload.as_mut_ptr().add(15); // high ret
    copy_nonoverlapping(dissected_high.as_ptr(), payload_pointer, 4);
    payload_pointer = payload.as_mut_ptr().add(51); // arg for LoadLibraryW
    copy_nonoverlapping(dissected_dllpath_addr.as_ptr(), payload_pointer, 8);
    payload_pointer = payload.as_mut_ptr().add(41); // LoadLibraryW address
    copy_nonoverlapping(dissected_loadlib_addr.as_ptr(), payload_pointer, 8);
    // end of setting up shellcode

    tcontext.Rip = code_cave as u64 + 0x08;
    if WriteProcessMemory(
        process.handle,
        code_cave,
        payload.as_ptr() as *const _,
        payload.len(),
        core::ptr::null_mut(),
    )
    .0 == 0
    {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        VirtualFreeEx(process.handle, code_cave, 0, MEM_RELEASE);
        return Err(InjectionErrors::WriteProcessMemoryError(GetLastError().0).into());
    }

    if !SetThreadContext(thread_handle, &tcontext).as_bool() {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        VirtualFreeEx(process.handle, code_cave, 0, MEM_RELEASE);
        return Err(InjectionErrors::SetThreadContextError(thread_id, GetLastError().0).into());
    }

    PostThreadMessageA(thread_id, 0, WPARAM(0), LPARAM(0));
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);

    let _initial_instant = Instant::now();
    let mut check_byte = 1u8;
    while check_byte != 0 {
        if !ReadProcessMemory(
            process.handle,
            (code_cave as u64 + 0x0B) as *mut _,
            &mut check_byte as *mut u8 as *mut _,
            1,
            core::ptr::null_mut(),
        )
        .as_bool()
        {
            return Err(InjectionErrors::ReadProcessMemoryError(GetLastError().0).into());
        }
        if _initial_instant.elapsed().as_millis() > 10000 {
            return Err(InjectionErrors::TimeOutError.into());
        }
        thread::sleep(Duration::from_millis(200));
    }
    VirtualFreeEx(process.handle, code_cave, 0, MEM_RELEASE);
    VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
    Ok(())
}

unsafe fn load_library<T>(process: &Process<T>, cpath: Option<CPath>) -> Result<()> {
    let cpath = cpath.unwrap();
    let dllpath_addr = VirtualAllocEx(
        process.handle,
        core::ptr::null_mut(),
        cpath.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if dllpath_addr.is_null() {
        return Err(InjectionErrors::VirtualAllocExError(GetLastError().0).into());
    }
    if WriteProcessMemory(
        process.handle,
        dllpath_addr,
        cpath.as_ptr(),
        cpath.len(),
        core::ptr::null_mut(),
    )
    .0 == 0
    {
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::WriteProcessMemoryError(GetLastError().0).into());
    }
    let kernel_module = GetModuleHandleA(PCSTR("kernel32.dll\0".as_ptr()));
    if kernel_module.is_invalid() {
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::GetModuleHandleAError(GetLastError().0).into());
    }
    let loadlib_addr = GetProcAddress(kernel_module, PCSTR("LoadLibraryW\0".as_ptr()));
    let remote_thread_handle = CreateRemoteThread(
        process.handle,
        core::ptr::null(),
        0,
        mem::transmute(loadlib_addr),
        dllpath_addr,
        0,
        core::ptr::null_mut(),
    );
    if remote_thread_handle.is_invalid() {
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::RemoteThreadCreationError(GetLastError().0).into());
    }
    WaitForSingleObject(remote_thread_handle, INFINITE);
    CloseHandle(remote_thread_handle);
    VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
unsafe fn ntcreatethreadex<T>(process: &Process<T>, cpath: Option<CPath>) -> Result<()>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    let cpath = cpath.unwrap();
    let dllpath_addr = VirtualAllocEx(
        process.handle,
        core::ptr::null_mut(),
        cpath.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if dllpath_addr.is_null() {
        return Err(InjectionErrors::VirtualAllocExError(GetLastError().0).into());
    }
    if WriteProcessMemory(
        process.handle,
        dllpath_addr,
        cpath.as_ptr(),
        cpath.len(),
        core::ptr::null_mut(),
    )
    .0 == 0
    {
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::WriteProcessMemoryError(GetLastError().0).into());
    }
    let ntdll_module = GetModuleHandleA(PCSTR("ntdll.dll\0".as_ptr()));
    if ntdll_module.is_invalid() {
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::GetModuleHandleAError(GetLastError().0).into());
    }
    let kernel_module = GetModuleHandleA(PCSTR("kernel32.dll\0".as_ptr()));
    if kernel_module.is_invalid() {
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::GetModuleHandleAError(GetLastError().0).into());
    }
    let loadlib_addr = GetProcAddress(kernel_module, PCSTR("LoadLibraryW\0".as_ptr()));
    let ncreate_addr = GetProcAddress(ntdll_module, PCSTR("NtCreateThreadEx\0".as_ptr()));
    type PHANDLE = *mut HANDLE;
    type ACCESS_MASK = u32;
    type NTSTATUS = i32;
    type LPVOID = *mut c_void;
    type DWORD = u32;
    type LPTHREAD_START_ROUTINE = Option<unsafe extern "system" fn(LPVOID) -> DWORD>;
    // because silly windows-rs dont got them

    type nt_thread_signature = unsafe extern "C" fn(
        PHANDLE,
        ACCESS_MASK,
        LPVOID,
        HANDLE,
        LPTHREAD_START_ROUTINE,
        LPVOID,
        BOOL,
        DWORD, // stack size is dependant on architecture
        DWORD,
        DWORD,
        LPVOID,
    ) -> NTSTATUS;
    let ncreate_addr = mem::transmute::<_, nt_thread_signature>(ncreate_addr);
    let mut r_thread: HANDLE = mem::zeroed();

    ncreate_addr(
        &mut r_thread,
        THREAD_ALL_ACCESS.0,
        core::ptr::null_mut(),
        process.handle,
        mem::transmute(loadlib_addr),
        dllpath_addr,
        BOOL(0),
        0,
        0,
        0,
        core::ptr::null_mut(),
    );
    if r_thread.is_invalid() {
        VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);
        return Err(InjectionErrors::NtCreateThreadExError(GetLastError().0).into());
    }
    // idk why WaitForSingleObject doesn't work here... its just NtCreateThreadEx is undocumented...
    // works for 64 bit tho so idk!!

    WaitForSingleObject(r_thread, INFINITE);
    CloseHandle(r_thread);
    VirtualFreeEx(process.handle, dllpath_addr, 0, MEM_RELEASE);

    Ok(())
}
