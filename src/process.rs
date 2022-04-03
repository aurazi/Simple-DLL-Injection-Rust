use anyhow::Result;
use std::ffi::{self, CStr};
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::mem;
use std::ops;
use thiserror::Error;
use widestring::U16CString;
use windows::core::PCWSTR;
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, BOOL, HANDLE, HINSTANCE},
    Storage::FileSystem::GetFullPathNameW,
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, Thread32First, Thread32Next,
            PROCESSENTRY32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
        },
        ProcessStatus::{
            K32EnumProcessModules, K32GetModuleFileNameExA, K32GetModuleInformation,
            K32GetProcessImageFileNameA, MODULEINFO,
        },
        SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO},
        Threading::{IsWow64Process, OpenProcess, PROCESS_ACCESS_RIGHTS},
    },
};

#[derive(Error, Debug)]
pub enum ProcessErrors<T> {
    #[error("Failed to find PID for process {0}")]
    PIDSearchFailure(T),
    #[error("Failed to open process, PID {0}, ACCESS_RIGHTS: {1}, LAST_OS_ERROR: {2}")]
    OpenProcessFailure(u32, u32, u32),
    #[error("Failed to construct full path for {0}")]
    FullPathNameFailure(T),
    #[error("Failed to check if process is 64-bit {0}")]
    IsWow64Error(u32),
}

#[allow(non_snake_case)]
pub fn __GetFullPathNameW<T: AsRef<str> + Send + Sync + Display + Debug + 'static>(
    module_name: T,
) -> Result<widestring::U16CString> {
    let c_module_name = U16CString::from_str(&module_name).unwrap();
    let mut path_buffer = [0; 1024 as usize];
    unsafe {
        if GetFullPathNameW(
            PCWSTR(c_module_name.as_ptr()),
            &mut path_buffer,
            core::ptr::null_mut(),
        ) == 0
        {
            return Err(ProcessErrors::FullPathNameFailure(module_name).into());
        }
        Ok(U16CString::from_ptr_str(path_buffer.as_ptr()))
    }
}

#[allow(dead_code)]
pub struct Process<T> {
    pub handle: HANDLE,
    pub pid: u32,
    __marker: PhantomData<T>,
}
impl<T> Process<T>
where
    T: AsRef<str> + ToString + Send + Sync + Debug + Display + 'static,
{
    pub fn is_system_x64(&self) -> bool {
        unsafe {
            let mut sys_info: SYSTEM_INFO = mem::zeroed();
            GetNativeSystemInfo(&mut sys_info as *mut _);
            return sys_info.Anonymous.Anonymous.wProcessorArchitecture.0 == 9;
        }
    }
    pub fn is_x64_compatible(&self) -> Result<bool> {
        let is_process_x64 = self.is_x64_process();
        match is_process_x64 {
            Ok(is_process_x64) => {
                if self.is_system_x64() {
                    return Ok(is_process_x64);
                } else {
                    return Ok(false);
                }
            }
            Err(_) => return is_process_x64,
        }
    }
    pub fn is_x64_process(&self) -> Result<bool> {
        unsafe {
            let mut is_bool: BOOL = mem::zeroed();
            if !IsWow64Process(self.handle, &mut is_bool as *mut _).as_bool() {
                return Err(ProcessErrors::<T>::IsWow64Error(GetLastError().0).into());
            }
            Ok(!is_bool.as_bool())
        }
    }
    pub fn open_from_process_id(
        access_rights: PROCESS_ACCESS_RIGHTS,
        module_name: T,
        process_id: u32,
    ) -> Result<Self> {
        if process_id != 0 {
            let process_handle = unsafe { OpenProcess(access_rights, false, process_id) };
            if process_handle.is_invalid() {
                return Err(ProcessErrors::<&str>::OpenProcessFailure(
                    // work around lol
                    process_id,
                    access_rights.0,
                    unsafe { GetLastError().0 },
                )
                .into());
            }
            return Ok(Self {
                handle: process_handle,
                pid: process_id,
                __marker: PhantomData,
            });
        }
        Err(ProcessErrors::PIDSearchFailure(module_name).into())
    }
    pub fn open_from_process_name(
        access_rights: PROCESS_ACCESS_RIGHTS,
        module_name: T,
    ) -> Result<Self>
    where
        &'static str: PartialEq<T>,
    {
        let process_id = unsafe { find_process_id_by_process_name(&module_name) };
        return Self::open_from_process_id(access_rights, module_name, process_id);
    }
}
impl<T> ops::Drop for Process<T> {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

pub unsafe fn find_process_id_by_process_name<T: AsRef<str>>(module_name: &T) -> u32
where
    &'static str: PartialEq<T>,
{
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot.is_invalid() {
        return 0;
    }

    let mut entry: PROCESSENTRY32 = mem::zeroed();
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    if Process32First(snapshot, &mut entry).as_bool() {
        while Process32Next(snapshot, &mut entry).as_bool() {
            let found_module_name = ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as _)
                .to_str()
                .unwrap();
            if &found_module_name == module_name {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    0
}
pub unsafe fn get_thread_id_off_process_id(pid: u32) -> u32 {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if snapshot.is_invalid() {
        return 0;
    }

    let mut entry: THREADENTRY32 = mem::zeroed();
    entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;

    if Thread32First(snapshot, &mut entry).as_bool() {
        while Thread32Next(snapshot, &mut entry).as_bool() {
            if entry.th32OwnerProcessID == pid {
                CloseHandle(snapshot);
                return entry.th32ThreadID;
            }
        }
    }

    CloseHandle(snapshot);
    0
}
pub unsafe fn get_base_address_of_process(process_handle: HANDLE) -> usize {
    let mut executable_name = [0u8; 255];
    if K32GetProcessImageFileNameA(process_handle, &mut executable_name) == 0 {
        return 0;
    }
    let cexecutable_name = CStr::from_ptr(executable_name.as_ptr() as *const _);
    let strexecutable_name = cexecutable_name.to_str().unwrap();

    let mut modules = [mem::zeroed::<HINSTANCE>(); 1024];
    let mut cb = mem::zeroed::<u32>();

    if K32EnumProcessModules(
        process_handle,
        modules.as_mut_ptr(),
        mem::size_of_val(&modules) as u32,
        &mut cb,
    )
    .as_bool()
    {
        for hmodule in modules.into_iter() {
            if hmodule.is_invalid() {
                continue;
            }
            let mut hmodulefn = [0; 255];
            if K32GetModuleFileNameExA(process_handle, hmodule, &mut hmodulefn) != 0 {
                let needle = CStr::from_ptr(hmodulefn.as_ptr().add(2) as *const _)
                    .to_str()
                    .unwrap();
                if strexecutable_name.ends_with(needle) {
                    let mut module_info = mem::zeroed::<MODULEINFO>();
                    if !K32GetModuleInformation(
                        process_handle,
                        hmodule,
                        &mut module_info,
                        mem::size_of::<MODULEINFO>() as u32,
                    )
                    .as_bool()
                    {
                        dbg!("well this failed lol");
                        continue;
                    }
                    return module_info.lpBaseOfDll as usize;
                }
            }
        }
    }
    0
}
