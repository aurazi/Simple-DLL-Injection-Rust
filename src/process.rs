use anyhow::Result;
use std::ffi;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::mem;
use std::ops;
use thiserror::Error;
use widestring::U16CString;
use windows::core::PCWSTR;
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE},
    Storage::FileSystem::GetFullPathNameW,
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS},
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
}

#[allow(non_snake_case)]
pub fn __GetFullPathNameW<T: AsRef<str> + Send + Sync + Display + Debug + 'static>(
    module_name: T,
) -> Result<widestring::U16CString> {
    let c_module_name = U16CString::from_str(&module_name).unwrap();
    let mut path_buffer = [0; 255 as usize];
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
    let mut entry: PROCESSENTRY32 = mem::zeroed();
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

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
