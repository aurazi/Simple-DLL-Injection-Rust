use anyhow::Result;
use std::mem;
use thiserror::Error;
use windows::core::PCSTR;
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError},
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{
            VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
        },
        Threading::{CreateRemoteThread, WaitForSingleObject},
        WindowsProgramming::INFINITE,
    },
};

use crate::path::CPath;
use crate::process::Process;

#[derive(Error, Debug)]
pub enum InjectionErrors {
    #[error("Failed to virtual allocate, Last OS Error: {0}")]
    VirtualAllocExError(u32),
    #[error("Failed to write process memory, Last OS Error: {0}")]
    WriteProcessMemoryError(u32),
    #[error("Failed to get module handle, Last OS Error: {0}")]
    GetModuleHandleAError(u32),
    #[error("Failed to create remote thread, Last OS Error: {0}")]
    RemoteThreadCreationError(u32),
    #[error("Provided path does not exist")]
    PathDoesNotExistError,
}

pub struct Needle<T>(pub Process<T>);
pub enum InjectionMethod {
    LoadLibrary,
}

impl<T> Needle<T> {
    pub fn from_process(process: Process<T>) -> Self {
        Self(process)
    }
    pub fn inject(&self, injection_method: InjectionMethod, cpath: CPath) -> Result<()> {
        if !cpath.path_exists() {
            return Err(InjectionErrors::PathDoesNotExistError.into());
        }

        use InjectionMethod::*;
        match injection_method {
            LoadLibrary => unsafe {
                let dllpath_addr = VirtualAllocEx(
                    self.0.handle,
                    core::ptr::null_mut(),
                    cpath.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );
                if dllpath_addr.is_null() {
                    return Err(InjectionErrors::VirtualAllocExError(GetLastError().0).into());
                }
                if WriteProcessMemory(
                    self.0.handle,
                    dllpath_addr,
                    cpath.as_ptr(),
                    cpath.len(),
                    core::ptr::null_mut(),
                )
                .0 == 0
                {
                    VirtualFreeEx(self.0.handle, dllpath_addr, 0, MEM_RELEASE);
                    return Err(InjectionErrors::WriteProcessMemoryError(GetLastError().0).into());
                }
                let kernel_module = GetModuleHandleA(PCSTR("kernel32.dll\0".as_ptr()));
                if kernel_module.is_invalid() {
                    VirtualFreeEx(self.0.handle, dllpath_addr, 0, MEM_RELEASE);
                    return Err(InjectionErrors::GetModuleHandleAError(GetLastError().0).into());
                }
                let loadlib_addr = GetProcAddress(kernel_module, PCSTR("LoadLibraryW\0".as_ptr()));
                let remote_thread_handle = CreateRemoteThread(
                    self.0.handle,
                    core::ptr::null(),
                    0,
                    mem::transmute(loadlib_addr),
                    dllpath_addr,
                    0,
                    core::ptr::null_mut(),
                );
                if remote_thread_handle.is_invalid() {
                    VirtualFreeEx(self.0.handle, dllpath_addr, 0, MEM_RELEASE);
                    return Err(InjectionErrors::RemoteThreadCreationError(GetLastError().0).into());
                }
                WaitForSingleObject(remote_thread_handle, INFINITE);
                CloseHandle(remote_thread_handle);
                VirtualFreeEx(self.0.handle, dllpath_addr, 0, MEM_RELEASE);
            },
        }
        Ok(())
    }
}
