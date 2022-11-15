use core::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::process::Child;
mod windows {
    pub(crate) use windows::Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            Threading::{
                OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
            },
        },
    };
}

use super::{Architecture, CopyAddress, ProcessHandleExt, PutAddress, TryIntoProcessHandle};

/// On Windows a `Pid` is a unsigned 32-bit integer.
pub type Pid = u32;
/// On Windows a `ProcessHandle` is a `HANDLE`.
pub type ProcessHandle = (windows::HANDLE, Architecture);

impl ProcessHandleExt for ProcessHandle {
    #[must_use]
    fn check_handle(&self) -> bool {
        self.0.is_invalid()
    }
    #[must_use]
    fn null_type() -> ProcessHandle {
        (windows::HANDLE::default(), Architecture::from_native())
    }
    #[must_use]
    fn set_arch(self, arch: Architecture) -> Self {
        (self.0, arch)
    }
}

/// A `Pid` can be turned into a `ProcessHandle` with `OpenProcess`.
impl TryIntoProcessHandle for Pid {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        Ok((
            unsafe {
                windows::OpenProcess(
                    windows::PROCESS_CREATE_THREAD
                        | windows::PROCESS_QUERY_INFORMATION
                        | windows::PROCESS_VM_READ
                        | windows::PROCESS_VM_WRITE
                        | windows::PROCESS_VM_OPERATION,
                    false,
                    *self,
                )
            }?,
            Architecture::from_native(),
        ))
    }
}

/// A `std::process::Child` has a `HANDLE` from calling `CreateProcess`.
impl TryIntoProcessHandle for Child {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        Ok((
            windows::HANDLE(self.as_raw_handle() as isize),
            Architecture::from_native(),
        ))
    }
}

/// Use `ReadProcessMemory` to read memory from another process on Windows.
impl CopyAddress for ProcessHandle {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn get_pointer_width(&self) -> Architecture {
        self.1
    }

    #[allow(clippy::ptr_as_ptr)]
    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> std::io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        if unsafe {
            windows::ReadProcessMemory(
                self.0,
                addr as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                None,
            )
        } == false
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// Use `WriteProcessMemory` to write memory from another process on Windows.
impl PutAddress for ProcessHandle {
    #[allow(clippy::ptr_as_ptr)]
    fn put_address(&self, addr: usize, buf: &[u8]) -> std::io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if unsafe {
            windows::WriteProcessMemory(
                self.0,
                addr as *const c_void,
                buf.as_ptr().cast(),
                buf.len(),
                None,
            )
        } == false
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
