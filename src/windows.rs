use winapi::shared::minwindef;

use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::ptr;

use super::{Architecture, CopyAddress, ProcessHandleExt, PutAddress, TryIntoProcessHandle};

/// On Windows a `Pid` is a `DWORD`.
pub type Pid = minwindef::DWORD;
/// On Windows a `ProcessHandle` is a `HANDLE`.
pub type ProcessHandle = (winapi::um::winnt::HANDLE, Architecture);

impl ProcessHandleExt for ProcessHandle {
    #[must_use]
    fn check_handle(&self) -> bool {
        self.0.is_null()
    }
    #[must_use]
    fn null_type() -> ProcessHandle {
        (ptr::null_mut(), Architecture::from_native())
    }
    #[must_use]
    fn set_arch(self, arch: Architecture) -> Self {
        (self.0, arch)
    }
}

/// A `Pid` can be turned into a `ProcessHandle` with `OpenProcess`.
impl TryIntoProcessHandle for minwindef::DWORD {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        let handle = unsafe {
            winapi::um::processthreadsapi::OpenProcess(
                winapi::um::winnt::PROCESS_CREATE_THREAD
                    | winapi::um::winnt::PROCESS_QUERY_INFORMATION
                    | winapi::um::winnt::PROCESS_VM_READ
                    | winapi::um::winnt::PROCESS_VM_WRITE
                    | winapi::um::winnt::PROCESS_VM_OPERATION,
                winapi::shared::minwindef::FALSE,
                *self,
            )
        };
        if handle == (0 as winapi::um::winnt::HANDLE) {
            Err(std::io::Error::last_os_error())
        } else {
            Ok((handle, Architecture::from_native()))
        }
    }
}

/// A `std::process::Child` has a `HANDLE` from calling `CreateProcess`.
impl TryIntoProcessHandle for Child {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        Ok((self.as_raw_handle() as _, Architecture::from_native()))
    }
}

/// Use `ReadProcessMemory` to read memory from another process on Windows.
impl CopyAddress for ProcessHandle {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn get_pointer_width(&self) -> Architecture {
        self.1
    }

    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> std::io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        if unsafe {
            winapi::um::memoryapi::ReadProcessMemory(
                self.0,
                addr as minwindef::LPVOID,
                buf.as_mut_ptr() as minwindef::LPVOID,
                buf.len() as winapi::shared::basetsd::SIZE_T,
                ptr::null_mut(),
            )
        } == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// Use `WriteProcessMemory` to write memory from another process on Windows.
impl PutAddress for ProcessHandle {
    fn put_address(&self, addr: usize, buf: &[u8]) -> std::io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if unsafe {
            winapi::um::memoryapi::WriteProcessMemory(
                self.0,
                addr as minwindef::LPVOID,
                buf.as_ptr() as minwindef::LPCVOID,
                buf.len() as winapi::shared::basetsd::SIZE_T,
                ptr::null_mut(),
            )
        } == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
