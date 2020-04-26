use winapi::shared::minwindef;

use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::ptr;

use super::{CopyAddress, HandleChecker, PutAddress, TryIntoProcessHandle};

/// On Windows a `Pid` is a `DWORD`.
pub type Pid = minwindef::DWORD;
/// On Windows a `ProcessHandle` is a `HANDLE`.
pub type ProcessHandle = winapi::um::winnt::HANDLE;

impl HandleChecker for ProcessHandle {
    fn check_handle(&self) -> bool {
        self.is_null()
    }
    #[must_use]
    fn null_type() -> ProcessHandle {
        ptr::null_mut()
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
        if handle == (0 as ProcessHandle) {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(handle)
        }
    }
}

/// A `std::process::Child` has a `HANDLE` from calling `CreateProcess`.
impl TryIntoProcessHandle for Child {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        Ok(self.as_raw_handle() as ProcessHandle)
    }
}

/// Use `ReadProcessMemory` to read memory from another process on Windows.
impl CopyAddress for ProcessHandle {
    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> std::io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        if unsafe {
            winapi::um::memoryapi::ReadProcessMemory(
                *self,
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
                *self,
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
