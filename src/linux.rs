use libc::{c_void, iovec, pid_t, process_vm_readv, process_vm_writev};
use std::process::Child;

use super::{Architecture, CopyAddress, ProcessHandleExt, PutAddress, TryIntoProcessHandle};

/// On Linux a `Pid` is just a `libc::pid_t`.
pub type Pid = pid_t;
/// On Linux a `ProcessHandle` is just a `libc::pid_t`.
pub type ProcessHandle = (Pid, Architecture);

impl ProcessHandleExt for ProcessHandle {
    #[must_use]
    fn check_handle(&self) -> bool {
        self.0 != 0
    }
    #[must_use]
    fn null_type() -> Self {
        (0, Architecture::from_native())
    }
    #[must_use]
    fn set_arch(self, arch: Architecture) -> Self {
        (self.0, arch)
    }
}

/// A `Child` always has a pid, which is all we need on Linux.
impl TryIntoProcessHandle for Child {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        #[allow(clippy::cast_possible_wrap)]
        Ok((self.id() as Pid, Architecture::from_native()))
    }
}

impl TryIntoProcessHandle for Pid {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        Ok((*self, Architecture::from_native()))
    }
}

impl CopyAddress for ProcessHandle {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn get_pointer_width(&self) -> Architecture {
        self.1
    }

    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> std::io::Result<()> {
        let local_iov = iovec {
            iov_base: buf.as_mut_ptr().cast::<c_void>(),
            iov_len: buf.len(),
        };
        let remote_iov = iovec {
            iov_base: addr as *mut c_void,
            iov_len: buf.len(),
        };
        let result = unsafe { process_vm_readv(self.0, &local_iov, 1, &remote_iov, 1, 0) };
        if result == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl PutAddress for ProcessHandle {
    fn put_address(&self, addr: usize, buf: &[u8]) -> std::io::Result<()> {
        let local_iov = iovec {
            iov_base: buf.as_ptr() as *mut c_void,
            iov_len: buf.len(),
        };
        let remote_iov = iovec {
            iov_base: addr as *mut c_void,
            iov_len: buf.len(),
        };
        let result = unsafe { process_vm_writev(self.0, &local_iov, 1, &remote_iov, 1, 0) };
        if result == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
