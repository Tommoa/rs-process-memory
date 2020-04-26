use libc;
use mach;

use self::mach::kern_return::KERN_SUCCESS;
use self::mach::port::{mach_port_name_t, MACH_PORT_NULL};
use libc::{c_int, pid_t};
use std::process::Child;

use super::{CopyAddress, PutAddress, TryIntoProcessHandle};

/// On OS X a `Pid` is just a `libc::pid_t`.
pub type Pid = pid_t;
/// On OS X a `ProcessHandle` is a mach port.
pub type ProcessHandle = mach_port_name_t;

/// A small wrapper around `task_for_pid`, which taskes a pid returns the mach port representing its task.
fn task_for_pid(pid: Pid) -> std::io::Result<mach_port_name_t> {
    let mut task: mach_port_name_t = MACH_PORT_NULL;

    unsafe {
        let result =
            mach::traps::task_for_pid(mach::traps::mach_task_self(), pid as c_int, &mut task);
        if result != KERN_SUCCESS {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(task)
}

/// `Pid` can be turned into a `ProcessHandle` with `task_for_pid`.
impl TryIntoProcessHandle for Pid {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        task_for_pid(*self)
    }
}

/// This `TryIntoProcessHandle` impl simply calls the `TryIntoProcessHandle` impl for `Pid`.
impl TryIntoProcessHandle for Child {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        #[allow(clippy::cast_possible_wrap)]
        Pid::try_into_process_handle(&(self.id() as _))
    }
}

/// Here we use `mach_vm_write` to write a buffer to some arbitrary address on a process.
impl PutAddress for ProcessHandle {
    fn put_address(&self, addr: usize, buf: &[u8]) -> std::io::Result<()> {
        #[allow(clippy::cast_possible_truncation)]
        let result =
            unsafe { mach::vm::mach_vm_write(*self, addr as _, buf.as_ptr() as _, buf.len() as _) };
        if result != KERN_SUCCESS {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Use `vm_read_overwrite` to read memory from another process on OS X.
///
/// We use `vm_read_overwrite` instead of `vm_read` because it can handle non-aligned reads and
/// won't read an entire page.
impl CopyAddress for ProcessHandle {
    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> std::io::Result<()> {
        let mut read_len: u64 = 0;
        let result = unsafe {
            mach::vm::mach_vm_read_overwrite(
                *self,
                addr as _,
                buf.len() as _,
                buf.as_mut_ptr() as _,
                &mut read_len,
            )
        };

        if result != KERN_SUCCESS {
            return Err(std::io::Error::last_os_error());
        }

        if read_len == buf.len() as _ {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!(
                    "Mismatched read sizes for `vm_read_overwrite` (expected {}, got {})",
                    buf.len(),
                    read_len
                ),
            ))
        }
    }
}
