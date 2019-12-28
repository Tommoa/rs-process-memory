//! This crate provides tools for working with the raw memory of programs, whether that be the
//! implemented by the user.
//!
//! ## Examples
//! ```rust
//! # use process_memory::{Memory, DataMember, Pid, TryIntoProcessHandle};
//! // We have a variable with some value
//! let x = 4_u32;
//! println!("Original x-value: {}", x);
//!
//! // We need to make sure that we get a handle to a process, in this case, ourselves
//! let handle = (std::process::id() as Pid).try_into_process_handle().unwrap();
//! // We make a `DataMember` that has an offset referring to its location in memory
//! let member = DataMember::new_offset(handle, vec![&x as *const _ as usize]);
//! // The memory refered to is now the same
//! println!("Memory location: &x: {}, member: {}", &x as *const _ as usize,
//!     member.get_offset().unwrap());
//! assert_eq!(&x as *const _ as usize, member.get_offset().unwrap());
//! // The value of the member is the same as the variable
//! println!("Member value: {}", member.read().unwrap());
//! assert_eq!(x, member.read().unwrap());
//! // We can write to and modify the value of the variable using the member
//! member.write(&6_u32).unwrap();
//! println!("New x-value: {}", x);
//! assert_eq!(x, 6_u32);
//! ```
//! ```rust
//! # use process_memory::{Memory, LocalMember};
//! // We have a variable with some value
//! let x = 4_u32;
//! println!("Original x-value: {}", x);
//!
//! // We make a `LocalMember` that has an offset referring to its location in memory
//! let member = LocalMember::new_offset(vec![&x as *const _ as usize]);
//! // The memory refered to is now the same
//! println!("Memory location: &x: {}, member: {}", &x as *const _ as usize,
//!     member.get_offset().unwrap());
//! assert_eq!(&x as *const _ as usize, member.get_offset().unwrap());
//! // The value of the member is the same as the variable
//! println!("Member value: {}", member.read().unwrap());
//! assert_eq!(x, member.read().unwrap());
//! // We can write to and modify the value of the variable using the member
//! member.write(&6_u32).unwrap();
//! println!("New x-value: {}", x);
//! assert_eq!(x, 6_u32);
//! ```
#![deny(missing_docs)]
#![deny(unused_results)]
#![deny(unreachable_pub)]
#![deny(missing_debug_implementations)]
#![deny(rust_2018_idioms)]
#![deny(bad_style)]
#![deny(unused)]
#![deny(clippy::pedantic)]

mod data_member;
mod local_member;

pub use data_member::DataMember;
pub use local_member::LocalMember;

/// A trait that defines that it is possible to copy some memory from something represented by a
/// type into a buffer.
pub trait CopyAddress {
    /// Copy an address into user-defined buffer.
    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> std::io::Result<()>;

    /// Get the actual memory location from a set of offsets.
    ///
    /// If [`copy_address`] is already defined, then we can provide a standard implementation that
    /// will work across all operating systems.
    fn get_offset(&self, offsets: &[usize]) -> std::io::Result<usize> {
        // Look ma! No unsafes!
        let mut offset: usize = 0;
        let noffsets: usize = offsets.len();
        for next_offset in offsets.iter().take(noffsets - 1) {
            offset += next_offset;
            let mut copy: [u8; std::mem::size_of::<usize>()] = [0; std::mem::size_of::<usize>()];
            self.copy_address(offset, &mut copy)?;
            offset = usize::from_ne_bytes(copy);
        }

        offset += offsets[noffsets - 1];
        Ok(offset)
    }
}

/// A trait that defines that it is possible to put a buffer into the memory of something
/// represented by a type.
pub trait PutAddress {
    /// Put the data from a user-defined buffer at an address.
    fn put_address(&self, addr: usize, buf: &[u8]) -> std::io::Result<()>;
}

/// A `Pid` is a "process id". Each different platform has a different method for uniquely
/// identifying a process. You can see what the Rust standard library uses for your platform by
/// looking at [`std::process::id`].
pub use platform::Pid;
/// A `ProcessHandle` is a variable type that allows for access to functions that can manipulate
/// other processes. On platforms other than Linux, this is typically a different type than
/// [`Pid`], and thus it is a distinct type here.
pub use platform::ProcessHandle;

/// A trait that attempts to turn some type into a [`ProcessHandle`] so memory can be either copied
/// or placed into it.
pub trait TryIntoProcessHandle {
    /// Attempt to turn a type into a [`ProcessHandle`]. Whilst Linux provides the same type for
    /// [`Pid`]s and [`ProcessHandle`]s, Windows and macOS do not. As such, you need to ensure that
    /// `try_into_process_handle` is called on all [`Pid`]s to ensure cross-platform capabilities.
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle>;
}

impl TryIntoProcessHandle for ProcessHandle {
    fn try_into_process_handle(&self) -> std::io::Result<platform::ProcessHandle> {
        Ok(*self)
    }
}

/// A trait to check that a `ProcessHandle` it valid on various platforms.
pub trait HandleChecker {
    /// Returns `true` if the `ProcessHandle` is not null, and `false` otherwise.
    fn check_handle(&self) -> bool;
    /// Return the null equivalent of a `ProcessHandle`.
    #[must_use]
    fn null_type() -> ProcessHandle;
}

/// A trait that refers to and allows writing to a region of memory in a running program.
pub trait Memory<T> {
    /// Set the offsets to the location in memory. This is used for things such as multi-level
    /// pointers, such as a `Vec<Vec<T>>` or a `Vec<String>`.
    ///
    /// For those sorts of data structures, to access data you need to go via multiple pointers, so
    /// that if an inner region reallocates its size, the variable that is being modified will be
    /// correctly modified.
    fn set_offset(&mut self, new_offsets: Vec<usize>);

    /// Gets the actual total offset from the offsets given by [`Memory::set_offset`].
    ///
    /// This function is safe because it should never internally allow for a null pointer
    /// deference, and instead should return a [`std::io::Error`] with a [`std::io::ErrorKind`] of
    /// `Other`.
    fn get_offset(&self) -> std::io::Result<usize>;

    /// Reads the value of the pointer from the offsets given by [`Memory::set_offset`].
    ///
    /// This function is safe because it should never internally allow for a null pointer
    /// deference, and instead should return a [`std::io::Error`] with a [`std::io::ErrorKind`] of
    /// `Other`.
    fn read(&self) -> std::io::Result<T>;

    /// Writes `value` to the pointer from the offsets given by [`Memory::set_offset`].
    ///
    /// This function is safe because it should never internally allow for a null pointer
    /// deference, and instead should return a [`std::io::Error`] with a [`std::io::ErrorKind`] of
    /// `Other`.
    ///
    /// This function takes a reference instead of taking ownership so if the caller passes in a
    /// [String] or a [Vec], it does not have to be cloned.
    fn write(&self, value: &T) -> std::io::Result<()>;
}

#[cfg(target_os = "linux")]
mod platform {
    use libc;

    use libc::{c_void, iovec, pid_t, process_vm_readv, process_vm_writev};
    use std::process::Child;

    use super::{CopyAddress, HandleChecker, PutAddress, TryIntoProcessHandle};

    /// On Linux a `Pid` is just a `libc::pid_t`.
    pub type Pid = pid_t;
    /// On Linux a `ProcessHandle` is just a `libc::pid_t`.
    pub type ProcessHandle = pid_t;

    impl HandleChecker for ProcessHandle {
        fn check_handle(&self) -> bool {
            *self != 0
        }
        fn null_type() -> Pid {
            0
        }
    }

    /// A [`Child`] always has a pid, which is all we need on Linux.
    impl TryIntoProcessHandle for Child {
        fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
            Ok(self.id() as ProcessHandle)
        }
    }

    impl CopyAddress for ProcessHandle {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> std::io::Result<()> {
            let local_iov = iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf.len(),
            };
            let remote_iov = iovec {
                iov_base: addr as *mut c_void,
                iov_len: buf.len(),
            };
            let result = unsafe { process_vm_readv(*self, &local_iov, 1, &remote_iov, 1, 0) };
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
            let result = unsafe { process_vm_writev(*self, &local_iov, 1, &remote_iov, 1, 0) };
            if result == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use libc;
    use mach;

    use self::mach::kern_return::{kern_return_t, KERN_SUCCESS};
    use self::mach::message::mach_msg_type_number_t;
    use self::mach::port::{mach_port_name_t, mach_port_t, MACH_PORT_NULL};
    use self::mach::vm_types::{mach_vm_address_t, mach_vm_offset_t, mach_vm_size_t};
    use libc::{c_int, pid_t};
    use std::process::Child;

    use super::{CopyAddress, PutAddress, TryIntoProcessHandle};

    #[allow(non_camel_case_types)]
    type vm_map_t = mach_port_t;
    #[allow(non_camel_case_types)]
    type vm_address_t = mach_vm_address_t;
    #[allow(non_camel_case_types)]
    type vm_size_t = mach_vm_size_t;

    /// On OS X a `Pid` is just a `libc::pid_t`.
    pub type Pid = pid_t;
    /// On OS X a `ProcessHandle` is a mach port.
    pub type ProcessHandle = mach_port_name_t;

    extern "C" {
        /// Parameters
        ///  - target_task: The task that we will read from
        ///  - address: The address on the foreign task that we will read
        ///  - size: The number of bytes we want to read
        ///  - data: The local address to read into
        ///  - outsize: The actual size we read
        fn vm_read_overwrite(
            target_task: vm_map_t,
            address: vm_address_t,
            size: vm_size_t,
            data: vm_address_t,
            outsize: &mut vm_size_t,
        ) -> kern_return_t;
        /// Parameters:
        ///  - target_task: The task to which we will write
        ///  - address: The address on the foreign task that we will write to
        ///  - data: The local address of the data we're putting in
        ///  - data_count: The number of bytes we are copying
        fn mach_vm_write(
            target_task: vm_map_t,
            address: vm_address_t,
            data: mach_vm_offset_t,
            data_count: mach_msg_type_number_t,
        ) -> kern_return_t;
    }

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
    ///
    /// Unfortunately spawning a process on OS X does not hand back a mach
    /// port by default (you have to jump through several hoops to get at it),
    /// so there's no simple implementation of `TryIntoProcessHandle` for
    /// `std::process::Child`. This implementation is just provided for symmetry
    /// with other platforms to make writing cross-platform code easier.
    ///
    /// Ideally we would provide an implementation of `std::process::Command::spawn`
    /// that jumped through those hoops and provided the task port.
    impl TryIntoProcessHandle for Child {
        fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
            Pid::try_into_process_handle(&(self.id() as _))
        }
    }

    /// Here we use `mach_vm_write` to write a buffer to some arbitrary address on a process.
    impl PutAddress for ProcessHandle {
        fn put_address(&self, addr: usize, buf: &[u8]) -> std::io::Result<()> {
            let result =
                unsafe { mach_vm_write(*self, addr as _, buf.as_ptr() as _, buf.len() as _) };
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
                vm_read_overwrite(
                    *self,
                    addr as _,
                    buf.len() as _,
                    buf.as_ptr() as _,
                    &mut read_len,
                )
            };

            if result != KERN_SUCCESS {
                return Err(std::io::Error::last_os_error());
            }

            if read_len != buf.len() as _ {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!(
                        "Mismatched read sizes for `vm_read_overwrite` (expected {}, got {})",
                        buf.len(),
                        read_len
                    ),
                ))
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(windows)]
mod platform {
    use winapi;
    use winapi::shared::minwindef;

    use std::mem;
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
                    mem::size_of_val(buf) as winapi::shared::basetsd::SIZE_T,
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
                    mem::size_of_val(buf) as winapi::shared::basetsd::SIZE_T,
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
}

/// Copy `length` bytes of memory at `addr` from `source`.
///
/// This is just a convenient way to call `CopyAddress::copy_address` without
/// having to provide your own buffer.
pub fn copy_address<T>(addr: usize, length: usize, source: &T) -> std::io::Result<Vec<u8>>
where
    T: CopyAddress,
{
    let mut copy = vec![0; length];

    source.copy_address(addr, &mut copy)?;
    Ok(copy)
}
