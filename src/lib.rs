/// This crate is based off read-process-memory by luser. I have added the ability
/// to write to process memory as well (but only for Windows so far) so that it can
/// be used as a general purpose memory accesser
extern crate libc;

#[cfg(windows)]
extern crate winapi;


use std::io;

pub trait CopyAddress {
    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()>;
}

pub trait PutAddress {
    fn put_address(&self, addr: usize, buf: &[u8]) -> io::Result<()>;
    fn get_offset(&self, offsets: &Vec<usize>) -> usize;
}

pub use platform::Pid;
pub use platform::ProcessHandle;

pub trait Inject {
    fn inject(&self, dll: std::path::PathBuf) -> io::Result<ProcessHandle>;
}

pub trait TryIntoProcessHandle {
    fn try_into_process_handle(&self) -> io::Result<ProcessHandle>;
}

impl TryIntoProcessHandle for ProcessHandle {
    fn try_into_process_handle(&self) -> io::Result<platform::ProcessHandle> {
        Ok(*self)
    }
}

pub trait HandleChecker { 
    fn check_handle(&self) -> bool;
    #[cfg(target_os="linux")]
    fn null_type() -> libc::pid_t;
    #[cfg(windows)]
    fn null_type() -> winapi::HANDLE;
}

#[cfg(target_os="linux")]
pub mod platform {
    use libc::{pid_t, c_void, iovec, process_vm_readv, process_vm_writev};
    use std::io;
    use std::process::Child;

    use super::{CopyAddress, TryIntoProcessHandle, PutAddress, HandleChecker};

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

    /// A `process::Child` always has a pid, which is all we need on Linux.
    impl TryIntoProcessHandle for Child {
        fn try_into_process_handle(&self) -> io::Result<ProcessHandle> {
            Ok(self.id() as pid_t)
        }
    } 

    impl CopyAddress for ProcessHandle {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            let local_iov = iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf.len(),
            };
            let remote_iov = iovec {
                iov_base: addr as *mut c_void,
                iov_len: buf.len(),
            };
            let result = unsafe {
                process_vm_readv(*self, &local_iov, 1, &remote_iov, 1, 0)
            };
            if result == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
    impl PutAddress for ProcessHandle { 
        fn put_address(&self, addr: usize, buf: &[u8]) -> io::Result<()> {
            let local_iov = iovec {
                iov_base: buf.as_ptr() as *mut c_void,
                iov_len: buf.len(),
            };
            let remote_iov = iovec {
                iov_base: addr as *mut c_void,
                iov_len: buf.len(),
            };
            let result = unsafe {
                process_vm_writev(*self, &local_iov, 1, &remote_iov, 1, 0)
            };
            if result == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        fn get_offset(&self, offsets: &Vec<usize>) -> usize { 
            use std::mem;
            let mut offset: usize = 0;
            let noffsets: usize = offsets.len();
            for i in 0..noffsets-1 { 
                offset +=  offsets[i];
                unsafe {
                    let mut copy: [u8; 8] = [0; 8];
                    self.copy_address(offset, &mut copy)
                        .map_err(|e| {
                            warn!("copy_address failed for {:x}: {:?}", offset, e);
                            e
                        }).unwrap();
                    offset = mem::transmute(copy);
                }
            }
                    
            offset += offsets[noffsets-1];
            offset
        }
    }
    pub fn get_pid(process_name:&str) -> Pid { 
        use std::process::Command;
        let output = match Command::new("pidof").arg(process_name).output() {
            Err(_) => return 0,
            Ok(x) => x
        };
        let a : String = match String::from_utf8(output.stdout) { 
            Err(_) => "0".to_string(),
            Ok(x) => x
        };
        a.parse::<i32>().unwrap()
    } 
}

#[cfg(target_os="macos")]
mod platform {
    extern crate mach;

    use libc::{pid_t, c_int};
    use self::mach::kern_return::{kern_return_t, KERN_SUCCESS};
    use self::mach::port::{mach_port_t, mach_port_name_t, MACH_PORT_NULL};
    use self::mach::vm_types::{mach_vm_address_t, mach_vm_size_t};
    use self::mach::message::{mach_msg_type_number_t};
    use std::io;
    use std::process::Child;
    use std::ptr;
    use std::slice;

    use super::{CopyAddress, TryIntoProcessHandle};

    #[allow(non_camel_case_types)] type vm_map_t = mach_port_t;
    #[allow(non_camel_case_types)] type vm_address_t = mach_vm_address_t;
    #[allow(non_camel_case_types)] type vm_size_t = mach_vm_size_t;

    /// On OS X a `Pid` is just a `libc::pid_t`.
    pub type Pid = pid_t;
    /// On OS X a `ProcessHandle` is a mach port.
    pub type ProcessHandle = mach_port_name_t;

    extern "C" {
        fn vm_read(target_task: vm_map_t, address: vm_address_t, size: vm_size_t, data: &*mut u8, data_size: *mut mach_msg_type_number_t) -> kern_return_t;
    }

    /// A small wrapper around `task_for_pid`, which taskes a pid returns the mach port representing its task.
    fn task_for_pid(pid: pid_t) -> io::Result<mach_port_name_t> {
        let mut task: mach_port_name_t = MACH_PORT_NULL;

        unsafe {
            let result = mach::traps::task_for_pid(mach::traps::mach_task_self(), pid as c_int, &mut task);
            if result != KERN_SUCCESS {
                return Err(io::Error::last_os_error())
            }
        }

        Ok(task)
    }

    /// `Pid` can be turned into a `ProcessHandle` with `task_for_pid`.
    impl TryIntoProcessHandle for Pid {
        fn try_into_process_handle(&self) -> io::Result<ProcessHandle> {
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
        fn try_into_process_handle(&self) -> io::Result<ProcessHandle> {
            self.id().try_into_process_handle()
        }
    }

    /// Use `vm_read` to read memory from another process on OS X.
    impl CopyAddress for ProcessHandle {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            let page_addr      = (addr as i64 & (-4096)) as mach_vm_address_t;
	    let last_page_addr = ((addr as i64 + buf.len() as i64 + 4095) & (-4096)) as mach_vm_address_t;
            let page_size      = last_page_addr as usize - page_addr as usize;

            let read_ptr: *mut u8 = ptr::null_mut();
            let mut read_len: mach_msg_type_number_t = 0;

            let result = unsafe {
                vm_read(*self, page_addr as u64, page_size as vm_size_t, &read_ptr, &mut read_len)
            };

            if result != KERN_SUCCESS {
                return Err(io::Error::last_os_error())
            }

            if read_len != page_size as u32 {
                panic!("Mismatched read sizes for `vm_read` (expected {}, got {})", page_size, read_len)
            }

            let read_buf = unsafe { slice::from_raw_parts(read_ptr, read_len as usize) };

            let offset = addr - page_addr as usize;
            let len = buf.len();
            buf.copy_from_slice(&read_buf[offset..(offset + len)]);

            Ok(())
        }
    }
}

#[cfg(windows)]
pub mod platform {
    extern crate winapi;
    extern crate kernel32;

    use std::io;
    use std::mem;
    use std::os::windows::io::{AsRawHandle, RawHandle};
    use std::process::Child;
    use std::ptr;
    use std::path;

    use super::{CopyAddress, TryIntoProcessHandle, PutAddress, HandleChecker, Inject};

    /// On Windows a `Pid` is a `DWORD`.
    pub type Pid = winapi::DWORD;
    /// On Windows a `ProcessHandle` is a `HANDLE`.
    pub type ProcessHandle = RawHandle;

    impl HandleChecker for ProcessHandle {
        fn check_handle(&self) -> bool {
            self.is_null()
        }
        fn null_type() -> ProcessHandle { 
            use std::ptr;
            ptr::null_mut()
        }
    }

    /// A `Pid` can be turned into a `ProcessHandle` with `OpenProcess`.
    impl TryIntoProcessHandle for winapi::DWORD {
        fn try_into_process_handle(&self) -> io::Result<ProcessHandle> {
            let handle = unsafe { kernel32::OpenProcess(winapi::winnt::PROCESS_VM_READ | winapi::winnt::PROCESS_VM_WRITE | winapi::winnt::PROCESS_VM_OPERATION, winapi::FALSE, *self) };
            if handle == (0 as RawHandle) {
                Err(io::Error::last_os_error())
            } else {
                Ok(handle)
            }
        }
    }

    /// A `std::process::Child` has a `HANDLE` from calling `CreateProcess`.
    impl TryIntoProcessHandle for Child {
        fn try_into_process_handle(&self) -> io::Result<ProcessHandle> {
            Ok(self.as_raw_handle())
        }
    }

    impl Inject for ProcessHandle {
        fn inject(&self, dll: path::PathBuf) -> io::Result<ProcessHandle> {
            let path_str = match dll.to_str() {
                Some(s) => s,
                None => return Err(io::Error::new(io::ErrorKind::Other, "Couldn't turn dll path into a string!"))
            };
            let path_address = unsafe {
                kernel32::VirtualAllocEx(*self,
                                         ptr::null_mut(),
                                         path_str.len() as winapi::SIZE_T,
                                         winapi::winnt::MEM_RESERVE | winapi::winnt::MEM_COMMIT,
                                         winapi::winnt::PAGE_EXECUTE_READWRITE)
            } as usize;
            match self.put_address(path_address, path_str.as_bytes()) {
                Ok(_) => {},
                Err(err) => return Err(err)
            } 
            let ll_address = unsafe {
                kernel32::GetProcAddress(
                    kernel32::GetModuleHandleA("kernel32.dll".as_bytes().as_ptr() as winapi::LPCSTR),
                    "LoadLibraryA".as_bytes().as_ptr() as winapi::LPCSTR) 
            };
            Ok( unsafe { 
                kernel32::CreateRemoteThread(*self,
                                             ptr::null_mut(),
                                             0,
                                             mem::transmute(ll_address as *const ()),
                                             path_address as winapi::LPVOID,
                                             0,
                                             ptr::null_mut())
            })
        }
    }

    /// Use `ReadProcessMemory` to read memory from another process on Windows.
    impl CopyAddress for ProcessHandle {
        fn copy_address(&self, addr: usize, buf: &mut [u8]) -> io::Result<()> {
            if buf.len() == 0 {
                return Ok(());
            }

            if unsafe { kernel32::ReadProcessMemory(*self,
                                                    addr as winapi::LPVOID,
                                                    buf.as_mut_ptr() as winapi::LPVOID,
                                                    mem::size_of_val(buf) as winapi::SIZE_T,
                                                    ptr::null_mut()) } == winapi::FALSE
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// Use `WriteProcessMemory` to write memory from another process on Windows.
    impl PutAddress for ProcessHandle {
        fn put_address(&self, addr: usize, buf: &[u8]) -> io::Result<()> {
            if buf.len() == 0 {
                return Ok(());
            }
            if unsafe { kernel32::WriteProcessMemory(*self,
                                                     addr as winapi::LPVOID,
                                                     buf.as_ptr() as winapi::LPCVOID,
                                                     mem::size_of_val(buf) as winapi::SIZE_T,
                                                     ptr::null_mut()) } == winapi::FALSE
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        fn get_offset(&self, offsets: &Vec<usize>) -> usize { 
            let mut offset: usize = 0;
            let noffsets: usize = offsets.len();
            for i in 0..noffsets-1 { 
                offset +=  offsets[i];
                unsafe {
                    let mut copy: [u8; mem::size_of::<usize>()] = [0; mem::size_of::<usize>()];
                    self.copy_address(offset, &mut copy)
                        .map_err(|e| {
                            warn!("copy_address failed for {:x}: {:?}", offset, e);
                            e
                        }).unwrap();
                    offset = mem::transmute(copy);
                }
            }
                    
            offset += offsets[noffsets-1];
            offset
        }
    }

    /// A helper function to turn a c_char array to a String
    fn utf8_to_string(bytes: &[i8]) -> String { 
        use std::ffi::CStr;
        unsafe { CStr::from_ptr(bytes.as_ptr()).to_string_lossy().into_owned() }
    }

    pub fn get_pid(process_name: &str) -> Pid { 
        let mut entry = winapi::tlhelp32::PROCESSENTRY32 {
            dwSize: mem::size_of::<winapi::tlhelp32::PROCESSENTRY32>() as u32,
            cntUsage: 0,
            th32ProcessID: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            cntThreads: 0,
            th32ParentProcessID: 0,
            pcPriClassBase: 0,
            dwFlags: 0, 
            szExeFile: [0; winapi::MAX_PATH]
        };

        let snapshot: winapi::HANDLE;
        unsafe {
            snapshot = kernel32::CreateToolhelp32Snapshot(winapi::tlhelp32::TH32CS_SNAPPROCESS, 0); 
            if kernel32::Process32First(snapshot, &mut entry) == winapi::TRUE {
                while kernel32::Process32Next(snapshot, &mut entry) == winapi::TRUE { 
                    if utf8_to_string(&entry.szExeFile) == process_name { 
                        return entry.th32ProcessID
                    }
                }
            }
        }

        0
    } 
}

/// Copy `length` bytes of memory at `addr` from `source`.
///
/// This is just a convenient way to call `CopyAddress::copy_address` without
/// having to provide your own buffer.
pub fn copy_address<T>(addr: usize, length: usize, source: &T) -> io::Result<Vec<u8>>
    where T: CopyAddress
{
    debug!("copy_address: addr: {:x}", addr);

    let mut copy = vec![0; length];

    source.copy_address(addr, &mut copy)
        .map_err(|e| {
            warn!("copy_address failed for {:x}: {:?}", addr, e);
            e
        })
        .and(Ok(copy))
} 
