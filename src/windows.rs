use winapi::shared::minwindef;
use winapi::um::{handleapi::CloseHandle, tlhelp32};

use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::ptr;

use super::{
    Architecture, CopyAddress, GetLibraryInfo, LibraryInfo, ProcessHandleExt, ProcessInfo,
    PutAddress, TryIntoProcessHandle,
};

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

/// A `ProcessInfo` has a pid (= `u32`, = `minwindef::DWORD`), which can be turned into a `ProcessHandle`.
impl TryIntoProcessHandle for ProcessInfo {
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle> {
        self.pid.try_into_process_handle()
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

/// List all processes on the system.
///
/// Example:
/// ```rust
/// match process_memory::processes_iter().unwrap().find(|p| p.name == "MyGame.exe") {
///     None => println!("No such process currently exists"),
///     Some(p) => println!("Pid of {} is {}", p.name, p.pid)
/// }
/// ```
///
/// # Errors
/// Returns an `std::io::Error` with last operating system error when fetching process
/// list fails for some reason.
/// Return an `std::io::Error` with `Other` kind when failing to close the Windows `HANDLE`.
#[allow(clippy::cast_possible_truncation)]
pub fn processes_iter() -> std::io::Result<impl Iterator<Item = ProcessInfo>> {
    let mut entry = tlhelp32::PROCESSENTRY32 {
        dwSize: std::mem::size_of::<tlhelp32::PROCESSENTRY32>() as u32, // need to allow clippy truncation because of this
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; minwindef::MAX_PATH],
    };

    let mut processes = Vec::new();

    let snapshot: winapi::um::winnt::HANDLE;
    unsafe {
        snapshot = tlhelp32::CreateToolhelp32Snapshot(tlhelp32::TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        if tlhelp32::Process32First(snapshot, &mut entry) == minwindef::TRUE {
            // makeshift do-while
            loop {
                processes.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    name: utf8_to_string(&entry.szExeFile),
                });

                if tlhelp32::Process32Next(snapshot, &mut entry) == minwindef::FALSE {
                    break;
                }
            }
        }

        if CloseHandle(snapshot) == minwindef::FALSE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Could not close handle.",
            ));
        };
        Ok(processes.into_iter())
    }
}

/// Use `CreateToolhelp32Snapshot` to get and filter list of loaded libraries (also called modules)
/// of this process, returning the base address of it.
#[allow(clippy::cast_possible_truncation)]
impl GetLibraryInfo for Pid {
    fn libs_iter(&self) -> std::io::Result<Vec<LibraryInfo>> {
        // taken from https://stackoverflow.com/questions/41552466/how-do-i-get-the-physical-baseaddress-of-an-dll-used-in-a-process
        let mut module_entry = tlhelp32::MODULEENTRY32 {
            dwSize: std::mem::size_of::<tlhelp32::MODULEENTRY32>() as u32, // need the clippy exception because of this
            th32ModuleID: 0,
            th32ProcessID: 0,
            GlblcntUsage: 0,
            ProccntUsage: 0,
            modBaseAddr: std::ptr::null_mut(),
            modBaseSize: 0,
            hModule: std::ptr::null_mut(),
            szModule: [0; tlhelp32::MAX_MODULE_NAME32 + 1],
            szExePath: [0; minwindef::MAX_PATH],
        };

        let mut libs = Vec::new();

        unsafe {
            let snapshot = tlhelp32::CreateToolhelp32Snapshot(
                tlhelp32::TH32CS_SNAPMODULE | tlhelp32::TH32CS_SNAPMODULE32,
                *self,
            );
            if snapshot.is_null() {
                return Err(std::io::Error::last_os_error());
            }

            if tlhelp32::Module32First(snapshot, &mut module_entry) == minwindef::TRUE {
                // makeshift do-while
                loop {
                    libs.push(LibraryInfo {
                        name: utf8_to_string(&module_entry.szModule),
                        base: module_entry.modBaseAddr as usize,
                    });

                    if tlhelp32::Module32Next(snapshot, &mut module_entry) == minwindef::FALSE {
                        break;
                    }
                }
            }

            // We searched everything, nothing found
            if CloseHandle(snapshot) == minwindef::FALSE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Could not close handle.",
                ));
            };
            Ok(libs)
        }
    }
}

/// A helper function to turn a `c_char` array to a String
fn utf8_to_string(bytes: &[i8]) -> String {
    use std::ffi::CStr;
    unsafe {
        CStr::from_ptr(bytes.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_info() {
        let pid = std::process::id() as Pid;
        let base = pid.get_library_base("ntdll.dll").unwrap();
        assert_ne!(0, base);
        println!("ntdll.dll address: 0x{:X}", base);

        match pid
            .libs_iter()
            .unwrap()
            .iter()
            .find(|lib| lib.name == "this_dll_doesnt_exist.dll")
        {
            Some(_) => panic!(),
            None => {}
        }
    }

    #[test]
    fn getpid() {
        let proc = processes_iter()
            .unwrap()
            .find(|p| p.name == "svchost.exe")
            .unwrap();
        assert_eq!("svchost.exe", proc.name);

        match processes_iter()
            .unwrap()
            .find(|p| p.name == "this_process_doesnt_exist.exe")
        {
            Some(_) => panic!(),
            None => {}
        }
    }
}
