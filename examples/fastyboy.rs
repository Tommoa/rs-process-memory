//! An example program that writes a few variables in the game Mirror's Edge Catalyst. This example
//! is only supported on Windows as Mirror's Edge Catalyst only runs on Windows.
//!
//! The program sets the spawn timer to 1 second (down from the default of 10 seconds), lowers the
//! "level warmup time" to 1 second (also down from a default of 10 seconds) and disables emitters.
//! These modifications should make the time taken to load a level in Mirror's Edge Catalyst
//! significantly shorter.

extern crate process_memory;
#[cfg(windows)]
extern crate winapi;

#[cfg(not(windows))]
fn main() {
    println!("FastyBoy can only be run on systems supporting the game Mirror's Edge Catalyst, which as of writing is only Windows.")
}

/// A helper function to get a Pid from the name of a process
#[cfg(windows)]
pub fn get_pid(process_name: &str) -> process_memory::Pid {
    /// A helper function to turn a c_char array to a String
    fn utf8_to_string(bytes: &[i8]) -> String { 
        use std::ffi::CStr;
        unsafe { CStr::from_ptr(bytes.as_ptr()).to_string_lossy().into_owned() }
    }
    let mut entry = winapi::um::tlhelp32::PROCESSENTRY32 {
        dwSize: std::mem::size_of::<winapi::um::tlhelp32::PROCESSENTRY32>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0, 
        szExeFile: [0; winapi::shared::minwindef::MAX_PATH]
    };
    let snapshot: process_memory::ProcessHandle;
    unsafe {
        snapshot = winapi::um::tlhelp32::CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPPROCESS, 0); 
        if winapi::um::tlhelp32::Process32First(snapshot, &mut entry) == winapi::shared::minwindef::TRUE {
            while winapi::um::tlhelp32::Process32Next(snapshot, &mut entry) == winapi::shared::minwindef::TRUE { 
                if utf8_to_string(&entry.szExeFile) == process_name { 
                    return entry.th32ProcessID
                }
            }
        }
    }
    0
} 


#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use process_memory::*;
    let process_handle = get_pid("MirrorsEdgeCatalyst.exe").try_into_process_handle()?;

    let mut spawn_timer = DataMember::<f32>::new(process_handle);
    spawn_timer.set_offset(vec![0x1_42_14_2a_d8, 0xac]);

    let mut level_warmup = DataMember::<f32>::new(process_handle);
    level_warmup.set_offset(vec![0x1_42_14_2a_d8, 0x9c]);

    let mut emitters_enabled = DataMember::<bool>::new(process_handle); 
    emitters_enabled.set_offset(vec![0x1_42_3e_44_78, 0xac]); 

    spawn_timer.write(&1.0)?;
    level_warmup.write(&1.0)?;
    emitters_enabled.write(&false)?;

    println!("Spawn timer: {}", spawn_timer.read()?);
    println!("Level warmup: {}", level_warmup.read()?);
    println!("Emitters enabled: {}", emitters_enabled.read()?);
    Ok(())
}
