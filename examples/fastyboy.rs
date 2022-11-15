//! An example program that writes a few variables in the game Mirror's Edge Catalyst. This example
//! is only supported on Windows as Mirror's Edge Catalyst only runs on Windows.
//!
//! The program sets the spawn timer to 1 second (down from the default of 10 seconds), lowers the
//! "level warmup time" to 1 second (also down from a default of 10 seconds) and disables emitters.
//! These modifications should make the time taken to load a level in Mirror's Edge Catalyst
//! significantly shorter.
#[cfg(windows)]
mod windows {
    pub(crate) use windows::Win32::{
        Foundation::{CHAR, MAX_PATH},
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
    };
}
#[cfg(not(windows))]
fn main() {
    println!("FastyBoy can only be run on systems supporting the game Mirror's Edge Catalyst, which as of writing is only Windows.")
}

/// A helper function to get a Pid from the name of a process
#[cfg(windows)]
pub fn get_pid(process_name: &str) -> process_memory::Pid {
    /// A helper function to turn a CHAR array to a String
    fn utf8_to_string(bytes: &[windows::CHAR]) -> String {
        use std::ffi::CStr;
        unsafe {
            CStr::from_ptr(bytes.as_ptr() as *const i8)
                .to_string_lossy()
                .into_owned()
        }
    }

    let mut entry = windows::PROCESSENTRY32 {
        dwSize: std::mem::size_of::<windows::PROCESSENTRY32>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [windows::CHAR(0); windows::MAX_PATH as usize],
    };
    unsafe {
        // On Error return 0 as the pid. Maybe this function should instead return itself a Result
        // to indicate if a pid has been found?
        let snapshot = if let Ok(snapshot) =
            windows::CreateToolhelp32Snapshot(windows::TH32CS_SNAPPROCESS, 0)
        {
            snapshot
        } else {
            return 0;
        };
        if windows::Process32First(snapshot, &mut entry) == true {
            while windows::Process32Next(snapshot, &mut entry) == true {
                if utf8_to_string(&entry.szExeFile) == process_name {
                    return entry.th32ProcessID;
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

    unsafe {
        // safety: These are known to be the correct addresses for these types in
        // 'MirrorsEdgeCatalyst.exe'
        println!("Spawn timer: {}", spawn_timer.read()?);
        println!("Level warmup: {}", level_warmup.read()?);
        println!("Emitters enabled: {}", emitters_enabled.read()?);
    }
    Ok(())
}
