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

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use process_memory::*;
    let process_handle = get_pid("MirrorsEdgeCatalyst.exe")?.try_into_process_handle()?;

    let mut spawn_timer = DataMember::<f32>::new(process_handle);
    spawn_timer.set_offset(0x1_42_14_2a_d8, vec![0xac]);

    let mut level_warmup = DataMember::<f32>::new(process_handle);
    level_warmup.set_offset(0x1_42_14_2a_d8, vec![0x9c]);

    let mut emitters_enabled = DataMember::<bool>::new(process_handle);
    emitters_enabled.set_offset(0x1_42_3e_44_78, vec![0xac]);

    spawn_timer.write(&1.0)?;
    level_warmup.write(&1.0)?;
    emitters_enabled.write(&false)?;

    println!("Spawn timer: {}", spawn_timer.read()?);
    println!("Level warmup: {}", level_warmup.read()?);
    println!("Emitters enabled: {}", emitters_enabled.read()?);
    Ok(())
}
