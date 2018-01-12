extern crate process_memory;

use process_memory::data_member::*;
use process_memory::TryIntoProcessHandle;
use std::error::Error;

use std::process;

trait Attempt {
    fn attempt(&self);
}

impl<T> Attempt for Result<(), T> {
    fn attempt(&self) {
        match self {
            &Ok(_) => {},
            &Err(_) => {
                println!("Couldn't write to memory!"); 
                process::exit(1);
            }
        }
    }
}

fn main() { 
    let process_handle = match process_memory::platform::get_pid("MirrorsEdgeCatalyst.exe").try_into_process_handle() {
        Ok(x) => x,
        Err(err) => {
            println!("Error!\n\n{}", err.description());
            return;
        }
    };

    let mut spawn_timer = DataMember::<f32>::new();
    spawn_timer.set_offset(vec![0x142142ad8, 0xac]);

    let mut level_warmup = DataMember::<f32>::new();
    level_warmup.set_offset(vec![0x142142ad8, 0x9c]);

    let mut emitters_enabled = DataMember::<bool>::new(); 
    emitters_enabled.set_offset(vec![0x1423e4478, 0xac]); 

    spawn_timer.write(process_handle, "1").attempt();
    level_warmup.write(process_handle, "1").attempt();
    emitters_enabled.write(process_handle, "false").attempt();

    println!("Spawn timer: {}", match spawn_timer.read(process_handle) {
        Ok(x) => x,
        Err(_) => "Couldn't read memory!".to_owned()
    });
    println!("Level warmup: {}", match level_warmup.read(process_handle) {
        Ok(x) => x,
        Err(_) => "Couldn't read memory!".to_owned()
    });
    println!("Emitters enabled: {}", match emitters_enabled.read(process_handle) {
        Ok(x) => x,
        Err(_) => "Couldn't read memory!".to_owned()
    });
}
