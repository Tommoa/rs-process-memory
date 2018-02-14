extern crate process_memory;
#[macro_use]
extern crate log;
extern crate env_logger;

use process_memory::TryIntoProcessHandle;
use std::error::Error;

use std::process;
use std::path::PathBuf;
use std::fmt;

use process_memory::remote_member::RemoteMembers;

trait Attempt {
    fn attempt(&self);
}

impl<T, U> Attempt for Result<U, T> 
where T: fmt::Display
{
    fn attempt(&self) {
        match self {
            &Ok(_) => {},
            &Err(ref err) => {
                error!("{}", err); 
                process::exit(1);
            }
        }
    }
}

fn main() { 
    env_logger::init();
    use process_memory::Inject;
    use process_memory::remote_member::Types;
    let process_handle = match process_memory::platform::get_pid("MirrorsEdgeCatalyst.exe").try_into_process_handle() {
        Ok(x) => x,
        Err(err) => {
            println!("Error!\n\n{}", err.description());
            return;
        }
    };

    process_handle.inject(PathBuf::from("target\\release\\examples\\process-dll.dll").canonicalize().unwrap()).unwrap();
    let mut rm = RemoteMembers::new("\\\\.\\pipe\\MEC".to_owned());
    rm.create("spawn timer", Types::Float).attempt();
    rm.create("level warmup", Types::Float).attempt();
    rm.create("emitters enabled", Types::Bool).attempt();
    rm.set_offsets("spawn timer", vec![0x142142ad8, 0x98]).attempt();
    rm.set_offsets("level warmup", vec![0x142142ad8, 0x9c]).attempt();
    rm.set_offsets("emitters enabled", vec![0x1423e4478, 0xac]).attempt();
    rm.write("spawn timer", "1").attempt();
    rm.write("level warmup", "1").attempt();
    rm.write("emitters enabled", "false").attempt();
    println!("Spawn timer:      {}", rm.read("spawn timer").unwrap());
    println!("Level warmup:     {}", rm.read("level warmup").unwrap());
    println!("Emitters enabled: {}", rm.read("emitters enabled").unwrap()); 
}
