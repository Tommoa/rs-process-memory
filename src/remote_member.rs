
/// This module is only loaded when being built for Windows.
/// It will remain that way until I figure out a good way of doing ipc to the
///     .dll/.so on various unix platforms
/// Once `ipc-channel` gains Windows support, I'll probably use that.

extern crate named_pipe;

use serde::{ Deserialize, Serialize };
use rmps::{ Deserializer, Serializer };

use std::io::prelude::*;
use std::collections::{ HashSet, HashMap };

#[derive(Debug, Deserialize, Serialize)]
pub enum Msg {
    Offsets(String, Vec<usize>), 
    Get(String),
    Create(String, Types),
    Set(String, String),
    Exit
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub enum Types { 
    Int,
    Long,
    Float,
    Double,
    Bool,
    Str
} 

/// A struct to manage data members that exist on another thread as either a `DataMember` or a
/// `LocalMember`
///
/// This struct is *not* safe to share between threads, but is safe to send between threads.
pub struct RemoteMembers {
    members:        HashSet<String>,
    pipe_server:    named_pipe::PipeServer, 
    server_name:    String
} impl RemoteMembers {
    /// Create a new RemoteMembers struct. Please ensure your remote client is already listening or
    /// is about to listen as this will block until a client connects.
    pub fn new(server_name: String) -> RemoteMembers { 
        RemoteMembers {
            members:        HashSet::new(),
            pipe_server:    named_pipe::PipeOptions::new(server_name.clone()).single().unwrap().wait().unwrap(),
            server_name:    server_name
        }
    }
    /// Write a message to the pipe.
    fn send(&mut self, val: Msg) -> Result<usize, String> {
        use std::mem::{ transmute, size_of_val, size_of };

        let mut to_send = Vec::new();
        val.serialize(&mut Serializer::new(&mut to_send)).unwrap();
        let total = size_of_val(&to_send.len());
        if self.pipe_server.write(&unsafe { transmute::<usize, [u8; size_of::<usize>()]>(to_send.len()) }).ok() != Some(total) {
            error!("Couldn't write length of outgoing message to server. Reopening server");
            self.pipe_server = named_pipe::PipeOptions::new(self.server_name.clone()).single().unwrap().wait().unwrap();
            info!("Server reopened. Name {}.", self.server_name);
            return Err("Couldn't write length to server!".to_owned());
        }
        if self.pipe_server.write(&to_send).ok() != Some(to_send.len()) { 
            error!("Couldn't write message to server. Reopening server");
            self.pipe_server = named_pipe::PipeOptions::new(self.server_name.clone()).single().unwrap().wait().unwrap();
            info!("Server reopened. Name {}.", self.server_name);
            return Err("Couldn't write data to server!".to_owned());
        }
        Ok(total + to_send.len())
    }
    /// Closes down the server.
    pub fn exit(&mut self) {
        while let Err(err) = self.send(Msg::Exit) {
            error!("Couldn't send exit message to client! Reopening server and trying again");
            error!("\tError message: {}", err);
            self.pipe_server = named_pipe::PipeOptions::new(self.server_name.clone()).single().unwrap().wait().unwrap();
            info!("Server reopened. Name {}.", self.server_name);
        }
    }
    /// Creates a new data member on the client
    pub fn create(&mut self, name: &str, t: Types) -> Result<(), String> {
        let val = Msg::Create(name.to_owned(), t);
        match self.send(val) {
            Ok(x) => debug!("Wrote {} bytes to pipe!", x),
            Err(err) => return Err(err)
        }
        self.members.insert(name.to_owned());
        Ok(())
    }
    /// Sets the offsets of a data member on the client
    pub fn set_offsets(&mut self, name: &str, offsets: Vec<usize>) -> Result<(), String> { 
        if self.members.get(name).is_none() {
            error!("Attempted to get member with name {} that does not exist!", name);
            return Err(format!("No member with name {}!", name));
        }
        let val = Msg::Offsets(name.to_owned(), offsets);
        match self.send(val) {
            Ok(x) => debug!("Wrote {} bytes to pipe!", x),
            Err(err) => return Err(err)
        }
        Ok(())
    }
    /// Write a value to a data member on the client
    pub fn write(&mut self, name: &str, value: &str) -> Result<(), String> { 
        if self.members.get(name).is_none() {
            error!("Attempted to get member with name {} that does not exist!", name);
            return Err(format!("No member with name {}!", name));
        }
        let val = Msg::Set(name.to_owned(), value.to_owned());
        match self.send(val) {
            Ok(x) => debug!("Wrote {} bytes to pipe!", x),
            Err(err) => return Err(err)
        }
        Ok(())
    }
    /// Read a value from a data member on the client
    pub fn read(&mut self, name: &str) -> Result<String, String> {
        if self.members.get(name).is_none() {
            error!("Attempted to get member with name {} that does not exist!", name);
            return Err(format!("No member with name {}!", name));
        }
        let val = Msg::Get(name.to_owned());
        match self.send(val) {
            Ok(x) => debug!("Wrote {} bytes to pipe!", x),
            Err(err) => return Err(err)
        }

        use std::mem::size_of;
        use std::slice;
        let mut size = 0usize;
        let s : *mut usize = &mut size;
        let u = s as *mut u8;
        if self.pipe_server.read(unsafe { slice::from_raw_parts_mut(u, size_of::<usize>()) }).ok() != Some(size_of::<usize>()) {
            return Err("Error reading from client!".to_owned());
        }
        let mut vec = vec![0u8; size];
        if self.pipe_server.read_exact(&mut vec).is_err() {
            return Err("Error reading from client!".to_owned());
        } 
        let m: Msg = Deserialize::deserialize(&mut Deserializer::new(&vec[..])).unwrap();
        if let Msg::Get(re) = m {
            return Ok(re);
        }
        Err(format!("Wrong type response!\n{:?}", m))
    }
}
impl Drop for RemoteMembers {
    fn drop(&mut self) {
        self.exit();
    }
}
impl !Sync for RemoteMembers {}

use std::fs::File;
use local_member::*;
/// A struct to manage `LocalMember`s.
///
/// This struct is not safe to share between threads or send to another thread
pub struct LocalManager<'a> {
    members:    HashMap<String, Box<LocalMemory>>,
    pipe:       named_pipe::PipeClient,
    server:     String,
    out_file:   &'a mut File,
} impl<'a> LocalManager<'a> {
    pub fn new(server_name: String, out_file: &'a mut File ) -> LocalManager {
        LocalManager {
            members:    HashMap::new(),
            pipe:       named_pipe::PipeClient::connect(server_name.clone()).unwrap(),
            server:     server_name,
            out_file:   out_file,
        }
    }
    pub fn run(&mut self) { 
        writeln!(self.out_file, "Entering main loop").unwrap();
        use std::mem::size_of;
        use std::slice;
        loop {
            let mut size = 0usize;
            let s : *mut usize = &mut size;
            let u = s as *mut u8;
            if self.pipe.read(unsafe { slice::from_raw_parts_mut(u, size_of::<usize>()) }).ok() != Some(size_of::<usize>()) {
                self.pipe = named_pipe::PipeClient::connect(self.server.clone()).unwrap();
            }
            let mut vec = vec![0u8; size];
            if self.pipe.read_exact(&mut vec).is_err() {
                self.pipe = named_pipe::PipeClient::connect(self.server.clone()).unwrap();
            }
            let m: Msg = Deserialize::deserialize(&mut Deserializer::new(&vec[..])).unwrap();
            match m {
                Msg::Get(name) => {
                    self.get(&name);
                },
                Msg::Create(name, t) => {
                    writeln!(self.out_file, "Creating variable with name {} and type {:?}", name, t).unwrap();
                    self.create(&name, t);
                },
                Msg::Offsets(name, new_offsets) => {
                    writeln!(self.out_file, "Setting offsets for {} to {:?}", name, new_offsets).unwrap();
                    self.offsets(&name, new_offsets);
                },
                Msg::Set(name, value) => {
                    self.set(&name, &value);
                    writeln!(self.out_file, "Setting {} to {}", name, value).unwrap();
                }
                Msg::Exit => {
                    break;
                }
            }
        }
        writeln!(self.out_file, "Exiting main loop").unwrap();
    }
    pub fn offsets(&mut self, name: &str, new_offsets: Vec<usize>) {
        if let Some(member) = self.members.get_mut(name) {
            member.set_offset(new_offsets);
        }
    }
    pub fn set(&self, name: &str, value: &str) {
        if let Some(member) = self.members.get(name) {
            member.write(value);
        }
    }
    pub fn get(&mut self, name: &str) { 
        if let Some(member) = self.members.get(name) {
            use std::mem::{ transmute, size_of_val, size_of };
            let val = Msg::Get(member.read()); 

            let mut to_send = Vec::new();
            val.serialize(&mut Serializer::new(&mut to_send)).unwrap();
            let total = size_of_val(&to_send.len());
            if self.pipe.write(&unsafe { transmute::<usize, [u8; size_of::<usize>()]>(to_send.len()) }).ok() != Some(total) {
                self.pipe = named_pipe::PipeClient::connect(self.server.clone()).unwrap();
                return;
            }
            if self.pipe.write(&to_send).ok() != Some(to_send.len()) { 
                self.pipe = named_pipe::PipeClient::connect(self.server.clone()).unwrap();
                return;
            } 
        }
    }
    pub fn create(&mut self, name: &str, t: Types) {
        let member = match t { 
            Types::Int => {
                Box::new(LocalMember::<i32>::new()) as Box<LocalMemory>
            },
            Types::Long => {
                Box::new(LocalMember::<i64>::new())
            },
            Types::Float => {
                Box::new(LocalMember::<f32>::new())
            },
            Types::Double => {
                Box::new(LocalMember::<f64>::new())
            },
            Types::Bool => {
                Box::new(LocalMember::<bool>::new())
            },
            Types::Str => {
                Box::new(LocalMember::<String>::new())
            }
        };
        self.members.insert(name.to_owned(), member);
    }
}
impl<'a> !Sync for LocalManager<'a> {}
impl<'a> !Send for LocalManager<'a> {}
