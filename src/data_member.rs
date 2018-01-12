use { PutAddress, CopyAddress, ProcessHandle };

use std::{ io, mem, marker, fmt, str };
use std::marker::PhantomData;
use std::cell::RefCell;

pub trait Memory {
    fn set_offset(&mut self, Vec<usize>);
    fn read(&self, handle: ProcessHandle) -> Result<String, io::Error>;
    fn write(&self, handle: ProcessHandle, value: &str) -> Result<(), io::Error>;
}

pub struct DataMember<T> 
    where <T as str::FromStr>::Err: fmt::Debug,
    T: marker::Sized + fmt::Display + ToString + str::FromStr 
{
    offsets:    Vec<usize>,
    buffer:     RefCell<Vec<u8>>,
    _phantom:   PhantomData<*const T>
} 

impl<T> DataMember<T> 
    where <T as str::FromStr>::Err: fmt::Debug,
    T: marker::Sized + fmt::Display + ToString + str::FromStr
{
    pub fn new() -> DataMember<T> {
        DataMember {
            offsets:    Vec::new(),
            buffer:     RefCell::new(vec![0u8; mem::size_of::<T>()]),
            _phantom:   PhantomData
        }
    }
} 

impl Memory for DataMember<String> {
    fn set_offset(&mut self, new_offsets: Vec<usize>) {
        self.offsets = new_offsets;
    }
    fn read(&self, handle: ProcessHandle) -> Result<String, io::Error> {
        let offset = handle.get_offset(&self.offsets);
        let mut parts = Vec::<u8>::new(); 
        let mut addition_offset = 0usize;
        loop {
            let mut byte = [0u8; 1];
            match handle.copy_address(offset + addition_offset, &mut byte) {
                Ok(_) => {},
                Err(x) => return Err(x)
            };
            if byte[0] == 0 {
                break;
            }
            addition_offset += 1;
            parts.push(byte[0]);
        }
        Ok(String::from_utf8(parts).unwrap())
    }
    fn write(&self, handle: ProcessHandle, value: &str) -> Result<(), io::Error> {
        let offset = handle.get_offset(&self.offsets);
        let bytes = value.as_bytes();
        match handle.put_address(offset, bytes) {
            Ok(_) => {
                handle.put_address(offset + bytes.len(), &[0u8])
            }
            Err(x) => Err(x)
        }
    }
}

impl <T> Memory for DataMember<T> 
    where <T as str::FromStr>::Err: fmt::Debug,
    T: marker::Sized + fmt::Display + ToString + str::FromStr
{
    default fn set_offset(&mut self, new_offsets: Vec<usize>) {
        self.offsets = new_offsets;
    }
    default fn read(&self, handle: ProcessHandle) -> Result<String, io::Error> {
        let offset = handle.get_offset(&self.offsets);
        let mut buffer = self.buffer.borrow_mut();
        match handle.copy_address(offset, &mut buffer) {
            Ok(_) => { 
                let x : &T = unsafe { mem::transmute_copy(mem::transmute::<*mut Vec<u8>, &Vec<u8>>(self.buffer.as_ptr())) };
                Ok(x.to_string())
            },
            Err(x) => {
               return Err(x) 
            }
        }
    }
    default fn write(&self, handle: ProcessHandle, value: &str) -> Result<(), io::Error> {
        use std::slice;
        let offset = handle.get_offset(&self.offsets);
        let value : T = value.parse().unwrap();
        let p1 : *const T = &value;
        let p2 : *const u8 = p1 as *const _;
        let buffer = unsafe { 
            slice::from_raw_parts(p2, mem::size_of::<T>())
        };
        handle.put_address(offset, &buffer)
    }
}
