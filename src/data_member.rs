use crate::{CopyAddress, Memory, ProcessHandle, PutAddress};

/// # Tools for working with memory of other programs
/// This module provides functions for modifying the memory of a program from outside of the
/// address space of that program.
///
/// Examples:
/// ```rust
/// # use process_memory::{Memory, DataMember, Pid, TryIntoProcessHandle};
/// // We have a variable with some value
/// let x = 4u32;
/// println!("Original x-value: {}", x);
///
/// // We need to make sure that we get a handle to a process, in this case, ourselves
/// let handle = (std::process::id() as Pid).try_into_process_handle().unwrap();
/// // We make a `DataMember` that has an offset referring to its location in memory
/// let member = DataMember::new_offset(handle, vec![&x as *const _ as usize]);
/// // The memory refered to is now the same
/// println!("Memory location: &x: {}, member: {}", &x as *const _ as usize,
///     member.get_offset().unwrap());
/// assert_eq!(&x as *const _ as usize, member.get_offset().unwrap());
/// // The value of the member is the same as the variable
/// println!("Member value: {}", unsafe { member.read().unwrap() });
/// assert_eq!(x, unsafe { member.read().unwrap() });
/// // We can write to and modify the value of the variable using the member
/// member.write(&6u32).unwrap();
/// println!("New x-value: {}", x);
/// assert_eq!(x, 6u32);
/// ```
#[derive(Clone, Debug)]
pub struct DataMember<T> {
    offsets: Vec<usize>,
    process: ProcessHandle,
    _phantom: std::marker::PhantomData<*mut T>,
}

impl<T: Sized + Copy> DataMember<T> {
    /// Create a new `DataMember` from a [`ProcessHandle`]. You must remember to call
    /// [`try_into_process_handle`] on a [`Pid`], because the types may have the same backing type,
    /// resulting in errors when called with the wrong value.
    ///
    /// By default, there will be no offsets, leading to an error when attempting to call
    /// [`Memory::read`], so you will likely need to call [`Memory::set_offset`] before attempting
    /// any reads.
    ///
    /// [`try_into_process_handle`]: trait.TryIntoProcessHandle.html#tymethod.try_into_process_handle
    /// [`ProcessHandle`]: type.ProcessHandle.html
    /// [`Pid`]: type.Pid.html
    /// [`Memory::read`]: trait.Memory.html#tymethod.read
    /// [`Memory::set_offset`]: trait.Memory.html#tymethod.set_offset
    #[must_use]
    pub fn new(handle: ProcessHandle) -> Self {
        Self {
            offsets: Vec::new(),
            process: handle,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a new `DataMember` from a [`ProcessHandle`] and some number of offsets. You must
    /// remember to call [`try_into_process_handle`] on a [`Pid`] as sometimes the `Pid` can have
    /// the same backing type as a [`ProcessHandle`], resulting in an error.
    ///
    /// [`try_into_process_handle`]: trait.TryIntoProcessHandle.html#tymethod.try_into_process_handle
    /// [`ProcessHandle`]: type.ProcessHandle.html
    /// [`Pid`]: type.Pid.html
    #[must_use]
    pub fn new_offset(handle: ProcessHandle, offsets: Vec<usize>) -> Self {
        Self {
            offsets,
            process: handle,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: Sized + Copy> Memory<T> for DataMember<T> {
    fn set_offset(&mut self, new_offsets: Vec<usize>) {
        self.offsets = new_offsets;
    }

    fn get_offset(&self) -> std::io::Result<usize> {
        self.process.get_offset(&self.offsets)
    }

    unsafe fn read(&self) -> std::io::Result<T> {
        let offset = self.process.get_offset(&self.offsets)?;
        // This can't be [0_u8;size_of::<T>()] because no const generics.
        // It will be freed at the end of the function because no references are held to it.
        let mut buffer = vec![0_u8; std::mem::size_of::<T>()];
        self.process.copy_address(offset, &mut buffer)?;
        Ok(buffer.as_ptr().cast::<T>().read_unaligned())
    }

    fn write(&self, value: &T) -> std::io::Result<()> {
        use std::slice;
        let offset = self.process.get_offset(&self.offsets)?;
        let buffer: &[u8] = unsafe {
            slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
        };
        self.process.put_address(offset, buffer)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::TryIntoProcessHandle;
    #[test]
    fn modify_remote_i32() {
        let test = 4_i32;
        #[allow(clippy::cast_possible_wrap)]
        let handle = (std::process::id() as crate::Pid)
            .try_into_process_handle()
            .unwrap();
        println!("Process Handle: {:?}", handle);
        let mut member = DataMember::<i32>::new(handle);
        member.set_offset(vec![std::ptr::addr_of!(test) as usize]);
        unsafe {
            // safety: the memory being pointed to is known to be a valid i32 as we control it
            assert_eq!(test, member.read().unwrap());
        }
        member.write(&5_i32).unwrap();
        assert_eq!(test, 5_i32);
    }
    #[test]
    fn modify_remote_i64() {
        let test = 3_i64;
        #[allow(clippy::cast_possible_wrap)]
        let handle = (std::process::id() as crate::Pid)
            .try_into_process_handle()
            .unwrap();
        println!("Process Handle: {:?}", handle);
        let mut member = DataMember::<i64>::new(handle);
        member.set_offset(vec![std::ptr::addr_of!(test) as usize]);
        unsafe {
            // safety: the memory being pointed to is known to be a valid i64 as we control it
            assert_eq!(test, member.read().unwrap());
        }
        member.write(&-1_i64).unwrap();
        assert_eq!(test, -1);
    }
    #[test]
    fn modify_remote_usize() {
        let test = 0_usize;
        #[allow(clippy::cast_possible_wrap)]
        let handle = (std::process::id() as crate::Pid)
            .try_into_process_handle()
            .unwrap();
        println!("Process Handle: {:?}", handle);
        let mut member = DataMember::<usize>::new(handle);
        member.set_offset(vec![std::ptr::addr_of!(test) as usize]);
        unsafe {
            // safety: the memory being pointed to is known to be a valid usize as we control it
            assert_eq!(test, member.read().unwrap());
        }
        member.write(&0xffff).unwrap();
        assert_eq!(test, 0xffff);
    }
}
