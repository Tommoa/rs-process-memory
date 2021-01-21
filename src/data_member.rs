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
/// println!("Member value: {}", member.read().unwrap());
/// assert_eq!(x, member.read().unwrap());
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

    /// Create a new `DataMember` from a [`ProcessHandle`] and some number of (potentially negative) offsets.
    /// You must remember to call [`try_into_process_handle`] on a [`Pid`] as sometimes the `Pid` can have
    /// the same backing type as a [`ProcessHandle`], resulting in an error.
    ///
    /// [`try_into_process_handle`]: trait.TryIntoProcessHandle.html#tymethod.try_into_process_handle
    /// [`ProcessHandle`]: type.ProcessHandle.html
    /// [`Pid`]: type.Pid.htm
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn new_offset_relative(handle: ProcessHandle, offsets: Vec<isize>) -> Self {
        Self {
            // Yes, we are casting to usize. This will not touch any bits, but due to 2s complement,
            // we still get the correct result when adding offsets.
            offsets: offsets.into_iter().map(|x| x as usize).collect(),
            process: handle,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a new `DataMember` from a [`ProcessHandle`], pointing to the memory address in the
    /// remote process. Equivalent to `new_offset(handle, vec![addr])`. You must
    /// remember to call [`try_into_process_handle`] on a [`Pid`] as sometimes the `Pid` can have
    /// the same backing type as a [`ProcessHandle`], resulting in an error.
    ///
    /// [`try_into_process_handle`]: trait.TryIntoProcessHandle.html#tymethod.try_into_process_handle
    /// [`ProcessHandle`]: type.ProcessHandle.html
    /// [`Pid`]: type.Pid.html
    #[must_use]
    pub fn new_addr(handle: ProcessHandle, addr: usize) -> Self {
        Self {
            offsets: vec![addr],
            process: handle,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a new `DataMember` from a [`ProcessHandle`], pointing to the memory address in the
    /// process, then following a bunch of pointers and offsets, which may be negative.
    /// If you use CheatEngine and get a pointer of form "MyModule.dll + 0x12345678", plus a bunch
    /// of offsets, then you want to put the base address of the module as `addr`, `0x12345678` as
    /// the first offset, then any further offsets etc.
    /// This function is merely a convenience function, and is equivalent to
    /// `new_offset_relative(handle, vec![addr as isize, offsets[0], offsets[1], ...])`.
    /// You must
    /// remember to call [`try_into_process_handle`] on a [`Pid`] as sometimes the `Pid` can have
    /// the same backing type as a [`ProcessHandle`], resulting in an error.
    ///
    /// [`try_into_process_handle`]: trait.TryIntoProcessHandle.html#tymethod.try_into_process_handle
    /// [`ProcessHandle`]: type.ProcessHandle.html
    /// [`Pid`]: type.Pid.html
    #[must_use]
    #[allow(clippy::doc_markdown)]
    #[allow(clippy::cast_sign_loss)]
    pub fn new_addr_offset(handle: ProcessHandle, addr: usize, offsets: Vec<isize>) -> Self {
        let mut vec = vec![addr];
        // Yes, we are casting to usize. This will not touch any bits, and due to 2s complement,
        // we still get the correct result when adding offsets.
        vec.extend(offsets.into_iter().map(|x| x as usize));
        Self {
            offsets: vec,
            process: handle,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Creates a new `DataMember` by appending some more offets. Useful when you have a data
    /// structure, and want to refer to multiple fields in it, or use it as a starting point
    /// for chasing down more pointers.
    /// Since the pointed-to data type might have changed, this function is generic. It is your
    /// responsibility to make sure you know what you point to.
    #[allow(clippy::cast_sign_loss)]
    #[must_use]
    pub fn extend<TNew>(&self, more_offsets: Vec<isize>) -> DataMember<TNew> {
        let mut clone = DataMember {
            offsets: self.offsets.clone(),
            process: self.process,
            _phantom: std::marker::PhantomData,
        };
        // Yes, we are casting to usize. This will not touch any bits, and due to 2s complement,
        // we still get the correct result when adding offsets.
        clone
            .offsets
            .extend(more_offsets.into_iter().map(|x| x as usize));
        clone
    }

    /// Creates a new `DataMember`, based on self, by shifting the last offset by a number of
    /// bytes. Does not append new offsets. This is useful if you have a pointer to a struct
    /// and want to address different fields, or access elements in an array.
    #[allow(clippy::cast_sign_loss)]
    #[must_use]
    pub fn shift<TNew>(&self, n_bytes: isize) -> DataMember<TNew> {
        let mut clone = DataMember {
            offsets: self.offsets.clone(),
            process: self.process,
            _phantom: std::marker::PhantomData,
        };
        let new = clone.offsets[self.offsets.len() - 1].wrapping_add(n_bytes as usize);
        clone.offsets[self.offsets.len() - 1] = new;
        clone
    }
}

impl<T: Sized + Copy> Memory<T> for DataMember<T> {
    fn set_offset(&mut self, new_offsets: Vec<usize>) {
        self.offsets = new_offsets;
    }

    fn get_offset(&self) -> std::io::Result<usize> {
        self.process.get_offset(&self.offsets)
    }

    fn read(&self) -> std::io::Result<T> {
        let offset = self.process.get_offset(&self.offsets)?;
        // This can't be [0_u8;size_of::<T>()] because no const generics.
        // It will be freed at the end of the function because no references are held to it.
        let mut buffer = vec![0_u8; std::mem::size_of::<T>()];
        self.process.copy_address(offset, &mut buffer)?;
        Ok(unsafe { (buffer.as_ptr() as *const T).read_unaligned() })
    }

    fn write(&self, value: &T) -> std::io::Result<()> {
        use std::slice;
        let offset = self.process.get_offset(&self.offsets)?;
        let buffer: &[u8] =
            unsafe { slice::from_raw_parts(value as *const _ as _, std::mem::size_of::<T>()) };
        self.process.put_address(offset, &buffer)
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
        member.set_offset(vec![&test as *const _ as usize]);
        assert_eq!(test, member.read().unwrap());
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
        member.set_offset(vec![&test as *const _ as usize]);
        assert_eq!(test, member.read().unwrap());
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
        member.set_offset(vec![&test as *const _ as usize]);
        assert_eq!(test, member.read().unwrap());
        member.write(&0xffff).unwrap();
        assert_eq!(test, 0xffff);
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Player {
        x: u32,
        y: u32,
    }

    #[repr(C)]
    struct GameState {
        garbage: u32,
        garbage2: u32,
        players: [Box<Player>; 2], // note that this array is in-place, since it's fixed size.
    }

    #[test]
    fn multilevel_pointers() {
        let game = GameState {
            garbage: 42,
            garbage2: 1337,
            players: [
                Box::new(Player { x: 1, y: 2 }),
                Box::new(Player { x: 3, y: 4 }),
            ],
        };
        let handle = (std::process::id() as crate::Pid)
            .try_into_process_handle()
            .unwrap();

        // point to `game`, then our data is +4 from the base of `game`.
        let garbage2 = DataMember::<u32>::new_addr(handle, &game as *const _ as usize + 4);
        assert_eq!(1337, garbage2.read().unwrap());

        let garbage1 = garbage2.shift(-4);
        assert_eq!(42u32, garbage1.read().unwrap());

        // At `game + 2*sizeof(u32) + 1*sizeof(Player*) is where we find
        // a pointer to the second player.
        // So second_player.read() right now would just get you the pointer to the player.
        let second_player = DataMember::<*mut Player>::new_addr(
            handle,
            (&game as *const _ as usize) + 8 + handle.get_pointer_width().pointer_width_bytes(),
        );

        // But when we add an offset, in this case an offset of 0, we follow the pointer,
        // and thus second_player_x points to the beginning of the second player, which in this
        // case is also the x coordinate.
        let second_player_x = second_player.extend::<u32>(vec![0]);
        let second_player_y = second_player.extend::<u32>(vec![4]); // sizeof u32 = 4

        assert_eq!(3, second_player_x.read().unwrap());
        assert_eq!(4, second_player_y.read().unwrap());
    }
}
