use crate::Memory;

/// This struct provides functions for modifying the memory of a program from within the address
/// space of that program. This may be helpful for debug functions, or for an injected DLL.
///
/// # Examples:
/// ```rust
/// # use process_memory::{Memory, LocalMember};
/// // We have a variable with some value
/// let x = 4u32;
///
/// // We make a `LocalMember` that has an offset referring to its location in memory
/// let member = LocalMember::new_addr(&x as *const _ as usize);
/// // The memory refered to is now the same
/// assert_eq!(&x as *const _ as usize, member.get_offset().unwrap());
/// // The value of the member is the same as the variable
/// assert_eq!(x, member.read().unwrap());
/// // We can write to and modify the value of the variable using the member
/// member.write(&6u32).unwrap();
/// assert_eq!(x, 6u32);
/// ```
///
/// # Safety
///
/// These functions are technically ***not safe***. Do not attempt to read or write to any local
/// memory that you do not know is correct. If you're trying to explore your entire address space
/// or are testing to see if a pointer is allocated to you, use [`DataMember`] with your own PID.
///
/// Unfortunately it's not possible to implement some traits safely (e.g. [`Memory`] on
/// [`DataMember`] but implement it on other structures unsafely in Rust.
///
/// The implemented functions try to stop you from shooting yourself in the foot by checking none
/// of the pointers end up at the null pointer, but this does not guarantee that you won't be able
/// to mess something up really badly in your program.
#[derive(Clone, Debug, Default)]
pub struct LocalMember<T> {
    base: usize,
    offsets: Vec<isize>,
    _phantom: std::marker::PhantomData<*mut T>,
}

impl<T: Sized + Copy> LocalMember<T> {
    /// Creates a new `LocalMember` with no offsets. Any calls to
    /// [`Memory::read`] will attempt to read from a null pointer reference.
    ///
    /// To set offsets, use [`Memory::set_offset`]offset), or create the `LocalMember` using
    /// [`new_offset`].
    ///
    /// [`Memory::read`]: trait.Memory.html#tymethod.read
    /// [`Memory::set_offset`]: trait.Memory.html#tymethod.set_offset
    /// [`new_offset`]: struct.LocalMember.html#method.new_offset
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: 0,
            offsets: Vec::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a new `LocalMember` with a given set of offsets.
    #[must_use]
    pub fn new_addr(base: usize) -> Self {
        Self {
            base,
            offsets: Vec::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a new `LocalMember` with a given set of offsets.
    #[must_use]
    pub fn new_addr_offset(base: usize, offsets: Vec<isize>) -> Self {
        Self {
            base,
            offsets,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: Sized + Copy> Memory<T> for LocalMember<T> {
    fn set_offset(&mut self, new_base: usize, new_offsets: Vec<isize>) {
        self.base = new_base;
        self.offsets = new_offsets;
    }

    #[allow(clippy::cast_sign_loss)]
    fn get_offset(&self) -> std::io::Result<usize> {
        if self.offsets.is_empty() {
            Ok(self.base)
        } else {
            let mut offset = self.base;
            for i in 0..self.offsets.len() - 1 {
                offset = offset.wrapping_add(self.offsets[i] as usize); // should work because of 2s-complement
                if offset == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Would be a null dereference!",
                    ));
                }
                // We can't guarantee alignment, so we must use `read_unaligned()`
                // to ensure that its ok to read from, as `read()` requires that
                // our source pointer is properly aligned.
                unsafe {
                    offset = (offset as *const usize).read_unaligned();
                }
            }
            Ok(offset.wrapping_add(self.offsets[self.offsets.len() - 1] as usize))
        }
    }

    /// This will only return a error if one of the offsets gives a null pointer. or give a
    /// non-aligned read
    fn read(&self) -> std::io::Result<T> {
        let offset = self.get_offset()? as *const T;
        // Read the value of the pointer. We can't guarantee alignment, so this
        // is `read_unaligned()` instead of `read()`
        let x: T = unsafe { offset.read_unaligned() };
        Ok(x)
    }

    /// This will only return a error if one of the offsets gives a null pointer.
    fn write(&self, value: &T) -> std::io::Result<()> {
        use std::ptr::copy_nonoverlapping;

        let offset = self.get_offset()? as *mut T;
        unsafe {
            copy_nonoverlapping(value, offset, 1_usize);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn modify_local_i32() {
        let test = 4_i32;
        let mut member = LocalMember::<i32>::new();
        member.set_offset(&test as *const _ as usize, vec![]);
        assert_eq!(test, member.read().unwrap());
        member.write(&5_i32).unwrap();
        assert_eq!(test, 5_i32);
    }
    #[test]
    fn modify_local_i64() {
        let test = 3_i64;
        let mut member = LocalMember::<i64>::new();
        member.set_offset(&test as *const _ as usize, vec![]);
        assert_eq!(test, member.read().unwrap());
        member.write(&-1_i64).unwrap();
        assert_eq!(test, -1);
    }
    #[test]
    fn modify_local_usize() {
        let test = 0_usize;
        let member = LocalMember::<usize>::new_addr(&test as *const _ as usize);
        assert_eq!(test, member.read().unwrap());
        member.write(&0xffff).unwrap();
        assert_eq!(test, 0xffff);
    }
}
