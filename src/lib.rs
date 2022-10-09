#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(unused_results)]
#![deny(unreachable_pub)]
#![deny(missing_debug_implementations)]
#![deny(rust_2018_idioms)]
#![deny(bad_style)]
#![deny(unused)]
#![deny(clippy::pedantic)]

mod architecture;
mod data_member;
mod local_member;

pub use architecture::Architecture;
pub use data_member::DataMember;
pub use local_member::LocalMember;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod platform;
#[cfg(windows)]
#[path = "windows.rs"]
mod platform;

/// A trait that defines that it is possible to copy some memory from something represented by a
/// type into a buffer.
pub trait CopyAddress {
    /// Copy an address into user-defined buffer.
    ///
    /// # Errors
    /// `std::io::Error` if an error occurs copying the address.
    fn copy_address(&self, addr: usize, buf: &mut [u8]) -> std::io::Result<()>;

    /// Get the actual memory location from a set of offsets.
    ///
    /// If [`copy_address`] and [`get_pointer_width`] are already defined, then
    /// we can provide a standard implementation that will work across all
    /// operating systems.
    ///
    /// # Errors
    /// `std::io::Error` if an error occurs copying the address.
    ///
    /// [`copy_address`]: #tymethod.copy_address
    /// [`get_pointer_width`]: #tymethod.get_pointer_width
    fn get_offset(&self, offsets: &[usize]) -> std::io::Result<usize> {
        // Look ma! No unsafes!
        let mut offset: usize = 0;
        let noffsets: usize = offsets.len();
        let mut copy = vec![0_u8; self.get_pointer_width() as usize];
        for next_offset in offsets.iter().take(noffsets - 1) {
            offset += next_offset;
            self.copy_address(offset, &mut copy)?;
            offset = self.get_pointer_width().pointer_from_ne_bytes(&copy);
        }

        offset += offsets[noffsets - 1];
        Ok(offset)
    }

    /// Get the the pointer width of the underlying process.
    /// This is required for [`get_offset`] to work.
    ///
    /// # Performance
    /// Any implementation of this function should be marked with
    /// `#[inline(always)]` as this function is *very* commonly called and
    /// should be inlined.
    ///
    /// [`get_offset`]: #method.get_offset
    fn get_pointer_width(&self) -> Architecture;
}

/// A trait that defines that it is possible to put a buffer into the memory of something
/// represented by a type.
pub trait PutAddress {
    /// Put the data from a user-defined buffer at an address.
    ///
    /// # Errors
    /// `std::io::Error` if an error occurs copying the address.
    fn put_address(&self, addr: usize, buf: &[u8]) -> std::io::Result<()>;
}

/// A `Pid` is a "process id". Each different platform has a different method for uniquely
/// identifying a process. You can see what the Rust standard library uses for your platform by
/// looking at `std::process::id`.
pub use platform::Pid;
/// A `ProcessHandle` is a variable type that allows for access to functions that can manipulate
/// other processes. On platforms other than Linux, this is typically a different type than
/// [`Pid`], and thus it is a distinct type here.
///
/// [`Pid`]: type.Pid.html
pub use platform::ProcessHandle;

/// A trait that attempts to turn some type into a [`ProcessHandle`] so memory can be either copied
/// or placed into it.
///
/// [`ProcessHandle`]: type.ProcessHandle.html
pub trait TryIntoProcessHandle {
    /// Attempt to turn a type into a [`ProcessHandle`]. Whilst Linux provides the same type for
    /// [`Pid`]s and [`ProcessHandle`]s, Windows and macOS do not. As such, you need to ensure that
    /// `try_into_process_handle` is called on all [`Pid`]s to ensure cross-platform capabilities.
    ///
    /// # Errors
    /// Returns an error if the type cannot be turned into a [`ProcessHandle`]
    ///
    /// [`ProcessHandle`]: type.ProcessHandle.html
    /// [`Pid`]: type.Pid.html
    fn try_into_process_handle(&self) -> std::io::Result<ProcessHandle>;
}

impl TryIntoProcessHandle for ProcessHandle {
    fn try_into_process_handle(&self) -> std::io::Result<platform::ProcessHandle> {
        Ok(*self)
    }
}

/// Additional functions on process handles
pub trait ProcessHandleExt {
    /// Returns `true` if the [`ProcessHandle`] is not null, and `false` otherwise.
    fn check_handle(&self) -> bool;
    /// Return the null equivalent of a [`ProcessHandle`].
    #[must_use]
    fn null_type() -> ProcessHandle;
    /// Set this handle to use some architecture
    #[must_use]
    fn set_arch(self, arch: Architecture) -> Self;
}

/// A trait that refers to and allows writing to a region of memory in a running program.
pub trait Memory<T> {
    /// Set the offsets to the location in memory. This is used for things such as multi-level
    /// pointers, such as a `Vec<Vec<T>>` or a `Vec<String>`.
    ///
    /// For those sorts of data structures, to access data you need to go via multiple pointers, so
    /// that if an inner region reallocates its size, the variable that is being modified will be
    /// correctly modified.
    fn set_offset(&mut self, new_offsets: Vec<usize>);

    /// Gets the actual total offset from the offsets given by [`Memory::set_offset`].
    ///
    /// This function is safe because it should never internally allow for a null pointer
    /// deference, and instead should return a `std::io::Error` with a `std::io::ErrorKind` of
    /// `Other`.
    ///
    /// # Errors
    /// Returns an error if copying memory fails or if a null pointer dereference would
    /// otherwise occur.
    ///
    /// [`Memory::set_offset`]: trait.Memory.html#tymethod.set_offset
    fn get_offset(&self) -> std::io::Result<usize>;

    /// Reads the value of the pointer from the offsets given by [`Memory::set_offset`].
    ///
    /// This function should never internally allow for a null pointer deference, and instead
    /// should return a `std::io::Error` with a `std::io::ErrorKind` of `Other`.
    ///
    /// # Safety
    /// This function is marked as unsafe as it may cause undefined behavior.
    ///
    /// The function will attempt to read a `T` from uncontrolled memory, and so may produce an
    /// invalid value (e.g. a value of `2` for a `bool`, which is [undefined]. The caller _must_
    /// ensure that the data being read is valid for a `T`, or should get an equivalent integer
    /// representation and check the bit pattern themselves.
    ///
    /// # Errors
    /// Returns an error if copying memory fails or if a null pointer dereference would
    /// otherwise occur.
    ///
    /// [`Memory::set_offset`]: trait.Memory.html#tymethod.set_offset
    /// [undefined]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html
    unsafe fn read(&self) -> std::io::Result<T>;

    /// Writes `value` to the pointer from the offsets given by [`Memory::set_offset`].
    ///
    /// This function is safe because it should never internally allow for a null pointer
    /// deference, and instead should return a `std::io::Error` with a `std::io::ErrorKind` of
    /// `Other`.
    ///
    /// This function takes a reference instead of taking ownership so if the caller passes in a
    /// `String` or a `Vec`, it does not have to be cloned.
    ///
    /// # Errors
    /// Returns an error if copying memory fails or if a null pointer dereference would
    /// otherwise occur.
    ///
    /// [`Memory::set_offset`]: trait.Memory.html#tymethod.set_offset
    fn write(&self, value: &T) -> std::io::Result<()>;
}

/// Copy `length` bytes of memory at `addr` from `source`.
///
/// This is just a convenient way to call [`CopyAddress::copy_address`] without
/// having to provide your own buffer.
///
/// # Errors
/// Returns an error if copying memory fails
pub fn copy_address<T>(addr: usize, length: usize, source: &T) -> std::io::Result<Vec<u8>>
where
    T: CopyAddress,
{
    let mut copy = vec![0; length];

    source.copy_address(addr, &mut copy)?;
    Ok(copy)
}
