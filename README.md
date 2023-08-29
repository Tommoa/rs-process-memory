# process-memory
[![](https://img.shields.io/crates/v/process-memory.svg)](https://crates.io/crates/process-memory)
[![](https://docs.rs/process-memory/badge.svg)](https://docs.rs/process-memory)
![Continuous Integration](https://github.com/Tommoa/rs-process-memory/workflows/Continuous%20integration/badge.svg)

This crate is loosely based on [`read-process-memory`](https://github.com/luser/read-process-memory) by luser, but has been extended to be able to write to process memory as well.

The current supported platforms are:
 - Windows
 - OSX
 - Linux

Some examples of use cases for this tool are:
 - Remote debugging tools
 - Game "trainers"
 - Rust clones of Cheat Engine

## Examples
```rust
// We need the following from process-memory
# use process_memory::{Memory, DataMember, Pid, TryIntoProcessHandle};

// We have a variable with some value
let x = 4_u32;


// We need to make sure that we get a handle to a process
// that we want to read from, in this case, ourselves
let handle = ( std::process::id() as Pid ).try_into_process_handle().unwrap();

// We make a `DataMember` that has an offset referring to the location
// of our variable x in memory
let member = DataMember::new_offset(handle, vec![&x as *const _ as usize]);

// Variable member and x now refer to the same memory
assert_eq!(&x as *const _ as usize, member.get_offset().unwrap());

// The value of member is the same as x
assert_eq!(x, unsafe { member.read().unwrap() });

// We can write to and modify the value of x using member
member.write(&6_u32).unwrap();
assert_eq!(x, 6_u32);
```


```rust
# use process_memory::{Memory, LocalMember};

// We have a variable with some value
let x = 4_u32;

// We make a `LocalMember` that has an offset referring to its location in memory
let member = LocalMember::new_offset(vec![&x as *const _ as usize]);

// The memory refered to is now the same
assert_eq!(&x as *const _ as usize, member.get_offset().unwrap());

// The value of the member is the same as the variable
assert_eq!(x, unsafe { member.read().unwrap() });

// We can write to and modify the value of the variable using the member
member.write(&6_u32).unwrap();
assert_eq!(x, 6_u32);
```

```no_run
# use process_memory::{Architecture, Memory, DataMember, Pid, ProcessHandleExt, TryIntoProcessHandle};
# fn get_pid(process_name: &str) -> Pid {
#     std::process::id() as Pid
# }

// We get a handle for a target process with a different architecture to ourselves
let handle = get_pid("32Bit.exe").try_into_process_handle().unwrap()
    .set_arch(Architecture::Arch32Bit);

// We make a `DataMember` that has a series of offsets refering to a known value in
// the target processes memory
let member = DataMember::new_offset(handle, vec![0x01_02_03_04, 0x04, 0x08, 0x10]);

// The memory offset can now be correctly calculated:
let targetMemoryLocation = member.get_offset().unwrap();

// The memory offset can now be used to retrieve and modify values:
let currentValue = unsafe { member.read().unwrap() };

member.write(&123_u32).unwrap();
```
