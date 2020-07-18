# process-memory
[![](https://img.shields.io/crates/v/process-memory.svg)](https://crates.io/crates/process-memory)
[![](https://docs.rs/process-memory/badge.svg)](https://docs.rs/process-memory)
![Continuous Integration](https://github.com/Tommoa/rs-process-memory/workflows/Continuous%20integration/badge.svg)

This crate is loosely based on [`read-process-memory`](https://github.com/luser/read-process-memory) by luser, but has been extended to be able to write to process memory as well.

The current supported platforms are:
 - Windows
 - OSX
 - Linux

## Examples
```rust
use process_memory::{Memory, DataMember, Pid, TryIntoProcessHandle};
// We have a variable with some value
let x = 4_u32;
println!("Original x-value: {}", x);

// We need to make sure that we get a handle to a process, in this case, ourselves
let handle = (std::process::id() as Pid).try_into_process_handle().unwrap();
// We make a `DataMember` that has an offset referring to its location in memory
let member = DataMember::new_offset(handle, vec![&x as *const _ as usize]);
// The memory refered to is now the same
println!("Memory location: &x: {}, member: {}", &x as *const _ as usize,
    member.get_offset().unwrap());
assert_eq!(&x as *const _ as usize, member.get_offset().unwrap());
// The value of the member is the same as the variable
println!("Member value: {}", member.read().unwrap());
assert_eq!(x, member.read().unwrap());
// We can write to and modify the value of the variable using the member
member.write(&6_u32).unwrap();
println!("New x-value: {}", x);
assert_eq!(x, 6_u32);
```
```rust
use process_memory::{Memory, LocalMember};
// We have a variable with some value
let x = 4_u32;
println!("Original x-value: {}", x);

// We make a `LocalMember` that has an offset referring to its location in memory
let member = LocalMember::new_offset(vec![&x as *const _ as usize]);
// The memory refered to is now the same
println!("Memory location: &x: {}, member: {}", &x as *const _ as usize,
    member.get_offset().unwrap());
assert_eq!(&x as *const _ as usize, member.get_offset().unwrap());
// The value of the member is the same as the variable
println!("Member value: {}", member.read().unwrap());
assert_eq!(x, member.read().unwrap());
// We can write to and modify the value of the variable using the member
member.write(&6_u32).unwrap();
println!("New x-value: {}", x);
assert_eq!(x, 6_u32);
```
