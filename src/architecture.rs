use std::convert::TryInto;

/// Enum representing the architecture of a process
#[derive(Clone, Debug, Copy)]
#[repr(u8)]
pub enum Architecture {
    /// 8-bit architecture
    #[cfg(any(
        target_pointer_width = "8",
        target_pointer_width = "16",
        target_pointer_width = "32",
        target_pointer_width = "64",
        target_pointer_width = "128"
    ))]
    Arch8Bit = 1,
    /// 16-bit architecture
    #[cfg(any(
        target_pointer_width = "16",
        target_pointer_width = "32",
        target_pointer_width = "64",
        target_pointer_width = "128"
    ))]
    Arch16Bit = 2,
    /// 32-bit architecture
    #[cfg(any(
        target_pointer_width = "32",
        target_pointer_width = "64",
        target_pointer_width = "128"
    ))]
    Arch32Bit = 4,
    /// 64-bit architecture
    #[cfg(any(target_pointer_width = "64", target_pointer_width = "128"))]
    Arch64Bit = 8,
    /// 128-bit architecture
    #[cfg(target_pointer_width = "128")]
    Arch128Bit = 16,
}

impl Architecture {
    /// Create an Architecture matching that of the host process.
    pub fn from_native() -> Architecture {
        #[cfg(target_pointer_width = "8")]
        return Architecture::Arch8Bit;
        #[cfg(target_pointer_width = "16")]
        return Architecture::Arch16Bit;
        #[cfg(target_pointer_width = "32")]
        return Architecture::Arch32Bit;
        #[cfg(target_pointer_width = "64")]
        return Architecture::Arch64Bit;
        #[cfg(target_pointer_width = "128")]
        return Architecture::Arch128Bit;
    }

    /// Convert bytes read from memory into a pointer in the
    /// current architecture.
    pub fn pointer_from_ne_bytes(self, bytes: &[u8]) -> usize {
        match self {
            #[cfg(any(
                target_pointer_width = "8",
                target_pointer_width = "16",
                target_pointer_width = "32",
                target_pointer_width = "64",
                target_pointer_width = "128"
            ))]
            Architecture::Arch8Bit => {
                u8::from_ne_bytes(bytes.try_into().unwrap()) as usize
            }
            #[cfg(any(
                target_pointer_width = "16",
                target_pointer_width = "32",
                target_pointer_width = "64",
                target_pointer_width = "128"
            ))]
            Architecture::Arch16Bit => {
                u16::from_ne_bytes(bytes.try_into().unwrap()) as usize
            }
            #[cfg(any(
                target_pointer_width = "32",
                target_pointer_width = "64",
                target_pointer_width = "128"
            ))]
            Architecture::Arch32Bit => {
                u32::from_ne_bytes(bytes.try_into().unwrap()) as usize
            }
            #[cfg(any(target_pointer_width = "64", target_pointer_width = "128"))]
            Architecture::Arch64Bit => {
                u64::from_ne_bytes(bytes.try_into().unwrap()) as usize
            }
            #[cfg(target_pointer_width = "128")]
            Architecture::Arch128Bit => {
                u128::from_ne_bytes(bytes.try_into().unwrap()) as usize
            }
        }
    }
}
