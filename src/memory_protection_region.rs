use std::fmt;

use bitflags::bitflags;
use windows::Win32::System::Memory::{
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE,
};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MemoryRegionProtection: u32 {
        const NO_PROTECTION = 0;
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
    }
}

impl fmt::Display for MemoryRegionProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "NO_PROTECTION");
        }

        let mut parts = Vec::new();
        if self.contains(Self::READ) {
            parts.push("READ");
        }
        if self.contains(Self::WRITE) {
            parts.push("WRITE");
        }
        if self.contains(Self::EXECUTE) {
            parts.push("EXECUTE");
        }

        write!(f, "{}", parts.join(" | "))
    }
}

impl From<PAGE_PROTECTION_FLAGS> for MemoryRegionProtection {
    /// Converts a Win32 memory protection value into our internal library type.
    fn from(protection: PAGE_PROTECTION_FLAGS) -> Self {
        match protection {
            p if p == PAGE_EXECUTE => Self::EXECUTE,
            p if p == PAGE_READONLY => Self::READ,
            p if p == PAGE_READWRITE => Self::READ | Self::WRITE,
            p if p == PAGE_EXECUTE_READ => Self::READ | Self::EXECUTE,
            p if p == PAGE_EXECUTE_READWRITE => Self::READ | Self::WRITE | Self::EXECUTE,
            _ => Self::NO_PROTECTION,
        }
    }
}

impl From<MemoryRegionProtection> for PAGE_PROTECTION_FLAGS {
    /// Converts our protection flags to the equivalent Win32 protection constant.
    fn from(protection: MemoryRegionProtection) -> Self {
        match protection {
            p if p == MemoryRegionProtection::EXECUTE => PAGE_EXECUTE,
            p if p == MemoryRegionProtection::READ => PAGE_READONLY,
            p if p == (MemoryRegionProtection::READ | MemoryRegionProtection::WRITE) => {
                PAGE_READWRITE
            }
            p if p == (MemoryRegionProtection::READ | MemoryRegionProtection::EXECUTE) => {
                PAGE_EXECUTE_READ
            }
            p if p
                == (MemoryRegionProtection::READ
                    | MemoryRegionProtection::WRITE
                    | MemoryRegionProtection::EXECUTE) =>
            {
                PAGE_EXECUTE_READWRITE
            }
            // TODO(aalhendi): Verify default behavior
            _ => PAGE_READONLY, // Default to read-only if no match
        }
    }
}
