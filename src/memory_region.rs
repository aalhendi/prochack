use std::{ffi::c_void, ptr::NonNull};

use crate::MemoryRegionProtection;

/// Represents an allocated range of memory in a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    /// Start address (in process virtual address space) of region
    /// Using NonNull as it's guaranteed to be non-zero and covariant
    address: NonNull<u8>,
    /// Size of region in bytes
    size: usize,
    /// Memory protection flags for the region
    protection: MemoryRegionProtection,
}

impl MemoryRegion {
    /// Creates a new MemoryRegion with the specified address, size, and protection flags.
    ///
    /// # Arguments
    ///
    /// * `address` - Start address (in process virtual address space) of region
    /// * `size` - Number of bytes in region
    /// * `protection` - Flags representing memory protection properties
    ///
    /// # Examples
    ///
    /// ```
    /// use prochack::{MemoryRegion, MemoryRegionProtection};
    ///
    /// let region = MemoryRegion::new(
    ///     0x1000,
    ///     4096,
    ///     MemoryRegionProtection::READ | MemoryRegionProtection::WRITE
    /// );
    /// ```
    pub fn new(address: *mut c_void, size: usize, protection: MemoryRegionProtection) -> Self {
        let address = NonNull::new(address as *mut u8).expect("Unable to convert ptr to NonNull");
        Self {
            address,
            size,
            protection,
        }
    }

    /// Returns the start address (in process virtual address space) of the region.
    pub fn address(&self) -> NonNull<u8> {
        self.address
    }

    /// Returns the size (in bytes) of the region.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the protection properties of the region.
    pub fn protection(&self) -> MemoryRegionProtection {
        self.protection
    }
}
