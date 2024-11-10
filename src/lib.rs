use std::ffi::c_void;

use memory_protection_region::MemoryRegionProtection;
use memory_region::MemoryRegion;
use windows::Win32::{
    Foundation::{HANDLE, HMODULE, MAX_PATH},
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT},
        ProcessStatus::{K32EnumProcessModules, K32EnumProcesses, K32GetModuleBaseNameA},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE},
    },
};

pub mod memory_protection_region;
mod memory_region;

/// Represents a Windows process with its associated handle and information.
///
/// This struct maintains a handle to a Windows process and provides methods
/// to query information about it. The handle is automatically closed when
/// the struct is dropped.
#[derive(Debug)]
pub struct Process {
    /// The process ID (PID) of the process
    pub pid: u32,
    /// Internal cache for the process name
    _name: String,
    /// Windows handle to the process
    pub handle: HANDLE,
}

impl Process {
    /// Creates a new Process instance from a process ID (PID).
    ///
    /// This function attempts to open a handle to the process with
    /// PROCESS_QUERY_INFORMATION and PROCESS_VM_READ permissions.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process ID to open
    ///
    /// # Returns
    ///
    /// * `Some(Process)` if the process was successfully opened
    /// * `None` if the process couldn't be opened (e.g., insufficient permissions)
    ///
    /// # Examples
    ///
    /// ```rust
    /// if let Some(process) = Process::new(1234) {
    ///     println!("Successfully opened process {}", process.pid);
    /// }
    /// ```
    pub fn new(pid: u32) -> Option<Self> {
        // Skip system process and idle process
        if pid == 0 || pid == 4 {
            return None;
        }

        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                false,
                pid,
            )
        };

        match handle {
            Ok(handle) => Some(Self {
                pid,
                _name: String::new(),
                handle,
            }),
            Err(_e) => {
                // eprintln!("{e}");
                None
            }
        }
    }

    /// Gets the name of the process (e.g., "firefox.exe").
    ///
    /// This method queries the process's first module to get its base name.
    /// For most processes, this is the executable name.
    ///
    /// # Returns
    ///
    /// The name of the process as a String. Returns an empty string if the
    /// name couldn't be retrieved.
    ///
    /// # Examples
    ///
    /// ```rust
    /// if let Some(process) = Process::new(1234) {
    ///     println!("Process name: {}", process.name());
    /// }
    /// ```
    pub fn name(&self) -> String {
        let mut module = Default::default();
        let mut bytes_needed = 0;
        unsafe {
            // API wants an array, but we only make one "module"'s worth of space and give it that.
            if !K32EnumProcessModules(
                self.handle,
                &mut module,
                size_of::<HMODULE>() as u32,
                &mut bytes_needed,
            )
            .as_bool()
            {
                panic!("Failed to get first module");
            }

            let mut buffer = vec![0u8; MAX_PATH as usize];
            let chars_written = K32GetModuleBaseNameA(self.handle, module, &mut buffer);

            if chars_written == 0 {
                return String::new();
            }

            let name = buffer[..chars_written as usize].to_vec();
            String::from_utf8(name).unwrap()
        }
    }

    /// Returns a list of memory regions in the process's address space.
    ///
    /// This method queries the process memory using VirtualQueryEx to get information
    /// about all memory regions. Only committed memory regions are included.
    ///
    /// # Returns
    ///
    /// A vector of MemoryRegion instances representing committed memory regions
    /// in the process's address space.
    ///
    /// # Examples
    ///
    /// ```rust
    /// if let Some(process) = Process::new(1234) {
    ///     for region in process.memory_regions() {
    ///         println!("Region at {:p} with size {}", region.address(), region.size());
    ///     }
    /// }
    /// ```
    pub fn memory_regions(&self) -> Vec<MemoryRegion> {
        let mut regions = Vec::new();
        let mut mem_info = Default::default();
        let mut addr = std::ptr::null_mut();
        unsafe {
            while VirtualQueryEx(
                self.handle,
                Some(addr),
                &mut mem_info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                if mem_info.State == MEM_COMMIT {
                    let r = MemoryRegion::new(
                        mem_info.BaseAddress,
                        mem_info.RegionSize,
                        mem_info.Protect.into(),
                    );
                    regions.push(r);
                    println!("{:p} {} {}", r.address(), r.size(), r.protection())
                }

                addr = addr.wrapping_add(mem_info.RegionSize);
            }
        }

        regions
    }

    /// Reads memory from the specified region in the process's address space.
    ///
    /// # Arguments
    ///
    /// * `region` - The MemoryRegion to read from
    ///
    /// # Returns
    ///
    /// A vector containing the bytes read from the specified memory region.
    /// The vector's length will match the number of bytes actually read.
    ///
    /// # Panics
    ///
    /// Panics if ReadProcessMemory fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// if let Some(process) = Process::new(1234) {
    ///     let regions = process.memory_regions();
    ///     if let Some(region) = regions.first() {
    ///         let memory = process.read(region);
    ///         println!("Read {} bytes from region", memory.len());
    ///     }
    /// }
    /// ```
    pub fn read(&self, region: &MemoryRegion) -> Vec<u8> {
        let mut mem = Vec::with_capacity(region.size());

        let mut bytes_read = 0;
        unsafe {
            if ReadProcessMemory(
                self.handle,
                region.address().as_ptr() as *mut c_void,
                mem.as_mut_ptr() as *mut c_void,
                mem.capacity(),
                Some(&mut bytes_read),
            )
            .is_err()
            {
                panic!("Failed to read memory region.");
            }
            mem.set_len(bytes_read);
        }

        mem
    }

    /// Writes data to the specified region in the process's address space.
    ///
    /// # Arguments
    ///
    /// * `region` - The MemoryRegion to write to
    /// * `data` - The bytes to write to the region
    ///
    /// # Panics
    ///
    /// * Panics if the data length exceeds the region size
    /// * Panics if WriteProcessMemory fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// if let Some(process) = Process::new(1234) {
    ///     let regions = process.memory_regions();
    ///     if let Some(region) = regions.first() {
    ///         let data = vec![0u8; 4];
    ///         process.write(*region, &data);
    ///     }
    /// }
    /// ```
    pub fn write(&self, region: MemoryRegion, data: &[u8]) {
        assert!(data.len() <= region.size()); // TODO(aalhendi): manage footgun
        unsafe {
            if WriteProcessMemory(
                self.handle,
                region.address().as_ptr() as *mut c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                None,
            )
            .is_err()
            {
                panic!("Failed to write memory region.")
            }
        }
    }
}

/// Retrieves a list of all process IDs in the system.
///
/// This function uses K32EnumProcesses to get a list of all running processes.
/// It automatically handles cases where there are more processes than the
/// initial buffer size by growing the buffer as needed.
///
/// # Returns
///
/// A vector containing the process IDs of all running processes.
///
/// # Panics
///
/// Panics if the Windows API call fails to enumerate processes.
fn get_pids() -> Vec<u32> {
    let mut pids = Vec::with_capacity(1024);
    let mut bytes_returned = 0;
    loop {
        let current_size = if pids.is_empty() {
            1024
        } else {
            pids.len() * 2
        };
        pids.resize(current_size, 0);

        unsafe {
            if !K32EnumProcesses(
                pids.as_mut_ptr(),
                (pids.len() * size_of::<u32>()) as u32,
                &mut bytes_returned,
            )
            .as_bool()
            {
                panic!("Failed to get PIDs");
            }
        }

        // got all processes
        if bytes_returned < (pids.len() * size_of::<u32>()) as u32 {
            let count = bytes_returned as usize / size_of::<u32>();
            pids.truncate(count);
            break;
        }

        // else buffer was full - need larger buffer for next iteration
    }

    pids
}

/// Finds all processes with a given name.
///
/// This function searches through all running processes and returns those
/// whose name matches the provided name exactly.
///
/// # Arguments
///
/// * `name` - The process name to search for (e.g., "firefox.exe")
///
/// # Returns
///
/// A vector of `Process` instances for all matching processes. The vector
/// will be empty if no matching processes are found.
///
/// # Examples
///
/// ```rust
/// let firefox_processes = find_process("firefox.exe");
/// println!("Found {} Firefox processes", firefox_processes.len());
/// ```
pub fn find_process(name: &str) -> Vec<Process> {
    let mut procs = Vec::new();

    for pid in get_pids() {
        if let Some(proc) = Process::new(pid) {
            if proc.name() == name {
                procs.push(proc);
            }
        }
    }

    procs
}

/// Searches for and replaces a pattern of bytes in a process's memory region.
///
/// # Arguments
///
/// * `process` - The process to modify memory in
/// * `region` - The memory region to search through
/// * `find` - The byte pattern to search for
/// * `replace` - The bytes to replace matches with
/// * `num_occurrences` - Optional limit on number of replacements to make. If None, replaces all occurrences
///
/// # Returns
///
/// * `Ok(usize)` - The number of replacements made
/// * `Err(std::io::Error)` - If memory read/write operations fail
///
/// # Examples
///
/// ```rust
/// let process = Process::new(1234).unwrap();
/// let region = process.memory_regions()[0];
///
/// // Replace first occurrence of "Hello" with "World"
/// let matches = replace_memory(
///     &process,
///     &region,
///     b"Hello",
///     b"World",
///     Some(1)
/// ).unwrap();
/// println!("Made {} replacements", matches);
/// ```
pub fn replace_memory(
    process: &Process,
    region: &MemoryRegion,
    find: &[u8],
    replace: &[u8],
    num_occurrences: Option<usize>,
) -> Result<usize, std::io::Error> {
    let memory = process.read(region);

    let mut matches = 0;
    let max_matches = num_occurrences.unwrap_or(usize::MAX);
    let search_range = 0..memory.len().saturating_sub(find.len());

    for i in search_range {
        if matches >= max_matches {
            break;
        }

        if memory[i..].starts_with(find) {
            process.write(
                MemoryRegion::new(
                    (region.address().as_ptr() as usize + i) as *mut c_void,
                    replace.len(),
                    region.protection(),
                ),
                replace,
            );
            matches += 1;
        }
    }

    Ok(matches)
}

/// Generic version of replace_memory that works with any Copy type.
///
/// Converts the input slices to byte arrays and calls the base replace_memory function.
/// Useful for replacing patterns of integers, wide strings, or other fixed-size types.
///
/// # Type Parameters
///
/// * `T` - Any type that implements Copy
///
/// # Arguments
///
/// * `process` - The process to modify memory in
/// * `region` - The memory region to search through
/// * `find` - The pattern to search for as a slice of T
/// * `replace` - The replacement pattern as a slice of T
/// * `num_occurrences` - Optional limit on number of replacements to make
///
/// # Returns
///
/// * `Ok(usize)` - The number of replacements made
/// * `Err(std::io::Error)` - If memory read/write operations fail
///
/// # Safety
///
/// Uses unsafe code to convert typed slices to byte slices. The conversion assumes
/// the memory layout of T is contiguous with no padding.
///
/// # Examples
///
/// ```rust
/// let process = Process::new(1234).unwrap();
/// let region = process.memory_regions()[0];
///
/// // Replace wide string using u16 slice
/// let find: Vec<u16> = "Hello".encode_utf16().collect();
/// let replace: Vec<u16> = "World".encode_utf16().collect();
///
/// let matches = replace_memory_generic(
///     &process,
///     &region,
///     &find,
///     &replace,
///     Some(1)
/// ).unwrap();
/// ```
pub fn replace_memory_generic<T: Copy>(
    process: &Process,
    region: &MemoryRegion,
    find: &[T],
    replace: &[T],
    num_occurrences: Option<usize>,
) -> Result<usize, std::io::Error> {
    let find_bytes = unsafe {
        std::slice::from_raw_parts(find.as_ptr() as *const u8, std::mem::size_of_val(find))
    };

    let replace_bytes = unsafe {
        std::slice::from_raw_parts(
            replace.as_ptr() as *const u8,
            std::mem::size_of_val(replace),
        )
    };

    replace_memory(process, region, find_bytes, replace_bytes, num_occurrences)
}
