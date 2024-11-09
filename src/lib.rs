use windows::Win32::{
    Foundation::{HANDLE, HMODULE, MAX_PATH},
    System::{
        ProcessStatus::{K32EnumProcessModules, K32EnumProcesses, K32GetModuleBaseNameA},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

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

        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) };

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
        unsafe {
            let mut module = std::mem::zeroed();
            let mut bytes_needed = 0;
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
