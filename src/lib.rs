use windows::Win32::{
    Foundation::{HANDLE, HMODULE, MAX_PATH},
    System::{
        ProcessStatus::{K32EnumProcessModules, K32EnumProcesses, K32GetModuleBaseNameA},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

pub struct Process {
    pub pid: u32,
    _name: String,
    pub handle: HANDLE,
}

impl Process {
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
