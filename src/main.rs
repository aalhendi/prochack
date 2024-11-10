use prochack::memory_protection_region::MemoryRegionProtection;
use prochack::{find_process, replace_memory_generic};

fn main() {
    for proc in find_process("Notepad.exe") {
        println!("{name} -> {id}", name = proc.name(), id = proc.pid);
        for region in proc.memory_regions() {
            if region
                .protection()
                .contains(MemoryRegionProtection::READ | MemoryRegionProtection::WRITE)
            {
                let pattern = "mom".encode_utf16().collect::<Vec<u16>>();
                let replacement = "MOM".encode_utf16().collect::<Vec<u16>>();
                replace_memory_generic(&proc, &region, &pattern, &replacement, Some(1))
                    .expect("failed to replace mem.");
            }
        }
    }
}
