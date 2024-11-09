use prochack::find_process;

fn main() {
    for proc in find_process("firefox.exe") {
        println!("{name} -> {id}", name = proc.name(), id = proc.pid);
        proc.memory_regions();
    }
}
