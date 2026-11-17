//! Windows-only developer utility; on other platforms it just reports that.

#[cfg(windows)]
mod imp {
    use pmonnt_core::process;

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        println!("Testing process enumeration...");

        let processes = process::enumerate_processes()?;
        println!("Found {} processes", processes.len());

        println!("First 10 processes:");
        for process in processes.iter().take(10) {
            println!("PID {}: {}", process.pid, process.name);
        }

        Ok(())
    }
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    imp::main()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("test_processes only runs on Windows");
}
