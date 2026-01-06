use pmonnt_core::process;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing process enumeration...");

    let processes = process::enumerate_processes()?;
    println!("Found {} processes", processes.len());

    println!("First 10 processes:");
    for process in processes.iter().take(10) {
        println!("PID {}: {}", process.pid, process.name);
    }

    Ok(())
}
