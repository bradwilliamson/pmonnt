use pmonnt_core::services;
use windows::Win32::System::Services::{
    SERVICE_CONTINUE_PENDING, SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

fn main() {
    // Test with known PIDs
    let dsa_pid = 5152; // DSAService.exe
    let brave_pid = 3648; // Brave.exe

    println!(
        "Testing service enumeration for DSAService.exe (PID {})",
        dsa_pid
    );
    match services::get_services_for_process(dsa_pid) {
        Ok(services) => {
            println!("Found {} services:", services.len());
            for svc in &services {
                println!("  - {} ({:?})", svc.name, svc.status);
            }
        }
        Err(e) => println!("Error: {}", e),
    }

    println!(
        "\nTesting service enumeration for Brave.exe (PID {})",
        brave_pid
    );
    match services::get_services_for_process(brave_pid) {
        Ok(services) => {
            println!("Found {} services:", services.len());
            for svc in &services {
                println!("  - {} ({:?})", svc.name, svc.status);
            }
        }
        Err(e) => println!("Error: {}", e),
    }

    // Also test enumerate_all_services directly (which calls enumerate_all_services_basic)
    println!("\n--- Testing enumerate_all_services ---");
    match pmonnt_core::services::enumerate_all_services() {
        Ok(all) => {
            let running: Vec<_> = all
                .iter()
                .filter(|s| matches!(s.status, pmonnt_core::services::ServiceStatus::Running))
                .collect();
            println!("Total services: {}, Running: {}", all.len(), running.len());

            // Search for Brave services
            println!("\nSearching for 'Brave' services:");
            let brave_services: Vec<_> = all
                .iter()
                .filter(|s| {
                    s.name.to_lowercase().contains("brave")
                        || s.display_name.to_lowercase().contains("brave")
                })
                .collect();
            for svc in brave_services {
                println!(
                    "  Found: {} ({}) - PID: {:?}",
                    svc.name, svc.display_name, svc.pid
                );
            }

            // Print first 5 running services
            for svc in running.iter().take(5) {
                println!("  Running: {} (PID {:?})", svc.name, svc.pid);
            }

            // Try to find a PID from the services to test get_services_for_process
            if let Some(svc_with_pid) = all.iter().find(|s| s.pid.is_some()) {
                let test_pid = svc_with_pid.pid.unwrap();
                println!("\nTesting service enumeration for PID {}", test_pid);

                match pmonnt_core::services::get_services_for_process(test_pid) {
                    Ok(services) => {
                        println!("Found {} services:", services.len());
                        for svc in &services {
                            println!(
                                "  - {} ({:?}) - PID: {:?}",
                                svc.name,
                                svc.status, // <-- This is the key field to check
                                svc.pid
                            );
                        }
                    }
                    Err(e) => {
                        println!("Error: {}", e);
                    }
                }
            } else {
                println!("Could not find any service with a PID to test get_services_for_process");
            }
        }
        Err(e) => println!("Error: {}", e),
    }

    println!("\n--- Windows API Constants ---");
    println!("SERVICE_STOPPED = {}", SERVICE_STOPPED.0);
    println!("SERVICE_START_PENDING = {}", SERVICE_START_PENDING.0);
    println!("SERVICE_STOP_PENDING = {}", SERVICE_STOP_PENDING.0);
    println!("SERVICE_RUNNING = {}", SERVICE_RUNNING.0);
    println!("SERVICE_CONTINUE_PENDING = {}", SERVICE_CONTINUE_PENDING.0);
    println!("SERVICE_PAUSE_PENDING = {}", SERVICE_PAUSE_PENDING.0);
    println!("SERVICE_PAUSED = {}", SERVICE_PAUSED.0);
}
