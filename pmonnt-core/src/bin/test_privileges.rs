use pmonnt_core::win::token_info::get_process_security_info;

fn main() {
    // Test on self
    let pid = std::process::id();
    println!("Testing privilege query on self (PID {})", pid);

    match get_process_security_info(pid) {
        Ok(info) => {
            println!("\n=== Security Info ===");
            println!("User: {}", info.summary.user);
            println!("Groups: {} entries", info.groups.len());
            if let Some(err) = &info.groups_error {
                println!("  Groups error: {}", err);
            }

            println!("\nPrivileges: {} entries", info.privileges.len());
            if let Some(err) = &info.privileges_error {
                println!("  Privileges error: {}", err);
            } else {
                for p in &info.privileges {
                    println!(
                        "  {} - {} (enabled: {}, attrs: {:?})",
                        p.name, p.display, p.enabled, p.attributes
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to get security info: {}", e);
            std::process::exit(1);
        }
    }
}
