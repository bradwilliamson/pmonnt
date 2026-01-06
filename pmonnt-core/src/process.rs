//! Process enumeration functionality

use anyhow::Result;

use crate::SignatureInfo;

/// Represents a Windows process
#[derive(Debug, Clone, PartialEq)]
pub struct Process {
    /// Process ID
    pub pid: u32,
    /// Process image name (e.g., "explorer.exe")
    pub name: String,
    /// Parent Process ID (optional)
    pub ppid: Option<u32>,
    /// CPU percentage (0.0 - 100.0+), calculated from kernel+user time delta
    pub cpu_percent: Option<f32>,
    /// Working set size in bytes
    pub memory_bytes: Option<u64>,
    /// GPU utilization percentage (0.0 - 100.0)
    pub gpu_percent: Option<f32>,
    /// Dedicated GPU memory in bytes (VRAM)
    pub gpu_memory_bytes: Option<u64>,

    /// Full executable path
    pub path: Option<String>,

    /// Digital signature information
    pub signature: Option<SignatureInfo>,
}

/// Get a list of all running processes
pub fn enumerate_processes() -> Result<Vec<Process>> {
    crate::win::process_enum::enumerate_processes()
}

/// Get the total count of running processes
pub fn get_process_count() -> Result<usize> {
    Ok(enumerate_processes()?.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_processes() {
        let processes = enumerate_processes().unwrap();
        assert!(!processes.is_empty());
        // Should have at least system processes
        assert!(processes.len() >= 5);
    }

    #[test]
    fn test_get_process_count() {
        let count = get_process_count().unwrap();
        assert!(count > 0);
    }
}
