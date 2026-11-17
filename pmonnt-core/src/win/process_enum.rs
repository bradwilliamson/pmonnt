//! Windows process enumeration implementation
//!
//! This module provides unsafe Windows API calls for process enumeration.
//! All unsafe blocks are documented with their invariants.

use crate::process::Process;
use crate::win::HandleGuard;
use anyhow::{Result, anyhow};
use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

/// Enumerate all running processes on the system.
///
/// Uses the wide-character ToolHelp API so executable names in any language come back
/// intact (the ANSI variant mangles anything outside the system code page).
pub fn enumerate_processes() -> Result<Vec<Process>> {
    // SAFETY: CreateToolhelp32Snapshot has no pointer arguments; on success the returned
    // handle is owned by us and closed by the guard below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(anyhow!("Failed to create process snapshot"));
    }
    // Owns the snapshot from here on, so every return path closes it.
    let snapshot = HandleGuard::new(snapshot);

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    // SAFETY: `entry` is a valid PROCESSENTRY32W with dwSize set, as the API requires.
    if unsafe { Process32FirstW(snapshot.raw(), &raw mut entry) }.is_err() {
        return Err(anyhow!("Failed to get first process"));
    }

    let mut processes = Vec::with_capacity(512);
    loop {
        processes.push(Process {
            pid: entry.th32ProcessID,
            name: wide_to_string(&entry.szExeFile),
            ppid: Some(entry.th32ParentProcessID),
            cpu_percent: None,
            memory_bytes: None,
            gpu_percent: None,
            gpu_memory_bytes: None,
            path: None,
            signature: None,
        });

        // SAFETY: same snapshot handle and entry buffer as above.
        if unsafe { Process32NextW(snapshot.raw(), &raw mut entry) }.is_err() {
            break;
        }
    }

    Ok(processes)
}

/// Convert a NUL-terminated UTF-16 buffer to a String, replacing invalid sequences.
fn wide_to_string(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_to_string_handles_non_ascii_and_missing_terminator() {
        let name: Vec<u16> = "日本語プロセス.exe\0garbage".encode_utf16().collect();
        assert_eq!(wide_to_string(&name), "日本語プロセス.exe");
        let unterminated: Vec<u16> = "Größe.exe".encode_utf16().collect();
        assert_eq!(wide_to_string(&unterminated), "Größe.exe");
    }

    #[test]
    fn enumerate_finds_current_process() {
        let me = std::process::id();
        let procs = enumerate_processes().unwrap();
        assert!(procs.iter().any(|p| p.pid == me && !p.name.is_empty()));
    }
}
