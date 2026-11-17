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
            create_time: None,
        });

        // SAFETY: same snapshot handle and entry buffer as above.
        if unsafe { Process32NextW(snapshot.raw(), &raw mut entry) }.is_err() {
            break;
        }
    }

    fill_create_times(&mut processes);
    Ok(processes)
}

/// Attach creation times from one `SystemProcessInformation` query.
///
/// ToolHelp does not report creation times. A process that exits between the two queries is
/// left without one, and a PID recycled in that window is caught by its parent PID no longer
/// matching, so a process never receives another instance's creation time.
fn fill_create_times(processes: &mut [Process]) {
    let entries = match crate::win::process_metrics::query_system_processes() {
        Ok(entries) => entries,
        Err(e) => {
            log::debug!("SystemProcessInformation query for creation times failed: {e}");
            return;
        }
    };
    let by_pid: crate::snapshot::PidMap<(u32, u64)> = entries
        .iter()
        .map(|e| (e.pid, (e.parent_pid, e.create_time)))
        .collect();
    for process in processes {
        if let Some(&(parent_pid, create_time)) = by_pid.get(&process.pid)
            && process.ppid == Some(parent_pid)
        {
            process.create_time = Some(create_time);
        }
    }
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

    #[test]
    fn enumerate_reports_creation_times() {
        let me = std::process::id();
        let procs = enumerate_processes().unwrap();
        let mine = procs.iter().find(|p| p.pid == me).unwrap();
        let expected = crate::win::process_metrics::system_process_entry(me)
            .unwrap()
            .create_time;
        assert_eq!(mine.create_time, Some(expected));
        assert!(expected > 0);
    }
}
