//! Windows process enumeration implementation
//!
//! This module provides unsafe Windows API calls for process enumeration.
//! All unsafe blocks are documented with their invariants.

use crate::process::Process;
use crate::win::HandleGuard;
use anyhow::{anyhow, Result};
use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

/// Enumerate all running processes on the system
///
/// # Safety
/// This function uses Windows API calls that are inherently unsafe.
/// The invariants are:
/// - All handles are properly closed using CloseHandle
/// - Memory is managed by Rust's ownership system
/// - No dangling pointers or use-after-free
pub fn enumerate_processes() -> Result<Vec<Process>> {
    let mut processes = Vec::new();

    // SAFETY: CreateToolhelp32Snapshot is a Windows API that creates a snapshot
    // of the current processes. The handle returned is valid and must be closed.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };

    if snapshot == INVALID_HANDLE_VALUE {
        return Err(anyhow!("Failed to create process snapshot"));
    }

    // SAFETY: Creating zero-initialized POD struct PROCESSENTRY32 which will be filled by Process32First
    let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    // SAFETY: Process32First enumerates the first process in the snapshot.
    // The process_entry structure is properly initialized with dwSize.
    let success = unsafe { Process32First(snapshot, &mut process_entry) };

    if success.is_err() {
        // SAFETY: Close the snapshot handle even on failure
        drop(HandleGuard::new(snapshot));
        return Err(anyhow!("Failed to get first process"));
    }

    loop {
        // Convert the ANSI string to a Rust String
        let name = ansi_to_string(&process_entry.szExeFile)?;

        let process = Process {
            pid: process_entry.th32ProcessID,
            name,
            ppid: Some(process_entry.th32ParentProcessID),
            cpu_percent: None,
            memory_bytes: None,
            gpu_percent: None,
            gpu_memory_bytes: None,
            path: None,
            signature: None,
        };

        processes.push(process);

        // SAFETY: Process32Next enumerates the next process in the snapshot.
        // The process_entry structure remains valid for reuse.
        let success = unsafe { Process32Next(snapshot, &mut process_entry) };

        if success.is_err() {
            break;
        }
    }

    // SAFETY: Close the snapshot handle when done (HandleGuard will close on drop)
    drop(HandleGuard::new(snapshot));

    Ok(processes)
}

/// Convert an ANSI (8-bit) string to a Rust String
fn ansi_to_string(ansi: &[i8]) -> Result<String> {
    // Find the null terminator
    let len = ansi.iter().position(|&c| c == 0).unwrap_or(ansi.len());

    // Convert i8 to u8 (safe since we're dealing with ASCII/ANSI)
    let bytes: Vec<u8> = ansi[..len].iter().map(|&c| c as u8).collect();

    String::from_utf8(bytes).map_err(|_| anyhow!("Invalid ANSI string"))
}
