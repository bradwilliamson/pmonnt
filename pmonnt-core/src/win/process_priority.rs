//! Process priority and affinity control.
//!
//! Provides safe wrappers around Windows process scheduling APIs.

use crate::win::HandleGuard;
use thiserror::Error;
use windows::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, HANDLE, WIN32_ERROR,
};
use windows::Win32::System::Threading::{
    GetPriorityClass, GetProcessAffinityMask, OpenProcess, SetPriorityClass,
    SetProcessAffinityMask, ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS,
    HIGH_PRIORITY_CLASS, IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION, REALTIME_PRIORITY_CLASS,
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PriorityError {
    #[error("Access denied - may require elevation")]
    AccessDenied,

    #[error("Process not found (PID {0})")]
    ProcessNotFound(u32),

    #[error("Invalid affinity mask - must have at least one CPU")]
    InvalidAffinityMask,

    #[error("Realtime priority requires elevation")]
    RealtimeRequiresElevation,

    #[error("Windows error: {0}")]
    Win32(u32),
}

/// Process priority class (matches Windows priority classes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PriorityClass {
    Idle,
    BelowNormal,
    Normal,
    AboveNormal,
    High,
    Realtime,
}

impl PriorityClass {
    fn to_win32(self) -> windows::Win32::System::Threading::PROCESS_CREATION_FLAGS {
        match self {
            PriorityClass::Idle => IDLE_PRIORITY_CLASS,
            PriorityClass::BelowNormal => BELOW_NORMAL_PRIORITY_CLASS,
            PriorityClass::Normal => NORMAL_PRIORITY_CLASS,
            PriorityClass::AboveNormal => ABOVE_NORMAL_PRIORITY_CLASS,
            PriorityClass::High => HIGH_PRIORITY_CLASS,
            PriorityClass::Realtime => REALTIME_PRIORITY_CLASS,
        }
    }

    fn from_win32(value: u32) -> Option<Self> {
        match value {
            v if v == IDLE_PRIORITY_CLASS.0 => Some(PriorityClass::Idle),
            v if v == BELOW_NORMAL_PRIORITY_CLASS.0 => Some(PriorityClass::BelowNormal),
            v if v == NORMAL_PRIORITY_CLASS.0 => Some(PriorityClass::Normal),
            v if v == ABOVE_NORMAL_PRIORITY_CLASS.0 => Some(PriorityClass::AboveNormal),
            v if v == HIGH_PRIORITY_CLASS.0 => Some(PriorityClass::High),
            v if v == REALTIME_PRIORITY_CLASS.0 => Some(PriorityClass::Realtime),
            _ => None,
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            PriorityClass::Idle => "Idle",
            PriorityClass::BelowNormal => "Below Normal",
            PriorityClass::Normal => "Normal",
            PriorityClass::AboveNormal => "Above Normal",
            PriorityClass::High => "High",
            PriorityClass::Realtime => "Realtime",
        }
    }

    pub fn all() -> &'static [PriorityClass] {
        &[
            PriorityClass::Idle,
            PriorityClass::BelowNormal,
            PriorityClass::Normal,
            PriorityClass::AboveNormal,
            PriorityClass::High,
            PriorityClass::Realtime,
        ]
    }
}

/// CPU affinity information.
#[derive(Debug, Clone)]
pub struct AffinityInfo {
    /// Current process affinity mask (which CPUs the process can use).
    pub process_mask: u64,
    /// System affinity mask (which CPUs exist on the system).
    pub system_mask: u64,
    /// Number of logical processors addressable by this mask.
    pub cpu_count: u32,
}

impl AffinityInfo {
    pub fn is_cpu_enabled(&self, cpu: u32) -> bool {
        if cpu >= 64 {
            return false;
        }
        (self.process_mask & (1u64 << cpu)) != 0
    }

    pub fn cpu_exists(&self, cpu: u32) -> bool {
        if cpu >= 64 {
            return false;
        }
        (self.system_mask & (1u64 << cpu)) != 0
    }

    pub fn enabled_cpus(&self) -> Vec<u32> {
        (0..64).filter(|&cpu| self.is_cpu_enabled(cpu)).collect()
    }

    pub fn available_cpus(&self) -> Vec<u32> {
        (0..64).filter(|&cpu| self.cpu_exists(cpu)).collect()
    }
}

// ============================================================================
// Query
// ============================================================================

pub fn get_priority_class(pid: u32) -> Result<PriorityClass, PriorityError> {
    let handle = open_process_query(pid)?;
    let _guard = HandleGuard::new(handle);

    // SAFETY: GetPriorityClass is called with valid process handle
    let value = unsafe { GetPriorityClass(handle) };
    if value == 0 {
        return Err(map_last_error(pid));
    }

    PriorityClass::from_win32(value).ok_or(PriorityError::Win32(value))
}

pub fn get_affinity(pid: u32) -> Result<AffinityInfo, PriorityError> {
    let handle = open_process_query(pid)?;
    let _guard = HandleGuard::new(handle);

    let mut process_mask: usize = 0;
    let mut system_mask: usize = 0;

    // SAFETY: GetProcessAffinityMask is called with valid process handle and properly initialized output pointers
    if unsafe { GetProcessAffinityMask(handle, &mut process_mask, &mut system_mask) }.is_err() {
        return Err(map_last_error(pid));
    }

    let system_mask_u64 = system_mask as u64;

    Ok(AffinityInfo {
        process_mask: process_mask as u64,
        system_mask: system_mask_u64,
        cpu_count: system_mask_u64.count_ones(),
    })
}

// ============================================================================
// Set
// ============================================================================

/// Set the priority class of a process.
///
/// Warning: `Realtime` priority is risky and often requires elevation.
pub fn set_priority_class(pid: u32, priority: PriorityClass) -> Result<(), PriorityError> {
    let handle = open_process_set(pid)?;
    let _guard = HandleGuard::new(handle);

    // SAFETY: SetPriorityClass is called with valid process handle and priority value
    if unsafe { SetPriorityClass(handle, priority.to_win32()) }.is_err() {
        let err = map_last_error(pid);
        if priority == PriorityClass::Realtime && matches!(err, PriorityError::AccessDenied) {
            return Err(PriorityError::RealtimeRequiresElevation);
        }
        return Err(err);
    }

    Ok(())
}

/// Set the CPU affinity mask of a process.
///
/// `mask` is a bitmask of CPUs (bit 0 = CPU 0, bit 1 = CPU 1, etc).
pub fn set_affinity(pid: u32, mask: u64) -> Result<(), PriorityError> {
    if mask == 0 {
        return Err(PriorityError::InvalidAffinityMask);
    }

    // Validate against system mask.
    let info = get_affinity(pid)?;
    if (mask & !info.system_mask) != 0 {
        return Err(PriorityError::InvalidAffinityMask);
    }

    let handle = open_process_set(pid)?;
    let _guard = HandleGuard::new(handle);

    // SAFETY: SetProcessAffinityMask is called with valid process handle and validated affinity mask
    if unsafe { SetProcessAffinityMask(handle, mask as usize) }.is_err() {
        return Err(map_last_error(pid));
    }

    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

fn open_process_query(pid: u32) -> Result<HANDLE, PriorityError> {
    // SAFETY: OpenProcess is called with valid PID and appropriate access rights
    match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => Ok(h),
        Err(_) => Err(map_last_error(pid)),
    }
}

fn open_process_set(pid: u32) -> Result<HANDLE, PriorityError> {
    // SAFETY: OpenProcess is called with valid PID and appropriate access rights
    match unsafe {
        OpenProcess(
            PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        )
    } {
        Ok(h) => Ok(h),
        Err(_) => Err(map_last_error(pid)),
    }
}

fn map_last_error(pid: u32) -> PriorityError {
    // SAFETY: GetLastError retrieves thread-local error code set by previous Windows API call
    let code = unsafe { GetLastError() }.0;
    match WIN32_ERROR(code) {
        ERROR_ACCESS_DENIED => PriorityError::AccessDenied,
        ERROR_INVALID_PARAMETER => PriorityError::ProcessNotFound(pid),
        _ => PriorityError::Win32(code),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_class_ordering() {
        assert!(PriorityClass::Idle < PriorityClass::Normal);
        assert!(PriorityClass::Normal < PriorityClass::High);
        assert!(PriorityClass::High < PriorityClass::Realtime);
    }

    #[test]
    fn test_get_own_priority() {
        let pid = std::process::id();
        let priority = get_priority_class(pid).unwrap();
        assert_eq!(priority, PriorityClass::Normal);
    }

    #[test]
    fn test_get_own_affinity() {
        let pid = std::process::id();
        let info = get_affinity(pid).unwrap();

        assert!(info.cpu_count >= 1);
        assert!(info.process_mask != 0);
        assert!(info.system_mask != 0);
        assert_eq!(info.process_mask & info.system_mask, info.process_mask);
    }

    #[test]
    fn test_set_own_priority_round_trip() {
        let pid = std::process::id();
        let original = get_priority_class(pid).unwrap();

        set_priority_class(pid, PriorityClass::BelowNormal).unwrap();
        assert_eq!(get_priority_class(pid).unwrap(), PriorityClass::BelowNormal);

        set_priority_class(pid, original).unwrap();
        assert_eq!(get_priority_class(pid).unwrap(), original);
    }

    #[test]
    fn test_invalid_affinity_mask() {
        let pid = std::process::id();
        let result = set_affinity(pid, 0);
        assert!(matches!(result, Err(PriorityError::InvalidAffinityMask)));
    }

    #[test]
    fn test_process_not_found() {
        let result = get_priority_class(999_999_999);
        assert!(matches!(
            result,
            Err(PriorityError::ProcessNotFound(_)) | Err(PriorityError::AccessDenied)
        ));
    }
}
