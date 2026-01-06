//! Service control operations (start, stop, restart, pause, resume).
//!
//! Provides safe wrappers around Windows Service Control Manager (SCM) APIs.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, ERROR_ACCESS_DENIED, ERROR_SERVICE_DOES_NOT_EXIST};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
    StartServiceW, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_ACCEPT_PAUSE_CONTINUE, SERVICE_CONTINUE_PENDING, SERVICE_CONTROL_CONTINUE,
    SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_STOP, SERVICE_PAUSED, SERVICE_PAUSE_CONTINUE,
    SERVICE_PAUSE_PENDING, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
    SERVICE_START_PENDING, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_PROCESS, SERVICE_STOP,
    SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

use crate::services::ServiceStatus;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ServiceControlError {
    #[error("Access denied - may require elevation")]
    AccessDenied,

    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    #[error("Service is already {0}")]
    AlreadyInState(String),

    #[error("Cannot {action} service: current state is {current_state}")]
    InvalidStateTransition {
        action: &'static str,
        current_state: String,
    },

    #[error("Timeout waiting for service to {0}")]
    Timeout(String),

    #[error("Service control manager unavailable")]
    ScmUnavailable,

    #[error("Windows error: {0}")]
    Win32(u32),
}

/// Result of a service control operation.
#[derive(Debug, Clone)]
pub struct ServiceControlResult {
    pub service_name: String,
    pub previous_state: ServiceStatus,
    pub new_state: ServiceStatus,
}

struct ScHandleGuard(SC_HANDLE);

impl ScHandleGuard {
    fn new(h: SC_HANDLE) -> Self {
        Self(h)
    }
}

impl Drop for ScHandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                // SAFETY: `self.0` is a live `SC_HANDLE` owned by this guard.
                CloseServiceHandle(self.0).ok();
            }
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

pub fn start_service(service_name: &str) -> Result<ServiceControlResult, ServiceControlError> {
    let (scm, service) =
        open_service_for_control(service_name, SERVICE_START | SERVICE_QUERY_STATUS)?;
    let _scm_guard = ScHandleGuard::new(scm);
    let _svc_guard = ScHandleGuard::new(service);

    let status = query_service_status(service)?;
    let previous_state = win32_state_to_status(status.dwCurrentState);

    if status.dwCurrentState == SERVICE_RUNNING {
        return Err(ServiceControlError::AlreadyInState("running".to_string()));
    }

    if status.dwCurrentState != SERVICE_STOPPED {
        return Err(ServiceControlError::InvalidStateTransition {
            action: "start",
            current_state: format!("{:?}", previous_state),
        });
    }

    // SAFETY: `service` is a valid service handle opened with `SERVICE_START` access.
    if unsafe { StartServiceW(service, None) }.is_err() {
        return Err(map_last_error(service_name));
    }

    let new_state = wait_for_state(service, SERVICE_RUNNING, Duration::from_secs(30))?;

    Ok(ServiceControlResult {
        service_name: service_name.to_string(),
        previous_state,
        new_state,
    })
}

pub fn stop_service(service_name: &str) -> Result<ServiceControlResult, ServiceControlError> {
    let (scm, service) =
        open_service_for_control(service_name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
    let _scm_guard = ScHandleGuard::new(scm);
    let _svc_guard = ScHandleGuard::new(service);

    let status = query_service_status(service)?;
    let previous_state = win32_state_to_status(status.dwCurrentState);

    if status.dwCurrentState == SERVICE_STOPPED {
        return Err(ServiceControlError::AlreadyInState("stopped".to_string()));
    }

    let mut new_status = SERVICE_STATUS_PROCESS::default();
    // SAFETY: `service` is a valid service handle opened with `SERVICE_STOP` access.
    // `new_status` is a valid writable out-parameter for the duration of the call.
    if unsafe {
        ControlService(
            service,
            SERVICE_CONTROL_STOP,
            &mut new_status as *mut _ as *mut _,
        )
    }
    .is_err()
    {
        return Err(map_last_error(service_name));
    }

    let new_state = wait_for_state(service, SERVICE_STOPPED, Duration::from_secs(30))?;

    Ok(ServiceControlResult {
        service_name: service_name.to_string(),
        previous_state,
        new_state,
    })
}

pub fn restart_service(service_name: &str) -> Result<ServiceControlResult, ServiceControlError> {
    let (scm, service) = open_service_for_control(
        service_name,
        SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS,
    )?;
    let _scm_guard = ScHandleGuard::new(scm);
    let _svc_guard = ScHandleGuard::new(service);

    let status = query_service_status(service)?;
    let previous_state = win32_state_to_status(status.dwCurrentState);

    if status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_PAUSED {
        let mut new_status = SERVICE_STATUS_PROCESS::default();
        // SAFETY: `service` is a valid service handle opened with `SERVICE_STOP` access.
        // `new_status` is a valid writable out-parameter for the duration of the call.
        if unsafe {
            ControlService(
                service,
                SERVICE_CONTROL_STOP,
                &mut new_status as *mut _ as *mut _,
            )
        }
        .is_err()
        {
            return Err(map_last_error(service_name));
        }
        let _ = wait_for_state(service, SERVICE_STOPPED, Duration::from_secs(30))?;
    }

    // SAFETY: `service` is a valid service handle opened with `SERVICE_START` access.
    if unsafe { StartServiceW(service, None) }.is_err() {
        return Err(map_last_error(service_name));
    }

    let new_state = wait_for_state(service, SERVICE_RUNNING, Duration::from_secs(30))?;

    Ok(ServiceControlResult {
        service_name: service_name.to_string(),
        previous_state,
        new_state,
    })
}

pub fn pause_service(service_name: &str) -> Result<ServiceControlResult, ServiceControlError> {
    let (scm, service) =
        open_service_for_control(service_name, SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS)?;
    let _scm_guard = ScHandleGuard::new(scm);
    let _svc_guard = ScHandleGuard::new(service);

    let status = query_service_status(service)?;
    let previous_state = win32_state_to_status(status.dwCurrentState);

    if status.dwCurrentState == SERVICE_PAUSED {
        return Err(ServiceControlError::AlreadyInState("paused".to_string()));
    }

    if status.dwCurrentState != SERVICE_RUNNING {
        return Err(ServiceControlError::InvalidStateTransition {
            action: "pause",
            current_state: format!("{:?}", previous_state),
        });
    }

    if (status.dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) == 0 {
        return Err(ServiceControlError::InvalidStateTransition {
            action: "pause",
            current_state: "service does not accept pause".to_string(),
        });
    }

    let mut new_status = SERVICE_STATUS_PROCESS::default();
    // SAFETY: `service` is a valid service handle opened with `SERVICE_PAUSE_CONTINUE` access.
    // `new_status` is a valid writable out-parameter for the duration of the call.
    if unsafe {
        ControlService(
            service,
            SERVICE_CONTROL_PAUSE,
            &mut new_status as *mut _ as *mut _,
        )
    }
    .is_err()
    {
        return Err(map_last_error(service_name));
    }

    let new_state = wait_for_state(service, SERVICE_PAUSED, Duration::from_secs(30))?;

    Ok(ServiceControlResult {
        service_name: service_name.to_string(),
        previous_state,
        new_state,
    })
}

pub fn resume_service(service_name: &str) -> Result<ServiceControlResult, ServiceControlError> {
    let (scm, service) =
        open_service_for_control(service_name, SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS)?;
    let _scm_guard = ScHandleGuard::new(scm);
    let _svc_guard = ScHandleGuard::new(service);

    let status = query_service_status(service)?;
    let previous_state = win32_state_to_status(status.dwCurrentState);

    if status.dwCurrentState != SERVICE_PAUSED {
        return Err(ServiceControlError::InvalidStateTransition {
            action: "resume",
            current_state: format!("{:?}", previous_state),
        });
    }

    let mut new_status = SERVICE_STATUS_PROCESS::default();
    // SAFETY: `service` is a valid service handle opened with `SERVICE_PAUSE_CONTINUE` access.
    // `new_status` is a valid writable out-parameter for the duration of the call.
    if unsafe {
        ControlService(
            service,
            SERVICE_CONTROL_CONTINUE,
            &mut new_status as *mut _ as *mut _,
        )
    }
    .is_err()
    {
        return Err(map_last_error(service_name));
    }

    let new_state = wait_for_state(service, SERVICE_RUNNING, Duration::from_secs(30))?;

    Ok(ServiceControlResult {
        service_name: service_name.to_string(),
        previous_state,
        new_state,
    })
}

pub fn get_service_status(service_name: &str) -> Result<ServiceStatus, ServiceControlError> {
    let (scm, service) = open_service_for_control(service_name, SERVICE_QUERY_STATUS)?;
    let _scm_guard = ScHandleGuard::new(scm);
    let _svc_guard = ScHandleGuard::new(service);

    let status = query_service_status(service)?;
    Ok(win32_state_to_status(status.dwCurrentState))
}

// ============================================================================
// Helpers
// ============================================================================

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn open_service_for_control(
    service_name: &str,
    access: u32,
) -> Result<(SC_HANDLE, SC_HANDLE), ServiceControlError> {
    // SAFETY: `OpenSCManagerW` has no pointer parameters in this usage (null machine/db names).
    let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
        .map_err(|_| ServiceControlError::ScmUnavailable)?;

    if scm.is_invalid() {
        return Err(ServiceControlError::ScmUnavailable);
    }

    let name_wide = to_wide_null(service_name);
    // SAFETY: `name_wide` is NUL-terminated UTF-16 for the duration of the call.
    // `scm` is a valid SCM handle.
    let service = unsafe { OpenServiceW(scm, PCWSTR::from_raw(name_wide.as_ptr()), access) };

    match service {
        Ok(svc) if !svc.is_invalid() => Ok((scm, svc)),
        _ => {
            // SAFETY: `scm` is a live SCM handle owned by this function on this path.
            unsafe { CloseServiceHandle(scm).ok() };
            Err(map_last_error(service_name))
        }
    }
}

fn query_service_status(service: SC_HANDLE) -> Result<SERVICE_STATUS_PROCESS, ServiceControlError> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut bytes_needed = 0u32;

    // SAFETY: `service` is a valid service handle opened with `SERVICE_QUERY_STATUS` access.
    // We provide a writable byte slice that points to `status` and is exactly the size of
    // `SERVICE_STATUS_PROCESS`.
    let result = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            Some(std::slice::from_raw_parts_mut(
                &mut status as *mut _ as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
            )),
            &mut bytes_needed,
        )
    };

    if result.is_err() {
        // SAFETY: `GetLastError` has no preconditions; it only reads thread-local state.
        return Err(ServiceControlError::Win32(unsafe { GetLastError() }.0));
    }

    Ok(status)
}

fn wait_for_state(
    service: SC_HANDLE,
    target_state: SERVICE_STATUS_CURRENT_STATE,
    timeout: Duration,
) -> Result<ServiceStatus, ServiceControlError> {
    let start = Instant::now();
    let poll_interval = Duration::from_millis(250);

    loop {
        let status = query_service_status(service)?;

        if status.dwCurrentState == target_state {
            return Ok(win32_state_to_status(status.dwCurrentState));
        }

        let is_pending = matches!(
            status.dwCurrentState,
            x if x == SERVICE_START_PENDING
                || x == SERVICE_STOP_PENDING
                || x == SERVICE_PAUSE_PENDING
                || x == SERVICE_CONTINUE_PENDING
        );

        if !is_pending && status.dwCurrentState != target_state {
            return Ok(win32_state_to_status(status.dwCurrentState));
        }

        if start.elapsed() > timeout {
            let action = match target_state {
                x if x == SERVICE_RUNNING => "start",
                x if x == SERVICE_STOPPED => "stop",
                x if x == SERVICE_PAUSED => "pause",
                _ => "complete",
            };
            return Err(ServiceControlError::Timeout(action.to_string()));
        }

        thread::sleep(poll_interval);
    }
}

fn win32_state_to_status(state: SERVICE_STATUS_CURRENT_STATE) -> ServiceStatus {
    match state {
        x if x == SERVICE_STOPPED => ServiceStatus::Stopped,
        x if x == SERVICE_START_PENDING => ServiceStatus::StartPending,
        x if x == SERVICE_STOP_PENDING => ServiceStatus::StopPending,
        x if x == SERVICE_RUNNING => ServiceStatus::Running,
        x if x == SERVICE_CONTINUE_PENDING => ServiceStatus::ContinuePending,
        x if x == SERVICE_PAUSE_PENDING => ServiceStatus::PausePending,
        x if x == SERVICE_PAUSED => ServiceStatus::Paused,
        _ => ServiceStatus::Stopped,
    }
}

fn map_last_error(service_name: &str) -> ServiceControlError {
    // SAFETY: `GetLastError` has no preconditions; it only reads thread-local state.
    let code = unsafe { GetLastError() }.0;
    match code {
        c if c == ERROR_ACCESS_DENIED.0 => ServiceControlError::AccessDenied,
        c if c == ERROR_SERVICE_DOES_NOT_EXIST.0 => {
            ServiceControlError::ServiceNotFound(service_name.to_string())
        }
        _ => ServiceControlError::Win32(code),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_conversion() {
        assert_eq!(
            win32_state_to_status(SERVICE_RUNNING),
            ServiceStatus::Running
        );
        assert_eq!(
            win32_state_to_status(SERVICE_STOPPED),
            ServiceStatus::Stopped
        );
        assert_eq!(win32_state_to_status(SERVICE_PAUSED), ServiceStatus::Paused);
    }

    #[test]
    fn test_nonexistent_service() {
        let result = get_service_status("ThisServiceDoesNotExist12345");
        assert!(matches!(
            result,
            Err(ServiceControlError::ServiceNotFound(_))
        ));
    }
}
