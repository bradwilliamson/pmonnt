//! Tests for Windows service state mapping functions

use pmonnt_core::services::{
    start_type_from_values, status_from_state, ServiceStartType, ServiceStatus,
};
use windows::Win32::System::Services::{SERVICE_START_TYPE, SERVICE_STATUS_CURRENT_STATE};

#[test]
fn test_status_from_state_running() {
    let state = SERVICE_STATUS_CURRENT_STATE(4); // SERVICE_RUNNING
    assert_eq!(status_from_state(state), ServiceStatus::Running);
}

#[test]
fn test_status_from_state_stopped() {
    let state = SERVICE_STATUS_CURRENT_STATE(1); // SERVICE_STOPPED
    assert_eq!(status_from_state(state), ServiceStatus::Stopped);
}

#[test]
fn test_status_from_state_paused() {
    let state = SERVICE_STATUS_CURRENT_STATE(7); // SERVICE_PAUSED
    assert_eq!(status_from_state(state), ServiceStatus::Paused);
}

#[test]
fn test_status_from_state_unknown() {
    let state = SERVICE_STATUS_CURRENT_STATE(99); // Unknown value
    assert_eq!(status_from_state(state), ServiceStatus::Stopped); // Default
}

#[test]
fn test_start_type_from_values_automatic() {
    let start_type = SERVICE_START_TYPE(2); // SERVICE_AUTO_START
    assert_eq!(
        start_type_from_values(start_type, false),
        ServiceStartType::Automatic
    );
}

#[test]
fn test_start_type_from_values_automatic_delayed() {
    let start_type = SERVICE_START_TYPE(2); // SERVICE_AUTO_START
    assert_eq!(
        start_type_from_values(start_type, true),
        ServiceStartType::AutomaticDelayed
    );
}

#[test]
fn test_start_type_from_values_manual() {
    let start_type = SERVICE_START_TYPE(3); // SERVICE_DEMAND_START
    assert_eq!(
        start_type_from_values(start_type, false),
        ServiceStartType::Manual
    );
}

#[test]
fn test_start_type_from_values_disabled() {
    let start_type = SERVICE_START_TYPE(4); // SERVICE_DISABLED
    assert_eq!(
        start_type_from_values(start_type, false),
        ServiceStartType::Disabled
    );
}
