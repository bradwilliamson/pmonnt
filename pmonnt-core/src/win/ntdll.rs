use std::ffi::c_void;
use windows::Win32::Foundation::{HANDLE, NTSTATUS};

#[link(name = "ntdll")]
extern "system" {
    pub fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;
}
