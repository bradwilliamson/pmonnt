use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
    QueryServiceConfig2W, QueryServiceConfigW, QueryServiceStatusEx, StartServiceW,
    ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SC_STATUS_PROCESS_INFO,
    SERVICE_ACCEPT_PAUSE_CONTINUE, SERVICE_AUTO_START, SERVICE_BOOT_START,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_CONTINUE,
    SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_STOP, SERVICE_DELAYED_AUTO_START_INFO,
    SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW, SERVICE_DISABLED, SERVICE_PAUSE_CONTINUE,
    SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_TYPE,
    SERVICE_STATE_ALL, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_PROCESS,
    SERVICE_STOP, SERVICE_SYSTEM_START, SERVICE_WIN32,
};

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub status: ServiceStatus,
    pub start_type: ServiceStartType,
    pub pid: Option<u32>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStartType {
    Automatic,
    AutomaticDelayed,
    Manual,
    Disabled,
    Boot,
    System,
}

struct ScmHandleGuard(SC_HANDLE);

impl ScmHandleGuard {
    fn new(h: SC_HANDLE) -> Self {
        Self(h)
    }
}

impl Drop for ScmHandleGuard {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid SC_HANDLE owned by this guard
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

struct ServiceHandleGuard(SC_HANDLE);

impl ServiceHandleGuard {
    fn new(h: SC_HANDLE) -> Self {
        Self(h)
    }
}

impl Drop for ServiceHandleGuard {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid SC_HANDLE owned by this guard
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }

    // SAFETY: ptr is non-null and points to a null-terminated wide string from Windows API
    // - Caller guarantees ptr is valid for reads
    // - Loop finds null terminator to determine valid length
    // - from_raw_parts creates slice from valid pointer and computed length
    unsafe {
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}

pub fn status_from_state(state: SERVICE_STATUS_CURRENT_STATE) -> ServiceStatus {
    // SERVICE_STATUS_CURRENT_STATE is a newtype around u32
    // We need to compare the inner values
    const STOPPED: u32 = 1;
    const START_PENDING: u32 = 2;
    const STOP_PENDING: u32 = 3;
    const RUNNING: u32 = 4;
    const CONTINUE_PENDING: u32 = 5;
    const PAUSE_PENDING: u32 = 6;
    const PAUSED: u32 = 7;

    match state.0 {
        STOPPED => ServiceStatus::Stopped,
        START_PENDING => ServiceStatus::StartPending,
        STOP_PENDING => ServiceStatus::StopPending,
        RUNNING => ServiceStatus::Running,
        CONTINUE_PENDING => ServiceStatus::ContinuePending,
        PAUSE_PENDING => ServiceStatus::PausePending,
        PAUSED => ServiceStatus::Paused,
        _ => ServiceStatus::Stopped,
    }
}

pub fn start_type_from_values(start_type: SERVICE_START_TYPE, delayed: bool) -> ServiceStartType {
    match start_type {
        s if s == SERVICE_AUTO_START => {
            if delayed {
                ServiceStartType::AutomaticDelayed
            } else {
                ServiceStartType::Automatic
            }
        }
        s if s == SERVICE_DEMAND_START => ServiceStartType::Manual,
        s if s == SERVICE_DISABLED => ServiceStartType::Disabled,
        s if s == SERVICE_BOOT_START => ServiceStartType::Boot,
        s if s == SERVICE_SYSTEM_START => ServiceStartType::System,
        _ => ServiceStartType::Manual,
    }
}

#[derive(Clone)]
struct BasicService {
    name: String,
    display_name: String,
    status: ServiceStatus,
    pid: Option<u32>,
}

struct BasicCache {
    last_refresh: Instant,
    services: Vec<BasicService>,
}

struct DetailsCacheEntry {
    last_refresh: Instant,
    start_type: ServiceStartType,
    description: Option<String>,
}

static BASIC_CACHE: OnceLock<Mutex<Option<BasicCache>>> = OnceLock::new();
static DETAILS_CACHE: OnceLock<Mutex<HashMap<String, DetailsCacheEntry>>> = OnceLock::new();

fn basic_cache() -> &'static Mutex<Option<BasicCache>> {
    BASIC_CACHE.get_or_init(|| Mutex::new(None))
}

fn details_cache() -> &'static Mutex<HashMap<String, DetailsCacheEntry>> {
    DETAILS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Enumerate all services (status + hosting PID) with a short TTL cache.
fn enumerate_all_services_basic() -> Result<Vec<BasicService>> {
    const TTL: Duration = Duration::from_secs(3);

    {
        let guard = basic_cache().lock().expect("basic service cache lock");
        if let Some(cache) = guard.as_ref() {
            if cache.last_refresh.elapsed() < TTL {
                return Ok(cache.services.clone());
            }
        }
        // drop lock before expensive work
        drop(guard);
    }

    // SAFETY: OpenSCManagerW with valid parameters (None uses defaults)
    let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)? };
    let _scm_guard = ScmHandleGuard::new(scm);

    let mut bytes_needed = 0u32;
    let mut services_returned = 0u32;
    let mut resume_handle = 0u32;

    // First call to get required buffer size.
    // SAFETY: EnumServicesStatusExW size query with None buffer
    // - scm is a valid SC_HANDLE from OpenSCManagerW
    // - None buffer is standard pattern for querying required size
    // - bytes_needed will be populated with required size
    let _ = unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            None,
        )
    };

    if bytes_needed == 0 {
        let err = windows::core::Error::from_win32();
        return Err(anyhow!("EnumServicesStatusExW failed: {err}"));
    }

    let mut buffer = vec![0u8; bytes_needed as usize];
    // SAFETY: EnumServicesStatusExW writes structured service data into the buffer
    // - Buffer size matches bytes_needed determined by first API call
    // - API populates the buffer with services_returned valid entries
    // - Each entry is an ENUM_SERVICE_STATUS_PROCESSW struct
    unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buffer),
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            None,
        )?;
    }

    let mut services = Vec::with_capacity(services_returned as usize);
    // SAFETY: Buffer populated by EnumServicesStatusExW with proper alignment
    // - Windows guarantees ENUM_SERVICE_STATUS_PROCESSW array alignment
    // - services_returned indicates the actual entry count written by OS
    // - Buffer sized to accommodate all entries
    let ptr = buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;

    for i in 0..(services_returned as usize) {
        // SAFETY: Pointer arithmetic within validated bounds (i < services_returned)
        let item = unsafe { &*ptr.add(i) };
        let name = wide_ptr_to_string(PCWSTR(item.lpServiceName.0).0);
        let display_name = wide_ptr_to_string(PCWSTR(item.lpDisplayName.0).0);
        let status = status_from_state(item.ServiceStatusProcess.dwCurrentState);
        let pid = match item.ServiceStatusProcess.dwProcessId {
            0 => None,
            v => Some(v),
        };

        services.push(BasicService {
            name,
            display_name,
            status,
            pid,
        });
    }

    let mut guard = basic_cache().lock().expect("basic service cache lock");
    *guard = Some(BasicCache {
        last_refresh: Instant::now(),
        services: services.clone(),
    });

    Ok(services)
}

fn get_service_details(scm: SC_HANDLE, name: &str) -> Result<(ServiceStartType, Option<String>)> {
    const TTL: Duration = Duration::from_secs(60);

    {
        let guard = details_cache().lock().expect("service details cache lock");
        if let Some(e) = guard.get(name) {
            if e.last_refresh.elapsed() < TTL {
                return Ok((e.start_type, e.description.clone()));
            }
        }
        drop(guard);
    }

    let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: OpenServiceW with valid parameters
    // - scm is a valid SC_HANDLE
    // - wname is a null-terminated UTF-16 string valid for the call
    // - wname.as_ptr() remains valid as wname is in scope
    let service = unsafe {
        OpenServiceW(
            scm,
            PCWSTR(wname.as_ptr()),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )?
    };
    let _svc_guard = ServiceHandleGuard::new(service);

    // QueryServiceConfigW
    let mut bytes_needed = 0u32;
    // SAFETY: QueryServiceConfigW size query
    // - service is a valid SC_HANDLE from OpenServiceW
    // - None buffer is standard pattern for size query
    let _ = unsafe { QueryServiceConfigW(service, None, 0, &mut bytes_needed) };
    if bytes_needed == 0 {
        // Fall back to defaults if we can't query.
        return Ok((ServiceStartType::Manual, None));
    }

    let mut cfg_buf = vec![0u8; bytes_needed as usize];
    // SAFETY: QueryServiceConfigW populates the buffer with QUERY_SERVICE_CONFIGW data
    // - Buffer size matches bytes_needed from the API
    // - Windows guarantees proper alignment for service config structures
    unsafe {
        QueryServiceConfigW(
            service,
            Some(cfg_buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
            cfg_buf.len() as u32,
            &mut bytes_needed,
        )?;
    }
    // SAFETY: Buffer was populated by QueryServiceConfigW with valid QUERY_SERVICE_CONFIGW
    // - API guarantees proper structure layout and alignment
    // - Buffer size verified to accommodate the structure
    let cfg = unsafe { &*(cfg_buf.as_ptr() as *const QUERY_SERVICE_CONFIGW) };

    // Delayed auto-start info (only meaningful for auto-start).
    let mut delayed = false;
    let mut bytes_needed2 = 0u32;
    // SAFETY: QueryServiceConfig2W size query for delayed auto-start info
    // - service is a valid SC_HANDLE
    // - None buffer for size query is standard Windows API pattern
    let _ = unsafe {
        QueryServiceConfig2W(
            service,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            None,
            &mut bytes_needed2,
        )
    };
    if bytes_needed2 > 0 {
        let mut buf2 = vec![0u8; bytes_needed2 as usize];
        // SAFETY: QueryServiceConfig2W data retrieval with properly sized buffer
        // - Buffer allocated with exact size from previous query
        // - service handle remains valid
        if unsafe {
            QueryServiceConfig2W(
                service,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                Some(&mut buf2),
                &mut bytes_needed2,
            )
        }
        .is_ok()
        {
            // SAFETY: QueryServiceConfig2W populated buf2 with SERVICE_DELAYED_AUTO_START_INFO
            // - Buffer size matches bytes_needed2 determined by the API
            // - Windows guarantees proper alignment for this structure
            let info = unsafe { &*(buf2.as_ptr() as *const SERVICE_DELAYED_AUTO_START_INFO) };
            delayed = info.fDelayedAutostart.as_bool();
        }
    }

    // Description
    let mut description: Option<String> = None;
    let mut bytes_needed3 = 0u32;
    // SAFETY: QueryServiceConfig2W size query for description
    // - service is a valid SC_HANDLE
    // - None buffer for size query
    let _ = unsafe {
        QueryServiceConfig2W(
            service,
            SERVICE_CONFIG_DESCRIPTION,
            None,
            &mut bytes_needed3,
        )
    };
    if bytes_needed3 > 0 {
        let mut buf3 = vec![0u8; bytes_needed3 as usize];
        // SAFETY: QueryServiceConfig2W data retrieval with properly sized buffer
        // - Buffer allocated with exact size from previous query
        // - service handle remains valid
        if unsafe {
            QueryServiceConfig2W(
                service,
                SERVICE_CONFIG_DESCRIPTION,
                Some(&mut buf3),
                &mut bytes_needed3,
            )
        }
        .is_ok()
        {
            // SAFETY: QueryServiceConfig2W populated buf3 with SERVICE_DESCRIPTIONW
            // - Buffer size matches bytes_needed3 from API
            // - Windows guarantees proper alignment and valid lpDescription pointer (or null)
            let info = unsafe { &*(buf3.as_ptr() as *const SERVICE_DESCRIPTIONW) };
            if !info.lpDescription.is_null() {
                description = Some(wide_ptr_to_string(PCWSTR(info.lpDescription.0).0));
            }
        }
    }

    let start_type = start_type_from_values(cfg.dwStartType, delayed);

    let mut guard = details_cache().lock().expect("service details cache lock");
    guard.insert(
        name.to_string(),
        DetailsCacheEntry {
            last_refresh: Instant::now(),
            start_type,
            description: description.clone(),
        },
    );

    Ok((start_type, description))
}

pub fn get_services_for_process(pid: u32) -> Result<Vec<ServiceInfo>> {
    let basics = enumerate_all_services_basic()?;
    let hosted: Vec<BasicService> = basics.into_iter().filter(|s| s.pid == Some(pid)).collect();

    if hosted.is_empty() {
        return Ok(Vec::new());
    }

    // SAFETY: OpenSCManagerW with valid parameters
    let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)? };
    let _scm_guard = ScmHandleGuard::new(scm);

    let mut out = Vec::with_capacity(hosted.len());
    for s in hosted {
        // Access denied shouldn’t fail the whole list.
        let (start_type, description) = match get_service_details(scm, &s.name) {
            Ok(v) => v,
            Err(_) => (ServiceStartType::Manual, None),
        };

        out.push(ServiceInfo {
            name: s.name,
            display_name: s.display_name,
            status: s.status,
            start_type,
            pid: s.pid,
            description,
        });
    }

    Ok(out)
}

/// Get services hosted by a specific process.
///
/// Alias for `get_services_for_process`.
pub fn get_services_for_pid(pid: u32) -> Result<Vec<ServiceInfo>> {
    get_services_for_process(pid)
}

pub fn enumerate_all_services() -> Result<Vec<ServiceInfo>> {
    let basics = enumerate_all_services_basic()?;

    // SAFETY: OpenSCManagerW with valid parameters (None uses defaults, SC_MANAGER_ENUMERATE_SERVICE is valid)
    let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)? };
    let _scm_guard = ScmHandleGuard::new(scm);

    let mut out = Vec::with_capacity(basics.len());
    for s in basics {
        let (start_type, description) = match get_service_details(scm, &s.name) {
            Ok(v) => v,
            Err(_) => (ServiceStartType::Manual, None),
        };

        out.push(ServiceInfo {
            name: s.name,
            display_name: s.display_name,
            status: s.status,
            start_type,
            pid: s.pid,
            description,
        });
    }

    Ok(out)
}

pub fn stop_service(service_name: &str, timeout: Duration) -> Result<()> {
    // SAFETY: OpenSCManagerW with valid parameters
    let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT)? };
    let _scm_guard = ScmHandleGuard::new(scm);

    let wname: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: OpenServiceW with valid null-terminated UTF-16 string and valid scm handle
    let service = unsafe {
        OpenServiceW(
            scm,
            PCWSTR(wname.as_ptr()),
            SERVICE_STOP | SERVICE_QUERY_STATUS,
        )?
    };
    let _svc_guard = ServiceHandleGuard::new(service);

    let mut status = SERVICE_STATUS::default();
    // SAFETY: ControlService with valid service handle and mutable status reference
    unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut status)? };

    wait_for_service_state(
        service,
        windows::Win32::System::Services::SERVICE_STOPPED,
        timeout,
    )
}

pub fn restart_service(service_name: &str, timeout: Duration) -> Result<()> {
    // Stop
    let _ = stop_service(service_name, timeout);

    // Start
    // SAFETY: OpenSCManagerW with valid parameters
    let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT)? };
    let _scm_guard = ScmHandleGuard::new(scm);

    let wname: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: OpenServiceW with valid null-terminated UTF-16 string and valid scm handle
    let service = unsafe {
        OpenServiceW(
            scm,
            PCWSTR(wname.as_ptr()),
            SERVICE_START | SERVICE_QUERY_STATUS,
        )?
    };
    let _svc_guard = ServiceHandleGuard::new(service);

    // SAFETY: StartServiceW with valid service handle, no arguments
    unsafe {
        // No args.
        StartServiceW(service, None)?;
    }

    wait_for_service_state(service, SERVICE_RUNNING, timeout)
}

pub fn start_service(service_name: &str, timeout: Duration) -> Result<()> {
    // SAFETY: OpenSCManagerW with valid parameters
    let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT)? };
    let _scm_guard = ScmHandleGuard::new(scm);

    let wname: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: OpenServiceW with valid null-terminated UTF-16 string and valid scm handle
    let service = unsafe {
        OpenServiceW(
            scm,
            PCWSTR(wname.as_ptr()),
            SERVICE_START | SERVICE_QUERY_STATUS,
        )?
    };
    let _svc_guard = ServiceHandleGuard::new(service);

    // SAFETY: StartServiceW with valid service handle
    unsafe {
        StartServiceW(service, None)?;
    }

    wait_for_service_state(service, SERVICE_RUNNING, timeout)
}

pub fn pause_service(service_name: &str, timeout: Duration) -> Result<()> {
    // SAFETY: OpenSCManagerW with valid parameters
    let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT)? };
    let _scm_guard = ScmHandleGuard::new(scm);

    let wname: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: OpenServiceW with valid null-terminated UTF-16 string and valid scm handle
    let service = unsafe {
        OpenServiceW(
            scm,
            PCWSTR(wname.as_ptr()),
            SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS,
        )?
    };
    let _svc_guard = ServiceHandleGuard::new(service);

    // Best-effort check for pause accept.
    let mut bytes_needed = 0u32;
    let mut buf = vec![0u8; std::mem::size_of::<SERVICE_STATUS_PROCESS>()];
    // SAFETY: QueryServiceStatusEx with valid service handle and properly sized buffer
    unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            Some(&mut buf),
            &mut bytes_needed,
        )?;
    }
    // SAFETY: Buffer properly sized and filled by QueryServiceStatusEx, valid for SERVICE_STATUS_PROCESS cast
    let ssp = unsafe { &*(buf.as_ptr() as *const SERVICE_STATUS_PROCESS) };
    if (ssp.dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) == 0 {
        return Err(anyhow!("Service does not accept pause"));
    }

    let mut status = SERVICE_STATUS::default();
    // SAFETY: ControlService with valid service handle and mutable status reference
    unsafe { ControlService(service, SERVICE_CONTROL_PAUSE, &mut status)? };

    wait_for_service_state(
        service,
        windows::Win32::System::Services::SERVICE_PAUSED,
        timeout,
    )
}

pub fn resume_service(service_name: &str, timeout: Duration) -> Result<()> {
    // SAFETY: OpenSCManagerW with valid parameters
    let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT)? };
    let _scm_guard = ScmHandleGuard::new(scm);

    let wname: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: OpenServiceW with valid null-terminated UTF-16 string and valid scm handle
    let service = unsafe {
        OpenServiceW(
            scm,
            PCWSTR(wname.as_ptr()),
            SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS,
        )?
    };
    let _svc_guard = ServiceHandleGuard::new(service);

    let mut status = SERVICE_STATUS::default();
    // SAFETY: ControlService with valid service handle and mutable status reference
    unsafe { ControlService(service, SERVICE_CONTROL_CONTINUE, &mut status)? };

    wait_for_service_state(service, SERVICE_RUNNING, timeout)
}

fn wait_for_service_state(
    service: SC_HANDLE,
    desired: SERVICE_STATUS_CURRENT_STATE,
    timeout: Duration,
) -> Result<()> {
    let start = Instant::now();

    loop {
        let mut bytes_needed = 0u32;
        let mut buf = vec![0u8; std::mem::size_of::<SERVICE_STATUS_PROCESS>()];
        // SAFETY: QueryServiceStatusEx with valid service handle and properly sized buffer
        unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                Some(&mut buf),
                &mut bytes_needed,
            )?;
        }
        // SAFETY: Buffer properly sized and filled by QueryServiceStatusEx, valid for SERVICE_STATUS_PROCESS cast
        let ssp = unsafe { &*(buf.as_ptr() as *const SERVICE_STATUS_PROCESS) };

        if ssp.dwCurrentState == desired {
            return Ok(());
        }

        if start.elapsed() > timeout {
            return Err(anyhow!("Timed out waiting for service state {}", desired.0));
        }

        std::thread::sleep(Duration::from_millis(200));
    }
}
