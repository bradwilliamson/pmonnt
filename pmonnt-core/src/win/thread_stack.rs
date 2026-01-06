use std::ffi::c_void;
use std::mem;
use std::sync::{Mutex, OnceLock};

use thiserror::Error;
use windows::core::PCSTR;
use windows::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, HANDLE, WIN32_ERROR,
};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, StackWalk64, SymCleanup, SymFromAddr, SymFunctionTableAccess64,
    SymGetModuleBase64, SymInitialize, SymSetOptions, ADDRESS64, CONTEXT_FLAGS, STACKFRAME64,
    SYMBOL_INFO, SYMOPT_DEFERRED_LOADS, SYMOPT_UNDNAME,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ, THREAD_ACCESS_RIGHTS, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    THREAD_SUSPEND_RESUME,
};

use crate::win::ntdll::NtQueryInformationProcess;
use crate::win::HandleGuard;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ThreadStackError {
    #[error("Access denied")]
    AccessDenied,

    #[error("Thread not found (TID {tid})")]
    ThreadNotFound { tid: u32 },

    #[error("Process not found (PID {pid})")]
    ProcessNotFound { pid: u32 },

    #[error("Unsupported: {reason}")]
    Unsupported { reason: String },

    #[error("{context} failed (Win32={code}){hint}")]
    Win32 {
        context: &'static str,
        code: u32,
        hint: String,
    },
}

fn hint_for_win32(code: u32) -> String {
    let is_elevated = crate::win::is_app_elevated();
    match code {
        5 => " (Access denied: try running elevated and enable SeDebugPrivilege)".to_string(),
        87 => " (Invalid parameter: thread/process may have exited)".to_string(),
        998 => {
            if is_elevated {
                " (No access: target is protected or you lack SeDebugPrivilege)".to_string()
            } else {
                " (No access: Run PMonNT as Administrator to capture stacks from this target)"
                    .to_string()
            }
        }
        _ => String::new(),
    }
}

fn map_last_error(context: &'static str, pid: u32, tid: u32) -> ThreadStackError {
    let code = unsafe { GetLastError() }.0;
    match WIN32_ERROR(code) {
        ERROR_ACCESS_DENIED => ThreadStackError::AccessDenied,
        ERROR_INVALID_PARAMETER => {
            // Ambiguous: could be PID or TID depending on which call failed.
            if tid != 0 {
                ThreadStackError::ThreadNotFound { tid }
            } else {
                ThreadStackError::ProcessNotFound { pid }
            }
        }
        _ => ThreadStackError::Win32 {
            context,
            code,
            hint: hint_for_win32(code),
        },
    }
}

static DBGHELP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

const PROCESS_WOW64_INFORMATION_CLASS: u32 = 26;

fn is_wow64_process(process: HANDLE) -> Result<bool, ThreadStackError> {
    // Returns the 32-bit PEB address for WoW64 processes. If 0, the process is not WoW64.
    let mut peb32: usize = 0;
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            PROCESS_WOW64_INFORMATION_CLASS,
            &mut peb32 as *mut usize as *mut c_void,
            mem::size_of::<usize>() as u32,
            std::ptr::null_mut(),
        )
    };
    // STATUS_SUCCESS == 0
    if status.0 != 0 {
        return Err(ThreadStackError::Unsupported {
            reason: format!(
                "NtQueryInformationProcess(ProcessWow64Information) failed (NTSTATUS=0x{:08x})",
                status.0
            ),
        });
    }
    Ok(peb32 != 0)
}

struct ResumeOnDrop {
    thread: HANDLE,
    did_suspend: bool,
}

impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        if self.did_suspend {
            unsafe {
                let _ = ResumeThread(self.thread);
            }
        }
    }
}

/// Best-effort stack trace for a remote thread.
///
/// Notes:
/// - Requires `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` on the process.
/// - Requires `THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME` on the thread.
/// - Currently supports native (non-WoW64) threads only.
#[cfg(windows)]
pub fn thread_stack_trace(
    pid: u32,
    tid: u32,
    max_frames: usize,
) -> Result<String, ThreadStackError> {
    if max_frames == 0 {
        return Ok(String::new());
    }

    // Best-effort: if we're elevated, this often improves access to service / higher-IL targets.
    // If it fails, we continue (we still want a clear error message below).
    let _ = crate::win::enable_debug_privilege();

    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) };
    let Ok(process) = process else {
        return Err(map_last_error("OpenProcess", pid, 0));
    };
    let process_guard = HandleGuard::new(process);

    // Prevent confusing failures: we don't currently implement Wow64GetThreadContext.
    if cfg!(target_arch = "x86_64") {
        if is_wow64_process(process_guard.raw())? {
            return Err(ThreadStackError::Unsupported {
                reason: "WoW64 (32-bit) targets are not supported yet for Stack".to_string(),
            });
        }
    }

    // Try multiple access right combinations for protected processes.
    // Some targets (e.g., Chrome sandbox) deny THREAD_GET_CONTEXT but allow limited query.
    let access_attempts = [
        // Standard approach: full access
        THREAD_ACCESS_RIGHTS(
            THREAD_GET_CONTEXT.0 | THREAD_SUSPEND_RESUME.0 | THREAD_QUERY_INFORMATION.0,
        ),
        // Reduced access: try without QUERY_INFORMATION
        THREAD_ACCESS_RIGHTS(THREAD_GET_CONTEXT.0 | THREAD_SUSPEND_RESUME.0),
        // Minimal access: just context
        THREAD_ACCESS_RIGHTS(THREAD_GET_CONTEXT.0),
    ];

    let mut thread_guard = None;
    let mut _last_open_error = None;

    for desired in access_attempts.iter() {
        let thread = unsafe { OpenThread(*desired, false, tid) };
        if let Ok(handle) = thread {
            thread_guard = Some(HandleGuard::new(handle));
            break;
        } else {
            _last_open_error = Some(unsafe { GetLastError() }.0);
        }
    }

    let Some(thread_guard) = thread_guard else {
        return Err(map_last_error("OpenThread", pid, tid));
    };

    // Best-effort suspend. Some protected processes may deny this, but we can try
    // capturing context without suspension (less reliable but sometimes works).
    let prev = unsafe { SuspendThread(thread_guard.raw()) };
    let did_suspend = prev != u32::MAX;

    let _resume = ResumeOnDrop {
        thread: thread_guard.raw(),
        did_suspend,
    };

    // Grab a context.
    // Request the minimum needed for unwinding (IP/SP/BP + general regs).
    // Some targets fail `GetThreadContext` with broader flag sets.
    #[cfg(target_arch = "x86_64")]
    const CONTEXT_MIN_FLAGS: u32 = 0x0010_0003;
    #[cfg(target_arch = "x86")]
    const CONTEXT_MIN_FLAGS: u32 = 0x0001_0003;
    #[cfg(target_arch = "x86_64")]
    const CONTEXT_FULL_FLAGS: u32 = 0x0010_0007;
    #[cfg(target_arch = "x86")]
    const CONTEXT_FULL_FLAGS: u32 = 0x0001_0007;

    let mut context: windows::Win32::System::Diagnostics::Debug::CONTEXT = unsafe { mem::zeroed() };

    // Try with minimal flags first, then fall back to more complete context
    let mut got_context = false;
    for flags in [CONTEXT_MIN_FLAGS, CONTEXT_FULL_FLAGS] {
        context = unsafe { mem::zeroed() };
        context.ContextFlags = CONTEXT_FLAGS(flags);
        if unsafe { GetThreadContext(thread_guard.raw(), &mut context) }.is_ok() {
            got_context = true;
            break;
        }
    }

    if !got_context {
        return Err(map_last_error("GetThreadContext", pid, tid));
    }

    // Serialize dbghelp usage. Sym* APIs are effectively process-global.
    let lock = DBGHELP_LOCK.get_or_init(|| Mutex::new(()));
    let _dbghelp_guard = lock.lock().expect("dbghelp lock poisoned");

    unsafe {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        // `invade_process = true` loads module list for symbol resolution.
        SymInitialize(process_guard.raw(), PCSTR::null(), true)
            .map_err(|_| map_last_error("SymInitialize", pid, tid))?;
    }

    let mut out = String::new();
    let mut frame: STACKFRAME64 = unsafe { mem::zeroed() };

    #[cfg(target_arch = "x86_64")]
    {
        use windows::Win32::System::Diagnostics::Debug::AddrModeFlat;

        unsafe extern "system" fn function_table_access(process: HANDLE, addr: u64) -> *mut c_void {
            SymFunctionTableAccess64(process, addr)
        }

        unsafe extern "system" fn get_module_base(process: HANDLE, addr: u64) -> u64 {
            SymGetModuleBase64(process, addr)
        }

        frame.AddrPC = ADDRESS64 {
            Offset: context.Rip as u64,
            Mode: AddrModeFlat,
            Segment: 0,
        };
        frame.AddrFrame = ADDRESS64 {
            Offset: context.Rbp as u64,
            Mode: AddrModeFlat,
            Segment: 0,
        };
        frame.AddrStack = ADDRESS64 {
            Offset: context.Rsp as u64,
            Mode: AddrModeFlat,
            Segment: 0,
        };

        // IMAGE_FILE_MACHINE_AMD64
        let machine: u32 = 0x8664;

        for idx in 0..max_frames {
            let ok = unsafe {
                StackWalk64(
                    machine,
                    process_guard.raw(),
                    thread_guard.raw(),
                    &mut frame,
                    &mut context as *mut _ as *mut c_void,
                    None,
                    Some(function_table_access),
                    Some(get_module_base),
                    None,
                )
            }
            .as_bool();
            if !ok {
                break;
            }

            let ip = frame.AddrPC.Offset;
            if ip == 0 {
                break;
            }

            let line = unsafe { format_frame(process_guard.raw(), ip) };
            out.push_str(&format!("#{idx:02} {line}\n"));
        }
    }

    unsafe {
        let _ = SymCleanup(process_guard.raw());
    }

    if out.trim().is_empty() {
        return Err(ThreadStackError::Unsupported {
            reason: "No frames captured (thread may have exited or context unavailable)"
                .to_string(),
        });
    }

    Ok(out)
}

#[cfg(not(windows))]
pub fn thread_stack_trace(
    _pid: u32,
    _tid: u32,
    _max_frames: usize,
) -> Result<String, ThreadStackError> {
    Err(ThreadStackError::Unsupported {
        reason: "Stack is only supported on Windows".to_string(),
    })
}

unsafe fn format_frame(process: HANDLE, addr: u64) -> String {
    let mut disp: u64 = 0;
    const MAX_NAME: usize = 256;
    let mut buf = vec![0u8; mem::size_of::<SYMBOL_INFO>() + MAX_NAME];
    let sym = buf.as_mut_ptr() as *mut SYMBOL_INFO;
    (*sym).SizeOfStruct = mem::size_of::<SYMBOL_INFO>() as u32;
    (*sym).MaxNameLen = MAX_NAME as u32;

    if SymFromAddr(process, addr, Some(&mut disp), sym).is_err() {
        return format!("0x{addr:x}");
    }

    // SYMBOL_INFO::Name is a C char buffer. windows-rs exposes it as a [u8; 1] tail.
    let name_ptr = (*sym).Name.as_ptr();
    let name = cstr_to_string(name_ptr);
    if disp > 0 {
        format!("{} + 0x{disp:x} (0x{addr:x})", name)
    } else {
        format!("{} (0x{addr:x})", name)
    }
}

unsafe fn cstr_to_string(ptr: *const i8) -> String {
    if ptr.is_null() {
        return "<unknown>".to_string();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
        if len > 4096 {
            break;
        }
    }
    let slice = std::slice::from_raw_parts(ptr as *const u8, len);
    String::from_utf8_lossy(slice).to_string()
}
