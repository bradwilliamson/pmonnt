use std::path::{Path, PathBuf};

use chrono::Local;
use thiserror::Error;
use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    MiniDumpIgnoreInaccessibleMemory, MiniDumpScanMemory, MiniDumpWithFullMemory,
    MiniDumpWithFullMemoryInfo, MiniDumpWithHandleData, MiniDumpWithIndirectlyReferencedMemory,
    MiniDumpWithThreadInfo, MiniDumpWithTokenInformation, MiniDumpWithUnloadedModules,
    MiniDumpWriteDump, MINIDUMP_TYPE,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use super::HandleGuard;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DumpKind {
    Mini,
    Full,
}

impl DumpKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DumpKind::Mini => "mini",
            DumpKind::Full => "full",
        }
    }
}

#[derive(Error, Debug, Clone)]
pub enum DumpError {
    #[error("{message}")]
    Message { message: String },
}

impl DumpError {
    fn win32(context: &str) -> Self {
        let err = unsafe { GetLastError() };
        let code = err.0;

        // A few targeted hints that are useful in the UI.
        let hint = match code {
            5 => "Access denied. Try running elevated (Admin) and ensure SeDebugPrivilege is enabled.",
            87 => "Invalid parameter. The process may have exited.",
            299 => "Only part of a ReadProcessMemory request was completed. Try a minidump instead of full dump.",
            _ => "",
        };

        let mut message = format!("{context} (Win32={code})");
        if !hint.is_empty() {
            message.push_str(". ");
            message.push_str(hint);
        }
        DumpError::Message { message }
    }

    fn dbghelp_failed() -> Self {
        // Best-effort guidance. In practice dbghelp.dll is present on Windows, but this helps if the call fails.
        DumpError::win32("MiniDumpWriteDump failed. Ensure dbghelp.dll is present and the target process is accessible")
    }
}

/// Default dump directory: %LOCALAPPDATA%\PMonNT\dumps\
/// Falls back to a "dumps" folder next to the current working directory.
pub fn default_dump_dir() -> PathBuf {
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let dir = Path::new(&local_appdata).join("PMonNT").join("dumps");
        return dir;
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("dumps")
}

fn sanitize_process_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        // Windows forbids: < > : " / \ | ? *
        let bad = matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*');
        if bad || ch.is_control() {
            out.push('_');
        } else {
            out.push(ch);
        }
    }

    let out = out.trim().trim_matches('.').trim_matches(' ').to_string();
    if out.is_empty() {
        "process".to_string()
    } else {
        out
    }
}

fn format_dump_filename_with_timestamp(
    process_name: &str,
    pid: u32,
    ts: &str,
    kind: DumpKind,
) -> String {
    let name = sanitize_process_name(process_name);
    format!("{name}_{pid}_{ts}_{}.dmp", kind.as_str())
}

fn dump_type_for(kind: DumpKind) -> MINIDUMP_TYPE {
    let flags = match kind {
        DumpKind::Mini => {
            MiniDumpWithIndirectlyReferencedMemory.0
                | MiniDumpScanMemory.0
                | MiniDumpWithUnloadedModules.0
                | MiniDumpWithThreadInfo.0
                | MiniDumpWithHandleData.0
                | MiniDumpIgnoreInaccessibleMemory.0
        }
        DumpKind::Full => {
            MiniDumpWithFullMemory.0
                | MiniDumpWithFullMemoryInfo.0
                | MiniDumpWithHandleData.0
                | MiniDumpWithThreadInfo.0
                | MiniDumpWithUnloadedModules.0
                | MiniDumpWithTokenInformation.0
                | MiniDumpIgnoreInaccessibleMemory.0
        }
    };

    MINIDUMP_TYPE(flags)
}

/// Write a process dump to disk using MiniDumpWriteDump.
///
/// - `out_dir` will be created if missing.
/// - File name format: {process_name}_{pid}_{yyyyMMdd_HHmmss}_{mini|full}.dmp
pub fn write_process_dump(
    pid: u32,
    process_name: &str,
    kind: DumpKind,
    out_dir: PathBuf,
) -> Result<PathBuf, DumpError> {
    std::fs::create_dir_all(&out_dir).map_err(|e| DumpError::Message {
        message: format!(
            "Failed to create dump directory '{}': {e}",
            out_dir.display()
        ),
    })?;

    let ts = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let filename = format_dump_filename_with_timestamp(process_name, pid, &ts, kind);
    let out_path = out_dir.join(filename);

    let file = std::fs::File::create(&out_path).map_err(|e| DumpError::Message {
        message: format!("Failed to create dump file '{}': {e}", out_path.display()),
    })?;

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;

        let proc = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
            .map_err(|_| DumpError::win32(&format!("Failed to open PID {pid} for dump")))?;
        let proc_guard = HandleGuard::new(proc);

        let file_handle = HANDLE(file.as_raw_handle());
        if file_handle.0.is_null() {
            return Err(DumpError::Message {
                message: "Invalid output file handle".to_string(),
            });
        }

        let dump_type = dump_type_for(kind);
        if unsafe {
            MiniDumpWriteDump(
                proc_guard.raw(),
                pid,
                file_handle,
                dump_type,
                None,
                None,
                None,
            )
        }
        .is_err()
        {
            let _ = std::fs::remove_file(&out_path);
            return Err(DumpError::dbghelp_failed());
        }

        Ok(out_path)
    }

    #[cfg(not(windows))]
    {
        let _ = (pid, process_name, kind, out_path);
        Err(DumpError::Message {
            message: "Process dumps are only supported on Windows".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_filename_format_includes_kind_and_sanitizes() {
        let f = super::format_dump_filename_with_timestamp(
            "bad:name.exe",
            123,
            "20260101_120000",
            DumpKind::Mini,
        );
        assert!(f.contains("bad_name.exe_123_20260101_120000_mini.dmp"));

        let f2 = super::format_dump_filename_with_timestamp(
            "<>:\\|?*",
            7,
            "20260101_120000",
            DumpKind::Full,
        );
        assert!(f2.ends_with("_7_20260101_120000_full.dmp"));
        assert!(!f2.contains(":\\"));
    }

    #[test]
    fn dump_output_dir_can_be_created() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("pmonnt_dump_test_{unique}"));

        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }

        std::fs::create_dir_all(&dir).expect("create temp dir");
        assert!(dir.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
