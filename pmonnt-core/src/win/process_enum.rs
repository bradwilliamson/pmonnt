//! Windows process enumeration (one `SystemProcessInformation` snapshot).

use crate::process::Process;
use anyhow::Result;

/// Enumerate all running processes on the system.
///
/// Uses one `SystemProcessInformation` query, so each process's PID, parent, creation time
/// and name come from the same kernel snapshot. (ToolHelp plus a second query for creation
/// times could pair a name with a different instance that reused the PID in between.)
/// Names are decoded from UTF-16, so executables in any language come back intact.
pub fn enumerate_processes() -> Result<Vec<Process>> {
    let entries = crate::win::process_metrics::query_processes_with_names()?;
    Ok(entries
        .into_iter()
        .map(|(entry, name)| Process {
            pid: entry.pid,
            // The idle process has no image name; keep ToolHelp's label for it.
            name: if entry.pid == 0 && name.is_empty() {
                "[System Process]".to_string()
            } else {
                name
            },
            ppid: Some(entry.parent_pid),
            cpu_percent: None,
            memory_bytes: None,
            gpu_percent: None,
            gpu_memory_bytes: None,
            path: None,
            signature: None,
            create_time: Some(entry.create_time),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_finds_current_process_by_name() {
        let me = std::process::id();
        let exe = std::env::current_exe().unwrap();
        let exe_name = exe.file_name().unwrap().to_string_lossy();
        let procs = enumerate_processes().unwrap();
        let mine = procs
            .iter()
            .find(|p| p.pid == me)
            .expect("current process listed");
        assert!(mine.name.eq_ignore_ascii_case(&exe_name), "{:?}", mine.name);
        assert!(procs.iter().any(|p| p.pid == 4 && p.name == "System"));
        assert!(
            procs
                .iter()
                .any(|p| p.pid == 0 && p.name == "[System Process]")
        );
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

    #[test]
    fn non_ascii_executable_names_survive() {
        // A copy of a tiny system executable under a non-ASCII name (review H4: the ANSI
        // ToolHelp API used to abort the whole snapshot on such names).
        let dir = std::env::temp_dir().join(format!("pmonnt_enum_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("日本語プロセス.exe");
        std::fs::copy(r"C:\Windows\System32\PING.EXE", &exe).unwrap();
        let mut child = std::process::Command::new(&exe)
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let procs = enumerate_processes();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);

        let procs = procs.unwrap();
        let name = &procs
            .iter()
            .find(|p| p.pid == pid)
            .expect("child listed")
            .name;
        assert_eq!(name, "日本語プロセス.exe");
    }
}
