use pmonnt_core::handles::HandleCache;
use pmonnt_core::module::{ModuleCache, map_address_to_module};
use pmonnt_core::reputation_service::ReputationService;
use pmonnt_core::snapshot::ProcessSnapshot;
use pmonnt_core::thread::{ThreadCache, ThreadInfo};
use pmonnt_core::token::TokenCache;
use pmonnt_core::win::handles::get_type_name;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;

pub(super) fn build_handles_report(
    pid: u32,
    pid_to_image_path: &HashMap<u32, String>,
    current_snapshot: &ProcessSnapshot,
    handle_cache: &HandleCache,
    scan_interval_secs: u64,
) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Get current timestamp (simple format)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let datetime = format!("{:.0}", now.as_secs());

    // Get process name from snapshot first, then fall back to image path
    let process_name = current_snapshot
        .processes
        .iter()
        .find(|p| p.pid == pid)
        .map_or_else(
            || {
                pid_to_image_path
                    .get(&pid)
                    .and_then(|path| std::path::Path::new(path).file_name())
                    .and_then(|name| name.to_str())
                    .unwrap_or("—")
            },
            |p| p.name.as_str(),
        );

    let mut report = format!(
        "PMonNT Handles Report\nTime: {datetime} (Unix timestamp)\nProcess: {process_name} (PID {pid})\n"
    );

    // Handle count and delta
    if let Some(summary) = handle_cache.get(pid) {
        let delta = handle_cache.get_delta(pid);
        let delta_str = if let Some(d) = delta {
            let sign = if d > 0 { "+" } else { "" };
            format!(" ({sign}{d})")
        } else {
            String::new()
        };
        let _ = writeln!(report, "Handles: {}{}", summary.total, delta_str);
    } else {
        report.push_str("Handles: unavailable (access restricted)\n");
    }

    // Leak status
    let is_leaking = handle_cache.is_leaking(pid);
    if is_leaking {
        report.push_str("Leak: YES");
        if let Some((samples, delta, flats_used)) = handle_cache.get_leak_explanation(pid) {
            let (_, _, flat_tol) = handle_cache.get_detector_config(pid);
            let _ = write!(
                report,
                " — Triggered: {samples} samples, +{delta} handles, flats {flats_used}/{flat_tol}"
            );
        }
        report.push('\n');
    } else {
        report.push_str("Leak: no\n");
    }

    // Top growing types
    let gaps = 5u64.saturating_sub(1);
    let estimated_seconds = gaps * scan_interval_secs;
    let _ = writeln!(
        report,
        "Top growing types (last 5 samples ~{estimated_seconds}s):"
    );

    if let Some(growing_types) = handle_cache.get_top_growing_types(pid) {
        if growing_types.is_empty() {
            report.push_str("  none\n");
        } else {
            for (type_idx, delta, current_count) in growing_types {
                let type_name = get_type_name(type_idx);
                let _ = writeln!(report, "  {type_name} +{delta} (now {current_count})");
            }
        }
    } else {
        report.push_str("  collecting history...\n");
    }

    report
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_full_report(
    pid: u32,
    pid_to_image_path: &HashMap<u32, String>,
    current_snapshot: &ProcessSnapshot,
    token_cache: &mut TokenCache,
    thread_cache: &mut ThreadCache,
    thread_prev: &HashMap<u32, Vec<ThreadInfo>>,
    module_cache: &mut ModuleCache,
    reputation_service: &Arc<ReputationService>,
    handle_cache: &HandleCache,
    scan_interval_secs: u64,
) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Get current timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let datetime = format!("{:.0}", now.as_secs());

    // Get process info
    let process = current_snapshot.processes.iter().find(|p| p.pid == pid);
    let process_name = process.map_or("—", |p| p.name.as_str());
    let ppid = process
        .and_then(|p| p.ppid)
        .map_or_else(|| "?".to_string(), |p| p.to_string());
    let image_path = pid_to_image_path
        .get(&pid)
        .map_or("unavailable", std::string::String::as_str);

    let mut report = format!(
        "PMonNT Process Report\nTime: {datetime} (Unix timestamp)\nProcess: {process_name} (PID {pid}, PPID {ppid})\nImage: {image_path}\n\n"
    );

    // TOKEN section
    report.push_str("TOKEN\n");
    let token_info = token_cache.get_token_info(pid);
    if token_info.is_success() {
        let _ = writeln!(
            report,
            "User: {}",
            token_info.user.as_deref().unwrap_or("—")
        );
        let _ = writeln!(
            report,
            "Integrity: {}",
            token_info.integrity.as_deref().unwrap_or("—")
        );
        let _ = writeln!(
            report,
            "Elevation: {}",
            if token_info.elevated.unwrap_or(false) {
                "elevated"
            } else {
                "unelevated"
            }
        );

        let enabled_privs = token_info.privileges.iter().filter(|p| p.enabled).count();
        let disabled_privs = token_info.privileges.len() - enabled_privs;
        let _ = write!(report, "Privileges (enabled): {enabled_privs}  ");

        // List top 5 enabled privileges
        let enabled_list: Vec<_> = token_info
            .privileges
            .iter()
            .filter(|p| p.enabled)
            .take(5)
            .map(|p| p.name.as_str())
            .collect();
        if !enabled_list.is_empty() {
            let _ = write!(report, "({})", enabled_list.join(", "));
        }
        report.push('\n');

        if disabled_privs > 0 {
            let _ = writeln!(report, "Privileges (disabled): {disabled_privs}");
        }
    } else {
        report.push_str("Token: unavailable (access restricted)\n");
    }
    report.push('\n');

    // THREADS section
    report.push_str("THREADS (last interval)\n");
    if let Some(current_threads) = thread_cache.get(pid) {
        if let Some(prev_threads) = thread_prev.get(&pid) {
            // Calculate deltas
            let mut thread_deltas: Vec<(u32, i64, Option<u64>)> = Vec::new(); // (tid, delta_ms, start_addr)

            for thread in current_threads {
                if let Some(prev_thread) = prev_threads.iter().find(|pt| pt.tid == thread.tid) {
                    let current_cpu = (thread.kernel_time_100ns + thread.user_time_100ns) / 10000; // Convert to ms
                    let prev_cpu =
                        (prev_thread.kernel_time_100ns + prev_thread.user_time_100ns) / 10000;
                    let delta = current_cpu as i64 - prev_cpu as i64;
                    if delta > 0 {
                        thread_deltas.push((thread.tid, delta, thread.start_address));
                    }
                }
            }

            // Sort by delta descending and take top 5
            thread_deltas.sort_by_key(|d| std::cmp::Reverse(d.1));
            thread_deltas.truncate(5);

            if thread_deltas.is_empty() {
                report.push_str("Top threads: none with positive delta\n");
            } else {
                report.push_str("Top threads:\n");
                for (tid, delta_ms, start_addr) in thread_deltas {
                    // Try to attribute to module
                    let module_info = if let Some(modules_result) = module_cache.get(pid) {
                        map_address_to_module(start_addr, &modules_result.modules).map_or_else(
                            || "?".to_string(),
                            |(mod_name, offset)| format!("{mod_name}+{offset:X}"),
                        )
                    } else {
                        "?".to_string()
                    };
                    let _ = writeln!(
                        report,
                        "  TID {}: +{}ms  start={:X}  module={}",
                        tid,
                        delta_ms,
                        start_addr.unwrap_or(0),
                        module_info
                    );
                }
            }
        } else {
            report.push_str("Top threads: collecting baseline...\n");
        }
    } else {
        report.push_str("Threads: not available (collecting...)\n");
    }
    report.push('\n');

    // MODULES section
    report.push_str("MODULES\n");
    if let Some(modules_result) = module_cache.get(pid) {
        let total = modules_result.modules.len();
        let signed = modules_result
            .modules
            .iter()
            .filter(|m| m.signed == Some(true))
            .count();
        let unsigned = modules_result
            .modules
            .iter()
            .filter(|m| m.signed == Some(false))
            .count();
        let unknown = total - signed - unsigned;

        let _ = writeln!(
            report,
            "Total: {total}  Signed: {signed}  Unsigned: {unsigned}  Unknown: {unknown}"
        );

        if unsigned > 0 {
            report.push_str("Unsigned (top 10):\n");
            let unsigned_modules: Vec<_> = modules_result
                .modules
                .iter()
                .filter(|m| m.signed == Some(false))
                .take(10)
                .collect();

            for module in unsigned_modules {
                let _ = writeln!(
                    report,
                    "  {}  {}",
                    module.name,
                    module.path.as_deref().unwrap_or("no path")
                );
            }
        }
    } else {
        report.push_str("Modules: not available (collecting...)\n");
    }
    report.push('\n');

    // HANDLES section - reuse existing logic
    report.push_str("HANDLES\n");
    if let Some(summary) = handle_cache.get(pid) {
        let delta = handle_cache.get_delta(pid);
        let delta_str = if let Some(d) = delta {
            let sign = if d > 0 { "+" } else { "" };
            format!(" ({sign}{d})")
        } else {
            String::new()
        };
        let _ = writeln!(report, "Handles: {}{}", summary.total, delta_str);
    } else {
        report.push_str("Handles: unavailable (access restricted)\n");
    }

    // Leak status
    let is_leaking = handle_cache.is_leaking(pid);
    if is_leaking {
        report.push_str("Leak: YES");
        if let Some((samples, delta, flats_used)) = handle_cache.get_leak_explanation(pid) {
            let (_, _, flat_tol) = handle_cache.get_detector_config(pid);
            let _ = write!(
                report,
                " — Triggered: {samples} samples, +{delta} handles, flats {flats_used}/{flat_tol}"
            );
        }
        report.push('\n');
    } else {
        report.push_str("Leak: no\n");
    }

    // Top growing types
    let gaps = 5u64.saturating_sub(1);
    let estimated_seconds = gaps * scan_interval_secs;
    let _ = writeln!(
        report,
        "Top growing types (last 5 samples ~{estimated_seconds}s):"
    );

    if let Some(growing_types) = handle_cache.get_top_growing_types(pid) {
        if growing_types.is_empty() {
            report.push_str("  none\n");
        } else {
            for (type_idx, delta, current_count) in growing_types {
                let type_name = get_type_name(type_idx);
                let _ = writeln!(report, "  {type_name} +{delta} (now {current_count})");
            }
        }
    } else {
        report.push_str("  collecting history...\n");
    }
    report.push('\n');

    // REPUTATION section
    report.push_str("REPUTATION\n");
    if let Some(hash) = pid_to_image_path.get(&pid) {
        // Try to get cached reputation result
        let reputation_result = reputation_service.get_result(hash);
        match reputation_result {
            Some(result) => {
                let _ = writeln!(report, "VT: {}", result.state);
                let _ = writeln!(
                    report,
                    "Hash: {}",
                    result.sha256.as_deref().unwrap_or("computing...")
                );
            }
            None => {
                report.push_str("Reputation: not requested or pending\n");
            }
        }
    } else {
        report.push_str("Reputation: image path unavailable\n");
    }

    report
}
