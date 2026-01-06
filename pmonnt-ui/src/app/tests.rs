// Tests for app module (moved from main.rs)
mod grouped_sort_tests {
    use super::super::state::{parse_ui_layout_config, serialize_ui_layout_config};
    use super::super::{perf_window, Density};
    use crate::process_rows::{build_grouped_rows, build_process_rows};
    use crate::process_table::{process_table_policy, ProcessColumns};
    use crate::theme::{apply_theme, Theme};
    use crate::util::{percent_used, sum_cpu_percent, sum_gpu_mem_bytes, sum_gpu_percent};
    use crate::view::GroupSort;
    use eframe::egui;
    use pmonnt_core::handles::HandleCache;
    use pmonnt_core::process;
    use pmonnt_core::win_process_metrics::IoRate;
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn proc(pid: u32, name: &str) -> process::Process {
        process::Process {
            pid,
            name: name.to_string(),
            ppid: None,
            cpu_percent: None,
            memory_bytes: None,
            gpu_percent: None,
            gpu_memory_bytes: None,
            path: None,
            signature: None,
        }
    }

    fn proc_with_ppid(pid: u32, ppid: Option<u32>, name: &str) -> process::Process {
        process::Process {
            pid,
            name: name.to_string(),
            ppid,
            cpu_percent: None,
            memory_bytes: None,
            gpu_percent: None,
            gpu_memory_bytes: None,
            path: None,
            signature: None,
        }
    }

    #[test]
    fn grouped_sort_cpu_desc_uses_total_cpu_sum() {
        let processes = vec![
            proc(1, "chrome.exe"),
            proc(2, "chrome.exe"),
            proc(3, "notepad.exe"),
        ];

        let handle_cache = HandleCache::new(0);
        let global_thread_counts: HashMap<u32, usize> = HashMap::new();

        // Total chrome: 30 + 30 = 60; notepad: 40.
        let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
        cpu_memory_data.insert(1, (30.0, Some(0)));
        cpu_memory_data.insert(2, (30.0, Some(0)));
        cpu_memory_data.insert(3, (40.0, Some(0)));

        let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
        let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();

        let empty_str_map: HashMap<u32, String> = HashMap::new();
        let empty_u32_map: HashMap<u32, u32> = HashMap::new();
        let empty_sig_cache: HashMap<String, pmonnt_core::SignatureInfo> = HashMap::new();

        let rows = build_grouped_rows(
            &processes,
            None,
            "",
            GroupSort::CPU,
            true,
            false,
            &handle_cache,
            &global_thread_counts,
            &cpu_memory_data,
            &io_rate_by_pid,
            &gpu_data,
            &empty_str_map,
            &empty_sig_cache,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_u32_map,
        );

        assert_eq!(rows[0].name, "chrome.exe");
        assert!(rows[0].cpu_percent > rows[1].cpu_percent);
    }

    #[test]
    fn grouped_sort_cpu_leader_toggle_changes_first_group() {
        // Aggregate CPU sort vs Leader CPU sort differ:
        // - a.exe has 2 children at 5% each: sum=10, leader=5
        // - b.exe has 1 child at 9%: sum=9, leader=9
        // So with Leader sort (desc) b.exe should come first.
        let processes = vec![proc(1, "a.exe"), proc(2, "a.exe"), proc(3, "b.exe")];

        let handle_cache = HandleCache::new(0);
        let global_thread_counts: HashMap<u32, usize> = HashMap::new();

        let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
        cpu_memory_data.insert(1, (5.0, Some(0)));
        cpu_memory_data.insert(2, (5.0, Some(0)));
        cpu_memory_data.insert(3, (9.0, Some(0)));

        let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
        let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();

        let empty_str_map: HashMap<u32, String> = HashMap::new();
        let empty_u32_map: HashMap<u32, u32> = HashMap::new();
        let empty_sig_cache: HashMap<String, pmonnt_core::SignatureInfo> = HashMap::new();

        let desc = build_grouped_rows(
            &processes,
            None,
            "",
            GroupSort::CPU,
            true,
            true,
            &handle_cache,
            &global_thread_counts,
            &cpu_memory_data,
            &io_rate_by_pid,
            &gpu_data,
            &empty_str_map,
            &empty_sig_cache,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_u32_map,
        );
        assert_eq!(desc[0].name, "b.exe");

        let asc = build_grouped_rows(
            &processes,
            None,
            "",
            GroupSort::CPU,
            false,
            true,
            &handle_cache,
            &global_thread_counts,
            &cpu_memory_data,
            &io_rate_by_pid,
            &gpu_data,
            &empty_str_map,
            &empty_sig_cache,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_u32_map,
        );
        assert_eq!(asc[0].name, "a.exe");
    }

    #[test]
    fn leader_sort_falls_back_to_cpu_when_sort_is_name() {
        let processes = vec![proc(10, "a.exe"), proc(11, "a.exe"), proc(20, "b.exe")];

        let handle_cache = HandleCache::new(0);
        let global_thread_counts: HashMap<u32, usize> = HashMap::new();

        let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
        cpu_memory_data.insert(10, (1.0, None));
        cpu_memory_data.insert(11, (1.0, None));
        cpu_memory_data.insert(20, (3.0, None));

        let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
        let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();
        let empty_str_map: HashMap<u32, String> = HashMap::new();
        let empty_u32_map: HashMap<u32, u32> = HashMap::new();
        let empty_sig_cache: HashMap<String, pmonnt_core::SignatureInfo> = HashMap::new();

        let desc = build_grouped_rows(
            &processes,
            None,
            "",
            GroupSort::Name,
            true,
            true,
            &handle_cache,
            &global_thread_counts,
            &cpu_memory_data,
            &io_rate_by_pid,
            &gpu_data,
            &empty_str_map,
            &empty_sig_cache,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_u32_map,
        );
        assert_eq!(desc[0].name, "b.exe");

        let asc = build_grouped_rows(
            &processes,
            None,
            "",
            GroupSort::Name,
            false,
            true,
            &handle_cache,
            &global_thread_counts,
            &cpu_memory_data,
            &io_rate_by_pid,
            &gpu_data,
            &empty_str_map,
            &empty_sig_cache,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_u32_map,
        );
        assert_eq!(asc[0].name, "a.exe");
    }

    #[test]
    fn grouped_sort_memory_desc_uses_total_memory_sum() {
        let processes = vec![proc(1, "a.exe"), proc(2, "b.exe")];

        let handle_cache = HandleCache::new(0);
        let global_thread_counts: HashMap<u32, usize> = HashMap::new();

        let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
        cpu_memory_data.insert(1, (0.0, Some(10_000)));
        cpu_memory_data.insert(2, (0.0, Some(50_000)));

        let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
        let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();
        let empty_str_map: HashMap<u32, String> = HashMap::new();
        let empty_u32_map: HashMap<u32, u32> = HashMap::new();
        let empty_sig_cache: HashMap<String, pmonnt_core::SignatureInfo> = HashMap::new();

        let rows = build_grouped_rows(
            &processes,
            None,
            "",
            GroupSort::Memory,
            true,
            false,
            &handle_cache,
            &global_thread_counts,
            &cpu_memory_data,
            &io_rate_by_pid,
            &gpu_data,
            &empty_str_map,
            &empty_sig_cache,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_u32_map,
        );

        assert_eq!(rows[0].name, "b.exe");
        assert!(rows[0].memory_bytes.unwrap() > rows[1].memory_bytes.unwrap());
    }

    #[test]
    fn grouped_sort_gpu_desc_uses_group_max_gpu() {
        let processes = vec![
            proc(1, "group.exe"),
            proc(2, "group.exe"),
            proc(3, "solo.exe"),
        ];

        let handle_cache = HandleCache::new(0);
        let global_thread_counts: HashMap<u32, usize> = HashMap::new();
        let cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();

        // group.exe max GPU = 75; solo.exe GPU = 50.
        let mut gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
        gpu_data.insert(1, (10.0, 0, 0, 0));
        gpu_data.insert(2, (75.0, 0, 0, 0));
        gpu_data.insert(3, (50.0, 0, 0, 0));

        let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();

        let empty_str_map: HashMap<u32, String> = HashMap::new();
        let empty_u32_map: HashMap<u32, u32> = HashMap::new();
        let empty_sig_cache: HashMap<String, pmonnt_core::SignatureInfo> = HashMap::new();

        let rows = build_grouped_rows(
            &processes,
            None,
            "",
            GroupSort::GPU,
            true,
            false,
            &handle_cache,
            &global_thread_counts,
            &cpu_memory_data,
            &io_rate_by_pid,
            &gpu_data,
            &empty_str_map,
            &empty_sig_cache,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_str_map,
            &empty_u32_map,
        );

        assert_eq!(rows[0].name, "group.exe");
        assert!(rows[0].gpu_percent >= rows[1].gpu_percent);
    }

    #[test]
    fn tree_sort_cpu_desc_sorts_siblings_by_cpu() {
        // root(1) with children [2,3]
        let p1 = proc_with_ppid(1, None, "root.exe");
        let p2 = proc_with_ppid(2, Some(1), "a.exe");
        let p3 = proc_with_ppid(3, Some(1), "b.exe");

        let processes = [p1, p2, p3];
        let pid_to_proc: HashMap<u32, &process::Process> =
            processes.iter().map(|p| (p.pid, p)).collect();

        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        children.insert(1, vec![2, 3]);

        let expanded: HashSet<u32> = [1].into_iter().collect();
        let handle_cache = HandleCache::new(0);
        let global_thread_counts: HashMap<u32, usize> = HashMap::new();

        let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
        cpu_memory_data.insert(2, (10.0, Some(0)));
        cpu_memory_data.insert(3, (90.0, Some(0)));

        let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();

        let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
        let empty_sig_cache: HashMap<String, pmonnt_core::SignatureInfo> = HashMap::new();

        let rows = build_process_rows(
            &[1],
            &children,
            &pid_to_proc,
            &expanded,
            None,
            None,
            "",
            16,
            GroupSort::CPU,
            true,
            &handle_cache,
            &global_thread_counts,
            &cpu_memory_data,
            &io_rate_by_pid,
            &gpu_data,
            &empty_sig_cache,
        );

        // rows: root, then children. Expect pid 3 first (higher CPU).
        assert_eq!(rows[0].pid, 1);
        assert_eq!(rows[1].pid, 3);
        assert_eq!(rows[2].pid, 2);
    }

    #[test]
    fn tree_sort_memory_desc_sorts_siblings_by_memory() {
        let p1 = proc_with_ppid(1, None, "root.exe");
        let p2 = proc_with_ppid(2, Some(1), "a.exe");
        let p3 = proc_with_ppid(3, Some(1), "b.exe");

        let processes = [p1, p2, p3];
        let pid_to_proc: HashMap<u32, &process::Process> =
            processes.iter().map(|p| (p.pid, p)).collect();

        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        children.insert(1, vec![2, 3]);

        let expanded: HashSet<u32> = [1].into_iter().collect();
        let handle_cache = HandleCache::new(0);
        let global_thread_counts: HashMap<u32, usize> = HashMap::new();

        let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
        cpu_memory_data.insert(2, (0.0, Some(10)));
        cpu_memory_data.insert(3, (0.0, Some(90)));

        let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();

        let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
        let empty_sig_cache: HashMap<String, pmonnt_core::SignatureInfo> = HashMap::new();

        let rows = build_process_rows(
            &[1],
            &children,
            &pid_to_proc,
            &expanded,
            None,
            None,
            "",
            16,
            GroupSort::Memory,
            true,
            &handle_cache,
            &global_thread_counts,
            &cpu_memory_data,
            &io_rate_by_pid,
            &gpu_data,
            &empty_sig_cache,
        );

        assert_eq!(rows[0].pid, 1);
        assert_eq!(rows[1].pid, 3);
        assert_eq!(rows[2].pid, 2);
    }

    #[test]
    fn responsive_column_policy_breakpoints_are_stable() {
        // Wide
        let wide = process_table_policy(1200.0);
        assert_eq!(wide.columns, ProcessColumns::Wide);
        assert!(wide.show_gpu_percent);
        assert!(wide.show_gpu_total);
        assert!(wide.show_gpu_mem_detail);
        assert!(wide.gpu_pct_w > 0.0);
        assert!(wide.gpu_total_w > 0.0);
        assert!(wide.gpu_mem_w > 0.0);
        assert!(wide.show_handles);
        assert!(wide.show_threads);

        // Medium
        let medium = process_table_policy(900.0);
        assert_eq!(medium.columns, ProcessColumns::Medium);
        assert!(medium.show_gpu_percent);
        assert!(medium.show_gpu_total);
        assert!(medium.show_gpu_mem_detail);
        assert!(medium.gpu_pct_w > 0.0);
        assert!(medium.gpu_total_w > 0.0);
        assert!(medium.gpu_mem_w > 0.0);
        assert!(medium.show_handles);
        assert!(medium.show_threads);

        // Narrow
        let narrow = process_table_policy(700.0);
        assert_eq!(narrow.columns, ProcessColumns::Narrow);
        assert!(narrow.show_gpu_percent);
        assert!(!narrow.show_gpu_total);
        assert!(!narrow.show_gpu_mem_detail);
        assert!(narrow.gpu_pct_w > 0.0);
        assert_eq!(narrow.gpu_total_w, 0.0);
        assert_eq!(narrow.gpu_mem_w, 0.0);
        assert!(!narrow.show_handles);
        assert!(narrow.show_threads);

        // Extra narrow
        let x = process_table_policy(480.0);
        assert_eq!(x.columns, ProcessColumns::ExtraNarrow);
        assert!(!x.show_gpu_percent);
        assert!(!x.show_gpu_total);
        assert!(!x.show_gpu_mem_detail);
        assert_eq!(x.gpu_pct_w, 0.0);
        assert_eq!(x.gpu_total_w, 0.0);
        assert_eq!(x.gpu_mem_w, 0.0);
        assert!(!x.show_handles);
        assert!(!x.show_threads);
    }

    #[test]
    fn tree_expansion_controls_child_visibility() {
        // root(1) with children [2,3]
        let p1 = proc_with_ppid(1, None, "root.exe");
        let p2 = proc_with_ppid(2, Some(1), "a.exe");
        let p3 = proc_with_ppid(3, Some(1), "b.exe");

        let processes = [p1, p2, p3];
        let pid_to_proc: HashMap<u32, &process::Process> =
            processes.iter().map(|p| (p.pid, p)).collect();

        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        children.insert(1, vec![2, 3]);

        let handle_cache = HandleCache::new(0);
        let global_thread_counts: HashMap<u32, usize> = HashMap::new();
        let cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
        let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();
        let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
        let empty_sig_cache: HashMap<String, pmonnt_core::SignatureInfo> = HashMap::new();

        // Collapsed: only root is visible.
        let expanded: HashSet<u32> = HashSet::new();
        let rows = build_process_rows(
            &[1],
            &children,
            &pid_to_proc,
            &expanded,
            None,
            None,
            "",
            16,
            GroupSort::Name,
            false,
            &handle_cache,
            &global_thread_counts,
            &cpu_memory_data,
            &io_rate_by_pid,
            &gpu_data,
            &empty_sig_cache,
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 1);

        // Expanded: root + children are visible.
        let expanded: HashSet<u32> = [1].into_iter().collect();
        let rows = build_process_rows(
            &[1],
            &children,
            &pid_to_proc,
            &expanded,
            None,
            None,
            "",
            16,
            GroupSort::Name,
            false,
            &handle_cache,
            &global_thread_counts,
            &cpu_memory_data,
            &io_rate_by_pid,
            &gpu_data,
            &empty_sig_cache,
        );
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].pid, 1);
        assert!(rows.iter().any(|r| r.pid == 2));
        assert!(rows.iter().any(|r| r.pid == 3));
    }

    #[test]
    fn theme_key_round_trips() {
        for t in [
            Theme::Dark,
            Theme::Light,
            Theme::GreenScreen,
            Theme::HighContrast,
        ] {
            let key = t.as_key();
            assert_eq!(Theme::from_key(key), Some(t));
        }
        assert_eq!(Theme::from_key("3270"), Some(Theme::GreenScreen));
        assert_eq!(Theme::from_key("unknown"), None);
    }

    #[test]
    fn ui_layout_config_parses_theme_and_serializes_stably() {
        let input = "# test\nleft_panel_width=500\ndensity=compact\ntheme=green_screen\n";
        let cfg = parse_ui_layout_config(input);
        assert_eq!(cfg.left_panel_width, 500.0);
        assert_eq!(cfg.density, Density::Compact);
        assert_eq!(cfg.theme, Theme::GreenScreen);

        let out = serialize_ui_layout_config(&cfg);
        let cfg2 = parse_ui_layout_config(&out);
        assert_eq!(cfg2.left_panel_width, cfg.left_panel_width);
        assert_eq!(cfg2.density, cfg.density);
        assert_eq!(cfg2.theme, cfg.theme);
    }

    #[test]
    fn ui_layout_config_is_backward_compatible_without_theme_key() {
        // Older configs didn't have a theme entry; we should default safely.
        let input = "# old config\nleft_panel_width=333\ndensity=comfortable\n";
        let cfg = parse_ui_layout_config(input);
        assert_eq!(cfg.left_panel_width, 333.0);
        assert_eq!(cfg.density, Density::Comfortable);
        assert_eq!(cfg.theme, Theme::Dark);
    }

    #[test]
    fn apply_theme_does_not_panic_for_any_theme() {
        // Historically, bad font configuration could brick the app at startup.
        // This test ensures all themes can be applied safely.
        let ctx = egui::Context::default();

        for t in [
            Theme::Dark,
            Theme::Light,
            Theme::GreenScreen,
            Theme::HighContrast,
        ] {
            let r = catch_unwind(AssertUnwindSafe(|| apply_theme(&ctx, t)));
            assert!(r.is_ok(), "apply_theme panicked for {:?}", t);
        }
    }

    #[test]
    fn totals_aggregate_cpu_and_gpu_are_clamped() {
        let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
        cpu_memory_data.insert(1, (60.0, Some(0)));
        cpu_memory_data.insert(2, (55.0, Some(0)));
        assert_eq!(sum_cpu_percent(&cpu_memory_data), 100.0);

        let mut gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
        gpu_data.insert(1, (10.0, 0, 0, 0));
        gpu_data.insert(2, (200.0, 0, 0, 0));
        assert_eq!(sum_gpu_percent(&gpu_data), 100.0);
    }

    #[test]
    fn percent_used_matches_task_manager_expectation() {
        assert_eq!(percent_used(16, 32), 50.0);
        assert_eq!(percent_used(0, 32), 0.0);
        assert_eq!(percent_used(32, 32), 100.0);
    }

    #[test]
    fn gpu_mem_totals_sum_across_pids() {
        let mut gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
        gpu_data.insert(1, (0.0, 10, 20, 30));
        gpu_data.insert(2, (0.0, 1, 2, 3));
        assert_eq!(sum_gpu_mem_bytes(&gpu_data), (11, 22, 33));
    }

    #[test]
    fn push_with_cap_keeps_latest_values() {
        let mut d: VecDeque<u32> = VecDeque::new();
        for i in 0..10 {
            perf_window::push_with_cap(&mut d, i, 4);
        }
        let got: Vec<u32> = d.into_iter().collect();
        assert_eq!(got, vec![6, 7, 8, 9]);
    }
}
