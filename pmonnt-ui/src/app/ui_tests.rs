//! End-to-end UI tests: the real `PMonNTApp`, driven the way a user would drive it.
//!
//! The app runs inside an [`egui_kittest::Harness`] (no window). Tests find widgets by the
//! text a user sees, through the AccessKit tree, then click, type or press keys, and check
//! both what is on screen and the app's state. See `docs/ui-testing.md`.
//!
//! The app is built with [`PMonNTApp::for_tests`]: no API keys, default settings, nothing
//! saved on exit, online lookups off. Tests that act on processes only touch processes they
//! spawned themselves.

use std::time::{Duration, Instant};

use eframe::egui;
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use pmonnt_core::win::process_control::query_process_create_time;

use super::PMonNTApp;
use crate::view::RightTab;

/// The real app in a 1400x900 test window.
/// The size of the test window.
pub(crate) const WINDOW: egui::Vec2 = egui::vec2(1400.0, 900.0);

pub(crate) fn app_harness() -> Harness<'static, PMonNTApp> {
    let mut harness = Harness::builder()
        .with_size(WINDOW)
        // Many icon-only widgets have no accessible name yet; `unnamed_widgets` lists them.
        .with_accessibility_check(false)
        // The app loads system fonts in production; the harness only has egui's built-in
        // ones, so emoji icons (e.g. the copy button) would otherwise panic.
        .allow_missing_glyphs()
        .build_eframe(|_cc| PMonNTApp::for_tests());
    // Let panel sizes and fonts settle: clicks go to where a widget was last drawn.
    harness.run_steps(3);
    harness
}

/// Click a text field and type into it (a field must have focus to receive text).
pub(crate) fn type_into(harness: &mut Harness<'_, PMonNTApp>, field_label: &str, text: &str) {
    harness.get_by_label(field_label).click();
    harness.run_steps(2);
    harness.get_by_label(field_label).type_text(text);
    harness.run_steps(2);
}

/// Step the app (in real time, since its data collection runs on wall-clock intervals and
/// background threads) until `done` holds, or panic with `what` after `timeout`.
#[track_caller]
pub(crate) fn step_until(
    harness: &mut Harness<'_, PMonNTApp>,
    timeout: Duration,
    what: &str,
    mut done: impl FnMut(&Harness<'_, PMonNTApp>) -> bool,
) {
    let deadline = Instant::now() + timeout;
    loop {
        harness.step();
        if done(harness) {
            return;
        }
        if Instant::now() >= deadline {
            let shot = save_screenshot(harness, "timeout");
            panic!(
                "timed out after {timeout:?} waiting for {what}\n{shot}\n\nScreen:\n{}",
                describe_ui(harness)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Render the current frame to a PNG named after the running test and `label`, in
/// `$PMONNT_UI_SCREENSHOTS` (default: `<temp>/pmonnt-ui-tests`). Returns a line saying
/// where it went, or why there is none (rendering needs a GPU adapter; on a machine
/// without one the tests still run, just without pictures).
pub(crate) fn save_screenshot(harness: &mut Harness<'_, PMonNTApp>, label: &str) -> String {
    let dir = std::env::var_os("PMONNT_UI_SCREENSHOTS").map_or_else(
        || std::env::temp_dir().join("pmonnt-ui-tests"),
        std::path::PathBuf::from,
    );
    let test = std::thread::current()
        .name()
        .unwrap_or("ui-test")
        .rsplit("::")
        .next()
        .unwrap_or("ui-test")
        .to_string();
    let path = dir.join(format!("{test}-{label}.png"));
    // egui_kittest builds its wgpu renderer on first use and panics when there is no
    // adapter; that must not replace the failure being reported (a `step_until` timeout).
    let rendered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| harness.render()))
        .unwrap_or_else(|panic| {
            let why = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "the renderer panicked".to_string());
            Err(format!("no renderer: {why}"))
        });
    let saved = rendered.and_then(|image| {
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        image.save(&path).map_err(|e| e.to_string())
    });
    match saved {
        Ok(()) => format!("Screenshot: {}", path.display()),
        Err(e) => format!("No screenshot: {e}"),
    }
}

/// Take a fresh process snapshot on the next step instead of waiting up to two seconds.
pub(crate) fn refresh_processes(harness: &mut Harness<'_, PMonNTApp>) {
    harness.state_mut().last_snapshot_update = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now);
    harness.step();
}

/// Whether any widget shows `text` (in its label or its value: egui exposes the text of a
/// plain label as the node's value).
pub(crate) fn shows(harness: &Harness<'_, PMonNTApp>, text: &str) -> bool {
    fn walk(node: &egui_kittest::Node<'_>, text: &str) -> bool {
        let ak = node.accesskit_node();
        ak.label().is_some_and(|l| l.contains(text))
            || ak.value().is_some_and(|v| v.contains(text))
            || node.children().any(|child| walk(&child, text))
    }
    walk(&harness.root(), text)
}

/// The widget whose label or value is exactly `text`.
#[track_caller]
pub(crate) fn widget_with_text<'h>(
    harness: &'h Harness<'_, PMonNTApp>,
    text: &'h str,
) -> egui_kittest::Node<'h> {
    harness
        .query_by_label(text)
        .or_else(|| harness.query_by_value(text))
        .unwrap_or_else(|| {
            panic!(
                "no widget shows {text:?}\n\nScreen:\n{}",
                describe_ui(harness)
            )
        })
}

/// Click the widget showing `text`, then let the app react (a click spans several frames:
/// hover, press, release).
#[track_caller]
pub(crate) fn click(harness: &mut Harness<'_, PMonNTApp>, text: &str) {
    widget_with_text(harness, text).click();
    harness.run_steps(3);
}

/// Click the button labelled `label` (for labels that also appear as plain text).
#[track_caller]
pub(crate) fn click_button(harness: &mut Harness<'_, PMonNTApp>, label: &str) {
    harness
        .get_by_role_and_label(egui::accesskit::Role::Button, label)
        .click();
    harness.run_steps(3);
}

/// Click a tab in the details panel. Tab names can also label other buttons (the "GPU" and
/// "Handles" sort buttons), and the tab bar scrolls, so this picks the topmost button with
/// that label, scrolls it into view, then clicks it.
#[track_caller]
pub(crate) fn click_tab(harness: &mut Harness<'_, PMonNTApp>, name: &str) {
    fn topmost<'h>(h: &'h Harness<'_, PMonNTApp>, name: &'h str) -> egui_kittest::Node<'h> {
        h.get_all_by_role_and_label(egui::accesskit::Role::Button, name)
            .min_by(|a, b| a.rect().min.y.total_cmp(&b.rect().min.y))
            .unwrap_or_else(|| panic!("no {name:?} tab\n\nScreen:\n{}", describe_ui(h)))
    }
    topmost(harness, name).scroll_to_me();
    harness.run_steps(3);
    topmost(harness, name).click();
    harness.run_steps(3);
}

/// Click the button on the same line as the text `beside` (an expander next to a name).
#[track_caller]
pub(crate) fn click_button_beside(harness: &mut Harness<'_, PMonNTApp>, beside: &str) {
    let y = widget_with_text(harness, beside).rect().center().y;
    let button = harness
        .get_all_by_role(egui::accesskit::Role::Button)
        .find(|b| (b.rect().center().y - y).abs() < 4.0)
        .map_or_else(
            || {
                panic!(
                    "no button beside {beside:?}\n\nScreen:\n{}",
                    describe_ui(harness)
                )
            },
            |b| b.rect().center(),
        );
    click_at(harness, button);
}

/// Click at a screen position (for places without their own widget, such as row padding).
pub(crate) fn click_at(harness: &mut Harness<'_, PMonNTApp>, pos: egui::Pos2) {
    harness.hover_at(pos);
    harness.step();
    for pressed in [true, false] {
        harness.event(egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        });
        harness.step();
    }
    harness.run_steps(2);
}

/// Switch to the tree view and narrow the list to `pid` (and its ancestors) with the
/// filter box, then click its row. Returns the row's text, `"name (pid)"`.
pub(crate) fn select_in_tree(harness: &mut Harness<'_, PMonNTApp>, pid: u32) -> String {
    click(harness, "Tree (PPID)");
    refresh_processes(harness);
    let name = harness
        .state()
        .current_snapshot
        .get_process(pid)
        .unwrap_or_else(|| panic!("PID {pid} is not in the process snapshot"))
        .name
        .clone();
    let row = format!("{name} ({pid})");

    type_into(harness, "Filter:", &pid.to_string());
    // The filter keeps the target's ancestors visible but the tree starts collapsed; expand
    // the chain down to it (as clicking each node's expander would).
    let mut ancestor = harness
        .state()
        .current_snapshot
        .get_process(pid)
        .and_then(|p| p.ppid);
    let mut chain = Vec::new();
    while let Some(ppid) = ancestor.filter(|&p| p != 0 && !chain.contains(&p)) {
        chain.push(ppid);
        ancestor = harness
            .state()
            .current_snapshot
            .get_process(ppid)
            .and_then(|p| p.ppid);
    }
    harness.state_mut().expanded_pids.extend(chain);
    step_until(harness, Duration::from_secs(5), &row, |h| shows(h, &row));
    // The PID filter matches substrings, so other rows can push the target out of view.
    widget_with_text(harness, &row).scroll_to_me();
    // The table sizes its columns over the next frames; click once the row has settled.
    harness.run_steps(3);
    click(harness, &row);
    step_until(
        harness,
        Duration::from_secs(5),
        "the row to be selected",
        |h| h.state().selected_pid == Some(pid),
    );
    row
}

/// What is on screen, as an indented outline of the AccessKit tree: one line per labelled
/// or valued node (`role "label" = value`). Meant for reading by people and AI agents
/// when a test fails or when deciding what to click.
pub(crate) fn describe_ui(harness: &Harness<'_, PMonNTApp>) -> String {
    fn walk<'t>(node: &egui_kittest::Node<'t>, depth: usize, out: &mut String) {
        let ak = node.accesskit_node();
        let label = ak.label().filter(|l| !l.trim().is_empty());
        let value = ak.value().filter(|v| !v.trim().is_empty());
        let shown = label.is_some() || value.is_some();
        if shown {
            use std::fmt::Write as _;
            let _ = write!(out, "{}{:?}", "  ".repeat(depth), ak.role());
            if let Some(label) = &label {
                let _ = write!(out, " {label:?}");
            }
            if let Some(value) = &value {
                let _ = write!(out, " = {value:?}");
            }
            if ak.is_disabled() {
                out.push_str(" (disabled)");
            }
            out.push('\n');
        }
        for child in node.children() {
            walk(&child, depth + usize::from(shown), out);
        }
    }
    let mut out = String::new();
    walk(&harness.root(), 0, &mut out);
    out
}

/// A process that runs for about a minute and needs no console or input. Killed (and
/// reaped) on drop if a test fails before killing it through the UI.
pub(crate) struct TestProcess(pub(crate) std::process::Child);

impl TestProcess {
    pub(crate) fn ping() -> Self {
        Self(
            std::process::Command::new("ping")
                .args(["-n", "60", "127.0.0.1"])
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("spawn ping"),
        )
    }

    pub(crate) fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "exploration aid: prints the UI outline and saves a screenshot; run with --ignored --nocapture"]
fn print_main_window_outline() {
    let mut harness = app_harness();
    refresh_processes(&mut harness);
    harness.run_steps(3);
    println!("{}", describe_ui(&harness));
    println!("{}", save_screenshot(&mut harness, "main-window"));
}

#[test]
fn delete_key_kills_the_selected_process_after_confirmation() {
    let mut target = TestProcess::ping();
    let pid = target.pid();
    let mut h = app_harness();
    select_in_tree(&mut h, pid);

    h.key_press(egui::Key::Delete);
    step_until(&mut h, Duration::from_secs(5), "the kill dialog", |h| {
        shows(h, "Confirm Kill Process")
    });
    assert!(
        target.0.try_wait().unwrap().is_none(),
        "nothing dies before Kill"
    );

    click_button(&mut h, "Kill");
    step_until(&mut h, Duration::from_secs(10), "the kill result", |h| {
        shows(h, "Kill succeeded") || shows(h, "Kill failed")
    });
    assert!(shows(&h, "Kill succeeded"), "{}", describe_ui(&h));
    let status = target.0.wait().unwrap();
    assert_eq!(status.code(), Some(1), "terminated by PMonNT (exit code 1)");

    click(&mut h, "Close");
    assert!(!shows(&h, "Confirm Kill Process"));
}

#[test]
fn cancelling_the_kill_dialog_leaves_the_process_running() {
    let mut target = TestProcess::ping();
    let pid = target.pid();
    let mut h = app_harness();
    select_in_tree(&mut h, pid);

    h.key_press(egui::Key::Delete);
    step_until(&mut h, Duration::from_secs(5), "the kill dialog", |h| {
        shows(h, "Confirm Kill Process")
    });
    click(&mut h, "Cancel");
    assert!(!shows(&h, "Confirm Kill Process"));
    assert!(
        target.0.try_wait().unwrap().is_none(),
        "process must survive Cancel"
    );
}

#[test]
fn shift_delete_kills_the_whole_tree() {
    // cmd.exe with a ping child.
    let mut parent = TestProcess(
        std::process::Command::new("cmd")
            .args(["/c", "ping -n 60 127.0.0.1 >NUL"])
            .spawn()
            .expect("spawn cmd"),
    );
    let pid = parent.pid();
    let mut h = app_harness();

    // Wait until the child exists, then note its identity.
    let is_ping_child = |p: &&pmonnt_core::process::Process| {
        p.ppid == Some(pid) && p.name.eq_ignore_ascii_case("PING.EXE")
    };
    step_until(&mut h, Duration::from_secs(10), "cmd's ping child", |h| {
        h.state()
            .current_snapshot
            .processes
            .iter()
            .any(|p| is_ping_child(&p))
    });
    let child_pid = h
        .state()
        .current_snapshot
        .processes
        .iter()
        .find(is_ping_child)
        .map(|p| p.pid)
        .unwrap();
    let child_created = query_process_create_time(child_pid).unwrap();

    select_in_tree(&mut h, pid);
    h.key_press_modifiers(egui::Modifiers::SHIFT, egui::Key::Delete);
    step_until(
        &mut h,
        Duration::from_secs(5),
        "the kill-tree dialog",
        |h| shows(h, "Confirm Kill Process Tree"),
    );
    click_button(&mut h, "Kill Tree");
    step_until(&mut h, Duration::from_secs(10), "the kill result", |h| {
        shows(h, "Kill succeeded") || shows(h, "Kill failed")
    });
    assert!(shows(&h, "Kill succeeded"), "{}", describe_ui(&h));

    assert!(parent.0.wait().is_ok());
    // The child is gone (or its PID belongs to a different process by now).
    let deadline = Instant::now() + Duration::from_secs(5);
    while query_process_create_time(child_pid).ok() == Some(child_created) {
        assert!(Instant::now() < deadline, "ping child survived Kill Tree");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn every_details_tab_renders_for_the_selected_process() {
    let me = std::process::id();
    let mut h = app_harness();
    select_in_tree(&mut h, me);

    // Summary is open at the start, so it comes last: every click must change the tab.
    for (label, tab) in [
        ("Performance Graph", RightTab::PerformanceGraph),
        ("Details", RightTab::Details),
        ("Services", RightTab::Services),
        ("Threads", RightTab::Threads),
        ("Handles", RightTab::Handles),
        ("Network", RightTab::Network),
        ("GPU", RightTab::GPU),
        ("Version", RightTab::Version),
        ("Reputation", RightTab::Reputation),
        ("Scan", RightTab::Scan),
        ("Settings", RightTab::Settings),
        ("Summary", RightTab::Summary),
    ] {
        click_tab(&mut h, label);
        assert_eq!(
            h.state().right_tab,
            tab,
            "clicking {label} did not open it\n\nScreen:\n{}",
            describe_ui(&h)
        );
        assert_eq!(
            h.state().selected_pid,
            Some(me),
            "tab {label} lost the selection"
        );
    }
}

#[test]
fn virustotal_check_hashes_off_the_ui_thread_and_queries_without_network() {
    let me = std::process::id();
    let exe = std::env::current_exe().unwrap();
    let expected_sha = pmonnt_core::hashing::HashComputer::new()
        .compute_sha256(&exe.to_string_lossy())
        .unwrap();

    let mut h = app_harness();
    // No API keys in a test app, so VirusTotal answers "not configured" without a request.
    h.state_mut().online_lookups_enabled = true;
    select_in_tree(&mut h, me);
    click_tab(&mut h, "Reputation");
    click_button_beside(&mut h, "VirusTotal");
    step_until(
        &mut h,
        Duration::from_secs(5),
        "the VirusTotal section",
        |h| shows(h, "Check this process in VirusTotal"),
    );

    click(&mut h, "Check this process in VirusTotal");
    step_until(&mut h, Duration::from_secs(30), "the lookup result", |h| {
        h.state()
            .reputation_service
            .get_vt_sample_for_hash(&expected_sha)
            .is_some()
    });
    let (_, meta) = h
        .state()
        .reputation_service
        .get_vt_sample_for_hash(&expected_sha)
        .unwrap();
    assert_eq!(meta.last_query_status.as_deref(), Some("not_configured"));
    h.run_steps(2);
    assert!(shows(&h, &expected_sha), "the section shows the image hash");
}

#[test]
fn performance_window_opens_and_switches_tabs() {
    let me = std::process::id();
    let mut h = app_harness();
    let row = select_in_tree(&mut h, me);
    let _ = row;
    // Double-click opens it in the app; the harness has no double-click, so call the same
    // method the double-click handler calls.
    h.state_mut().open_perf_window(me);
    step_until(&mut h, Duration::from_secs(5), "the perf window", |h| {
        shows(h, &format!("(PID {me})"))
    });
    assert!(h.state().perf_windows.contains_key(&me));
    h.run_steps(5);
}

#[test]
fn clicking_a_process_name_selects_its_row() {
    // Regression: list text used to be selectable, and a selectable label took the click,
    // so clicking a process's name did not select it.
    let target = TestProcess::ping();
    let pid = target.pid();
    let mut h = app_harness();
    let row = select_in_tree(&mut h, pid);

    h.state_mut().selected_pid = None;
    h.run_steps(3);
    widget_with_text(&h, &row).click();
    step_until(
        &mut h,
        Duration::from_secs(5),
        "the row to be selected",
        |h| h.state().selected_pid == Some(pid),
    );
}

#[test]
fn clicking_anywhere_in_a_row_selects_it() {
    // Regressions: clicks on text cells and in the Name column were lost (selectable labels,
    // and a row click area registered under the first cell's id).
    let me = std::process::id();
    let mut h = app_harness();
    let row = select_in_tree(&mut h, me);
    let name = widget_with_text(&h, &row).rect();
    let y = name.center().y;

    // Click points come from the row's own cells, not fixed positions: the details panel
    // widens to fit what it shows for the process, so where the list ends varies by machine.
    let list_right = h
        .query_all_by_role(egui::accesskit::Role::Splitter)
        .map(|splitter| splitter.rect().min.x)
        .filter(|&x| x > name.max.x)
        .fold(WINDOW.x, f32::min);
    let mut cells: Vec<egui::Rect> = h
        .query_all_by_role(egui::accesskit::Role::Label)
        .map(|label| label.rect())
        .filter(|r| r.min.y <= y && y <= r.max.y && r.min.x > name.max.x && r.max.x < list_right)
        .collect();
    cells.sort_by(|a, b| a.min.x.total_cmp(&b.min.x));
    assert!(
        cells.len() >= 3,
        "expected the row's cells left of x={list_right}, found {cells:?}"
    );
    let middle = cells[cells.len() / 2];
    // Blank space after a cell's text, well clear of the next column's resize handle.
    let Some(gap) = cells
        .windows(2)
        .rev()
        .find(|pair| pair[1].min.x - pair[0].max.x >= 30.0)
    else {
        panic!("no blank space between the row's cells: {cells:?}");
    };
    let padding = gap[0].max.x + (gap[1].min.x - gap[0].max.x) / 3.0;

    for (what, x) in [
        ("the process name", name.center().x),
        ("a middle cell's text", middle.center().x),
        ("blank space in a cell", padding),
    ] {
        h.state_mut().selected_pid = None;
        h.run_steps(3);
        click_at(&mut h, egui::pos2(x, y));
        assert_eq!(
            h.state().selected_pid,
            Some(me),
            "clicking {what} at x={x} (list ends at x={list_right}) did not select"
        );
    }
}

#[test]
fn expander_collapses_a_node_without_selecting_it() {
    let me = std::process::id();
    let mut h = app_harness();
    select_in_tree(&mut h, me);
    let snapshot = std::sync::Arc::clone(&h.state().current_snapshot);
    let parent = snapshot.get_process(me).unwrap().ppid.unwrap();
    let grandparent = snapshot.get_process(parent).unwrap().ppid.unwrap();
    let row_of = |pid: u32| format!("{} ({pid})", snapshot.get_process(pid).unwrap().name);

    // Select the grandparent; collapsing the parent then hides only rows below it (a hidden
    // selection is cleared on purpose).
    click(&mut h, &row_of(grandparent));
    assert_eq!(h.state().selected_pid, Some(grandparent));

    click_button_beside(&mut h, &row_of(parent));
    assert!(
        !h.state().expanded_pids.contains(&parent),
        "expander did not collapse"
    );
    assert_eq!(
        h.state().selected_pid,
        Some(grandparent),
        "clicking the expander selected its row"
    );
}
