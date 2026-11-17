# UI testing

PMonNT's UI can be driven in tests the way a person drives it: find a widget by the text on
screen, click it, type, press keys, then check what the window shows and what the app did.
This is how AI agents (and people) verify UI changes without clicking through the app by
hand. The tests live in `pmonnt-ui/src/app/ui_tests.rs` and run with the normal test suite
on Windows:

```
cargo test -p pmonnt-ui ui_tests
```

## How it works

[egui_kittest](https://docs.rs/egui_kittest) runs the real `PMonNTApp` (both `logic` and
`ui`, every frame) without opening a window. egui describes every widget through
AccessKit, the same tree screen readers use, and the harness queries that tree: a button is
found by its label, a text field by the label it is tied to, a plain label by its text.

The app is built with `PMonNTApp::for_tests()` (`AppEnvironment::Test`):

- no API keys are loaded, and online lookups start disabled with every reputation provider
  switched off, so nothing reaches the network unless a test turns lookups on (VirusTotal
  and MalwareBazaar then answer "not configured" locally; do not click ThreatFox Check,
  which works without a key);
- the saved layout and leak-detector settings are neither read nor written;
- the reputation cache is a throwaway file in the temp directory.

Use `for_tests()`, never `try_new()`, in tests: `try_new()` loads the user's keys and saves
their settings on exit.

The process list is the real one. Tests that act on processes only touch processes they
spawned themselves (`TestProcess::ping()`, a `ping -n 60` that is killed on drop).

## Helpers

| Helper | What it does |
|---|---|
| `app_harness()` | The app in a 1400x900 test window, settled for a few frames. |
| `select_in_tree(&mut h, pid)` | Switch to Tree view, filter to the PID, expand its ancestors and click its row. Returns the row text. |
| `click(&mut h, "text")` | Click the widget showing that text, then let the app react. |
| `click_button(&mut h, "label")` | Same, but only buttons (when the text also appears as a label). |
| `click_tab(&mut h, "Reputation")` | Click a details-panel tab (scrolls it into view; ignores same-named sort buttons). |
| `click_button_beside(&mut h, "text")` | Click the button on the same line as a text (row expanders, provider rows). |
| `click_at(&mut h, pos)` | Click a screen position (row padding and other places without a widget). |
| `type_into(&mut h, "Filter:", "1234")` | Focus a labelled text field and type. |
| `step_until(&mut h, timeout, "what", \|h\| ...)` | Run frames in real time until a condition holds. On timeout the panic includes the screen outline and a screenshot path. |
| `refresh_processes(&mut h)` | Take a fresh process snapshot now instead of waiting up to 2 s. |
| `shows(&h, "text")` | Whether any widget shows that text (labels expose their text as a value). |
| `describe_ui(&h)` | The screen as an indented outline: `role "label" = value`, one line per widget. |
| `save_screenshot(&mut h, "label")` | Render the frame to a PNG (see below). |

`h.state()` / `h.state_mut()` give the `PMonNTApp` itself, for checking results
(`selected_pid`, `kill_dialog`, caches) or for setup the UI does not offer.

## Seeing the screen

Two ways, both meant to be read by an agent:

- **Outline.** `describe_ui` prints what AccessKit sees. Run the exploration test to get
  the whole main window:

  ```
  cargo test -p pmonnt-ui print_main_window_outline -- --ignored --nocapture
  ```

- **Screenshots.** `save_screenshot` renders the frame with wgpu and writes
  `<test>-<label>.png` to `$PMONNT_UI_SCREENSHOTS` (default `%TEMP%\pmonnt-ui-tests`). A
  `step_until` timeout saves one automatically and prints its path. Rendering needs a GPU
  adapter (a software adapter works); without one the tests still run and the message says
  why there is no picture. From WSL the Windows temp directory is under `/mnt/c/Users/...`.

The same outline plus a screenshot is the fastest way to find out why a click did nothing:
in this repository it found that row clicks were lost in the Name column, that process names
were laid out right to left, and that most details tabs were cut off at the default panel
width.

## Writing a test

```rust
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
    click_button(&mut h, "Kill");
    step_until(&mut h, Duration::from_secs(10), "the kill result", |h| {
        shows(h, "Kill succeeded") || shows(h, "Kill failed")
    });
    assert_eq!(target.0.wait().unwrap().code(), Some(1));
}
```

Things that matter:

- **A click spans frames.** Hover, press and release are separate frames; the helpers step
  for you. If you call `node.click()` yourself, run a few steps before checking the result.
- **Click where the widget is now.** Clicks go to where a widget was last drawn. After
  anything that changes layout (selecting a row opens the details panel; tables size their
  columns over a few frames), step before clicking.
- **Off-screen widgets cannot be clicked.** Scroll them into view (`node.scroll_to_me()`)
  or narrow the list with the filter first.
- **Wall-clock time matters.** Snapshots refresh every 2 s and lookups run on background
  threads; use `step_until` with a timeout rather than a fixed number of steps.
- **Give new widgets a name.** Buttons are named by their text; a text field needs
  `.labelled_by(label.id)`. Icon-only buttons (`"📋"`, `">"`) are hard to find; prefer a
  text label or a hover text plus a stable neighbour (`click_button_beside`).
- **Not covered by the harness:** the app minimized (only `logic` runs then), native
  dialogs (file pickers, the Windows permissions editor) and separate OS windows. Perf
  windows render inside the main window in tests.
