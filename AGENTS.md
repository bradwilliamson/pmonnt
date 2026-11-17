# Notes for AI agents

PMonNT is a Windows process monitor: `pmonnt-core` (data collection, view model, reputation,
YARA; the platform-independent parts also build on Linux) and `pmonnt-ui` (egui app).
Toolchain: Rust 1.99.0 (`rust-toolchain.toml`).

## Checks before a change is done

On Windows:

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

On Linux (portable core only): `cargo test -p pmonnt-core`, and
`tools/valgrind/memcheck-core-tests.sh` for memory errors. Performance work: see
`docs/performance.md` (Gungraun/Valgrind benchmarks).

## Verifying UI changes

Do not stop at "it compiles": drive the UI. `pmonnt-ui/src/app/ui_tests.rs` runs the real
app headless, finds widgets by their on-screen text, clicks and types, and can print the
screen as an outline or save a screenshot. Read `docs/ui-testing.md` before writing a UI
test. Build the app with `PMonNTApp::for_tests()` in tests (never `try_new()`, which loads
the user's API keys and saves their settings), and only kill processes the test spawned.

## Conventions

- Lints are curated in the workspace `Cargo.toml`; the tree is warning-free under clippy
  `-D warnings`. Every `unsafe` block has a `// SAFETY:` comment.
- Win32 structs read from byte buffers go through `pmonnt_core::aligned_buf::AlignedBuf`.
- Long-running work stays off the UI thread (background worker, reputation worker); results
  are applied on the UI thread and checked against the current selection and process
  identity (`Process::create_time`), since Windows recycles PIDs.
