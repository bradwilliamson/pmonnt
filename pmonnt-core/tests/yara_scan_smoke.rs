#![cfg(windows)]

use std::sync::Arc;

use pmonnt_core::yara::engine::YaraEngine;
use pmonnt_core::yara::scanner::{ProcessScanner, ScanError, ScanOptions};
use tokio_util::sync::CancellationToken;

#[test]
#[ignore]
fn yara_scan_can_be_cancelled_via_token() {
    // Integration-style test: scans process memory and verifies cancellation path.
    // Ignored by default because it depends on OS state + may be slow.

    let engine = Arc::new(
        YaraEngine::compile(
            r#"rule PMonNT_Test_Rule {
    meta:
        description = "unit test rule"
        severity = "low"
    strings:
        $a = "PMonNT_YARA_TEST_STRING" ascii wide
    condition:
        $a
}"#,
        )
        .expect("compile test rules"),
    );

    // Keep the needle alive in this process' memory for the duration of the scan.
    let _needle = "PMonNT_YARA_TEST_STRING".to_string();

    let scanner = ProcessScanner::new(engine);
    let pid = std::process::id();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, async move {
        let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel(32);
        let cancel = CancellationToken::new();

        let scanner = scanner.clone();
        let cancel_for_task = cancel.clone();

        let task = tokio::task::spawn_local(async move {
            scanner
                .scan_process_with_options(pid, ScanOptions::deep(), progress_tx, cancel_for_task)
                .await
        });

        // Wait until we see at least one progress update, then cancel.
        let _ = progress_rx.recv().await;
        cancel.cancel();

        let res = task.await.expect("task join");
        assert!(matches!(res, Err(ScanError::Cancelled)));
    });
}
