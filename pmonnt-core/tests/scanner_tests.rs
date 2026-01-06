//! Tests for process scanner memory protection functions

use pmonnt_core::yara::scanner::process_scanner::ProcessScanner;
use windows::Win32::System::Memory::{
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
};

#[test]
fn test_is_readable_page_readonly() {
    assert!(ProcessScanner::is_readable(PAGE_READONLY.0));
}

#[test]
fn test_is_readable_page_readwrite() {
    assert!(ProcessScanner::is_readable(PAGE_READWRITE.0));
}

#[test]
fn test_is_readable_page_noaccess() {
    assert!(!ProcessScanner::is_readable(PAGE_NOACCESS.0));
}

#[test]
fn test_is_readable_page_guard() {
    assert!(!ProcessScanner::is_readable(PAGE_GUARD.0));
}

#[test]
fn test_is_executable_page_execute() {
    assert!(ProcessScanner::is_executable(PAGE_EXECUTE.0));
}

#[test]
fn test_is_executable_page_execute_read() {
    assert!(ProcessScanner::is_executable(PAGE_EXECUTE_READ.0));
}

#[test]
fn test_is_executable_page_readonly() {
    assert!(!ProcessScanner::is_executable(PAGE_READONLY.0));
}

#[test]
fn test_is_executable_page_readwrite() {
    assert!(!ProcessScanner::is_executable(PAGE_READWRITE.0));
}

// Integration tests for YARA scanning

#[test]
fn test_scanner_construction_succeeds() {
    use pmonnt_core::yara::engine::YaraEngine;
    use std::sync::Arc;
    
    let rule = r#"
rule test_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = Arc::new(YaraEngine::compile(rule).unwrap());
    
    // Should construct successfully
    let _scanner = ProcessScanner::new(engine);
}

#[test]
fn test_scanner_can_be_cloned() {
    use pmonnt_core::yara::engine::YaraEngine;
    use std::sync::Arc;
    
    let rule = r#"
rule test_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = Arc::new(YaraEngine::compile(rule).unwrap());
    let scanner = ProcessScanner::new(engine);
    
    // ProcessScanner implements Clone
    let _scanner2 = scanner.clone();
}

#[test]
fn test_multiple_scanners_share_engine() {
    use pmonnt_core::yara::engine::YaraEngine;
    use std::sync::Arc;
    
    let rule = r#"
rule shared_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = Arc::new(YaraEngine::compile(rule).unwrap());
    
    // Multiple scanners can share the same engine via Arc
    let _scanner1 = ProcessScanner::new(Arc::clone(&engine));
    let _scanner2 = ProcessScanner::new(Arc::clone(&engine));
    let _scanner3 = ProcessScanner::new(engine);
}


