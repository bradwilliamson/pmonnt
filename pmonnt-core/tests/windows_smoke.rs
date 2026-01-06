#[cfg(windows)]
mod windows_smoke {
    use std::env;

    #[test]
    fn enumerate_processes_has_current_pid() {
        let procs = pmonnt_core::win::process_enum::enumerate_processes().expect("enumerate");
        assert!(!procs.is_empty());

        let me = std::process::id();
        assert!(procs.iter().any(|p| p.pid == me));
    }

    #[test]
    fn current_process_image_path_is_non_empty() {
        let me = std::process::id();
        let path = pmonnt_core::win::process_path::get_process_image_path(me)
            .expect("current process image path should be readable");
        assert!(!path.trim().is_empty());
    }

    #[test]
    fn privileged_security_info_opt_in() {
        if env::var("PMONNT_RUN_PRIV_TESTS").ok().as_deref() != Some("1") {
            return;
        }

        let me = std::process::id();
        let sec = pmonnt_core::win::token_info::get_process_security_info(me)
            .expect("get_process_security_info");
        // Basic invariant: user SID string present.
        assert!(!sec.summary.user_sid.is_empty());
    }

    #[test]
    #[ignore] // Opt-in smoke test
    fn module_enumeration_returns_valid_data() {
        if env::var("PMONNT_RUN_SMOKE_TESTS").ok().as_deref() != Some("1") {
            return;
        }

        let me = std::process::id();
        let result = pmonnt_core::module::fetch_modules(me, false);
        
        // Should have no error
        assert!(result.error.is_none(), "Module enumeration should succeed for current process");
        
        // Current process should have at least one module (the exe itself)
        assert!(!result.modules.is_empty(), "Expected at least one module for current process");
    }

    #[test]
    #[ignore] // Opt-in smoke test
    fn signature_verification_succeeds() {
        if env::var("PMONNT_RUN_SMOKE_TESTS").ok().as_deref() != Some("1") {
            return;
        }

        let me = std::process::id();
        let path_str = pmonnt_core::win::process_path::get_process_image_path(me)
            .expect("current process image path");
        
        let path = std::path::Path::new(&path_str);
        
        // Query signature - should return either valid signature or known "not signed" state
        let sig_result = pmonnt_core::win::signature::verify_signature(path);
        
        // Should not error (even if unsigned, should return valid SignatureInfo)
        assert!(sig_result.is_ok(), "Signature query should not error");
    }

    #[test]
    #[ignore] // Opt-in smoke test
    fn thread_enumeration_returns_data() {
        if env::var("PMONNT_RUN_SMOKE_TESTS").ok().as_deref() != Some("1") {
            return;
        }

        let me = std::process::id();
        
        // Enumerate threads for current process
        let threads_result = pmonnt_core::win::thread::list_threads(me);
        
        // Should succeed
        assert!(threads_result.is_ok(), "Thread enumeration should succeed");
        
        // Current process should have at least one thread
        let threads = threads_result.unwrap();
        assert!(!threads.is_empty(), "Expected at least one thread for current process");
    }

    #[test]
    #[ignore] // Opt-in smoke test
    fn network_connections_query_succeeds() {
        if env::var("PMONNT_RUN_SMOKE_TESTS").ok().as_deref() != Some("1") {
            return;
        }

        // Query all network connections
        let result = pmonnt_core::network::get_all_connections();
        
        // Should succeed without error
        assert!(result.is_ok(), "Network connection query should not error");
    }

    #[test]
    #[ignore] // Opt-in smoke test  
    fn token_info_readable_for_current_process() {
        if env::var("PMONNT_RUN_SMOKE_TESTS").ok().as_deref() != Some("1") {
            return;
        }

        let me = std::process::id();
        
        // Get token info
        let token_result = pmonnt_core::win::token_info::get_process_security_info(me);
        
        if let Ok(sec) = token_result {
            // Should have user SID
            assert!(!sec.summary.user_sid.is_empty(), "User SID should not be empty");
        }
    }

    #[test]
    #[ignore] // Opt-in smoke test
    fn handle_query_succeeds() {
        if env::var("PMONNT_RUN_SMOKE_TESTS").ok().as_deref() != Some("1") {
            return;
        }

        // Query all handles
        let result = pmonnt_core::win::handles::enumerate_handles();
        
        // Should succeed
        assert!(result.is_ok(), "Handle query should not error");
        
        let handles = result.unwrap();
        // System should have handles
        assert!(!handles.is_empty(), "System should have handles");
    }
}


