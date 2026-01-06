//! Provider HTTP status code mapping tests
//! Verifies correct HTTP response → LookupState behavior

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use pmonnt_core::local_cache::LocalCacheProvider;
use pmonnt_core::providers::ThreatFoxProvider;
use pmonnt_core::reputation::{LookupState, ReputationProvider};
use pmonnt_core::vt::VirusTotalProvider;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn set_env(key: &str, val: String) -> Option<String> {
    let prev = std::env::var(key).ok();
    std::env::set_var(key, val);
    prev
}

fn restore_env(key: &str, prev: Option<String>) {
    match prev {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
}

fn spawn_http_server(listener: TcpListener, response: String) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                        if buf.len() > 16 * 1024 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    })
}

// ============================================================================
// VirusTotal HTTP Status Tests
// ============================================================================

#[test]
fn vt_200_ok_returns_hit() {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let prev = set_env("VT_BASE_URL", format!("http://{}/api/v3", addr));

    let body = include_str!("data/vt_hit_clean.json");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    let server = spawn_http_server(listener, response);

    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(dir.path().join("cache.json")));
    let vt = VirusTotalProvider::new(cache);
    vt.set_api_key("test_key".to_string());

    let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let state = vt.lookup_hash_sync(sha);

    assert!(matches!(state, LookupState::Hit(_)));
    let _ = server.join();
    restore_env("VT_BASE_URL", prev);
}

#[test]
fn vt_404_returns_not_found() {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let prev = set_env("VT_BASE_URL", format!("http://{}/api/v3", addr));

    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    let server = spawn_http_server(listener, response.to_string());

    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(dir.path().join("cache.json")));
    let vt = VirusTotalProvider::new(cache);
    vt.set_api_key("test_key".to_string());

    let sha = "0000000000000000000000000000000000000000000000000000000000000000";
    let state = vt.lookup_hash_sync(sha);

    assert!(matches!(state, LookupState::NotFound));
    let _ = server.join();
    restore_env("VT_BASE_URL", prev);
}

#[test]
fn vt_401_returns_error() {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let prev = set_env("VT_BASE_URL", format!("http://{}/api/v3", addr));

    let response = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    let server = spawn_http_server(listener, response.to_string());

    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(dir.path().join("cache.json")));
    let vt = VirusTotalProvider::new(cache);
    vt.set_api_key("bad_key".to_string());

    let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let state = vt.lookup_hash_sync(sha);

    // 401 returns Error state
    assert!(matches!(state, LookupState::Error(_)));
    let _ = server.join();
    restore_env("VT_BASE_URL", prev);
}

#[test]
fn vt_429_returns_error() {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let prev = set_env("VT_BASE_URL", format!("http://{}/api/v3", addr));

    let response = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n";
    let server = spawn_http_server(listener, response.to_string());

    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(dir.path().join("cache.json")));
    let vt = VirusTotalProvider::new(cache);
    vt.set_api_key("test_key".to_string());

    let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let state = vt.lookup_hash_sync(sha);

    // Rate limiting returns Error
    assert!(matches!(state, LookupState::Error(_)));
    let _ = server.join();
    restore_env("VT_BASE_URL", prev);
}

#[test]
fn vt_second_lookup_uses_cache() {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let prev = set_env("VT_BASE_URL", format!("http://{}/api/v3", addr));

    let body = include_str!("data/vt_hit_clean.json");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    // Server only handles ONE request
    let server = spawn_http_server(listener, response);

    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("cache.json");
    let cache = Arc::new(LocalCacheProvider::new(cache_path));
    let vt = VirusTotalProvider::new(cache);
    vt.set_api_key("test_key".to_string());

    let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // First lookup hits server
    let state1 = vt.lookup_hash_sync(sha);
    assert!(matches!(state1, LookupState::Hit(_)));

    let _ = server.join();

    // Second lookup uses cache (server is closed)
    let state2 = vt.lookup_hash_sync(sha);
    assert!(matches!(state2, LookupState::Hit(_)));

    restore_env("VT_BASE_URL", prev);
}

// ============================================================================
// ThreatFox HTTP Status Tests
// ============================================================================

#[test]
fn threatfox_200_ok_returns_hit() {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let prev = set_env("TF_BASE_URL", format!("http://{}", addr));

    let body = include_str!("data/threatfox_search_hash_ok.json");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    let server = spawn_http_server(listener, response);

    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(dir.path().join("cache.json")));
    let tf = ThreatFoxProvider::new(cache, None);

    let sha = "41434443af7c72f00e6abe8bd31c39e26341ad3fc5c7ae7ce4ef5872f3c12e5e";
    let state = tf.lookup_hash(sha);

    // ThreatFox uses Aggregated state
    assert!(matches!(state, LookupState::Aggregated(_)));
    let _ = server.join();
    restore_env("TF_BASE_URL", prev);
}

#[test]
fn threatfox_no_result_returns_not_found() {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let prev = set_env("TF_BASE_URL", format!("http://{}", addr));

    // ThreatFox returns 200 with "query_status": "no_result"
    let body = r#"{"query_status":"no_result","data":null}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    let server = spawn_http_server(listener, response);

    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(dir.path().join("cache.json")));
    let tf = ThreatFoxProvider::new(cache, None);

    let sha = "0000000000000000000000000000000000000000000000000000000000000000";
    let state = tf.lookup_hash(sha);

    assert!(matches!(state, LookupState::NotFound));
    let _ = server.join();
    restore_env("TF_BASE_URL", prev);
}

#[test]
fn threatfox_429_returns_error() {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let prev = set_env("TF_BASE_URL", format!("http://{}", addr));

    let response = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n";
    let server = spawn_http_server(listener, response.to_string());

    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(dir.path().join("cache.json")));
    let tf = ThreatFoxProvider::new(cache, None);

    let sha = "41434443af7c72f00e6abe8bd31c39e26341ad3fc5c7ae7ce4ef5872f3c12e5e";
    let state = tf.lookup_hash(sha);

    assert!(matches!(state, LookupState::Error(_)));
    let _ = server.join();
    restore_env("TF_BASE_URL", prev);
}

#[test]
fn threatfox_network_error_returns_offline() {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    // Point to invalid URL that will fail to connect
    let prev = set_env("TF_BASE_URL", "http://127.0.0.1:1".to_string());

    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(dir.path().join("cache.json")));
    let tf = ThreatFoxProvider::new(cache, None);

    let sha = "41434443af7c72f00e6abe8bd31c39e26341ad3fc5c7ae7ce4ef5872f3c12e5e";
    let state = tf.lookup_hash(sha);

    // Connection refused should map to Offline
    assert!(matches!(state, LookupState::Offline));
    restore_env("TF_BASE_URL", prev);
}
