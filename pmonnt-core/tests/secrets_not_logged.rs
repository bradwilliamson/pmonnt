use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use log::{LevelFilter, Log, Metadata, Record};

use pmonnt_core::local_cache::LocalCacheProvider;
use pmonnt_core::providers::{MalwareBazaarProvider, ThreatFoxProvider};
use pmonnt_core::reputation::LookupState;
use pmonnt_core::vt::VirusTotalProvider;

static LOG_BUF: OnceLock<Mutex<String>> = OnceLock::new();
static LOGGER_INIT: OnceLock<()> = OnceLock::new();
static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

static LOGGER: BufLogger = BufLogger;

struct BufLogger;

impl Log for BufLogger {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        let buf = LOG_BUF.get_or_init(|| Mutex::new(String::new()));
        let mut guard = buf.lock().unwrap();
        guard.push_str(&format!("{}\n", record.args()));
    }

    fn flush(&self) {}
}

fn init_logger_once() {
    LOGGER_INIT.get_or_init(|| {
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(LevelFilter::Debug);
    });
}

fn clear_logs() {
    let buf = LOG_BUF.get_or_init(|| Mutex::new(String::new()));
    *buf.lock().unwrap() = String::new();
}

fn take_logs() -> String {
    let buf = LOG_BUF.get_or_init(|| Mutex::new(String::new()));
    buf.lock().unwrap().clone()
}

fn set_env_var(key: &str, value: String) -> Option<String> {
    let prev = std::env::var(key).ok();
    std::env::set_var(key, value);
    prev
}

fn restore_env_var(key: &str, prev: Option<String>) {
    match prev {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
}

fn spawn_one_shot_http_server(listener: TcpListener, reply: String) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));

            // Read only until end-of-headers so we don't block waiting for EOF.
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
            let _ = stream.write_all(reply.as_bytes());
            let _ = stream.flush();
        }
    })
}

#[test]
fn vt_lookup_does_not_log_api_key_value() {
    init_logger_once();
    clear_logs();

    // Avoid concurrent tests racing on env vars.
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // VT provider forms: {base_url}/files/{sha}
    let prev_vt = set_env_var("VT_BASE_URL", format!("http://{}/api/v3", addr));

    let reply_body = include_str!("data/vt_hit_clean.json");
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reply_body.as_bytes().len(),
        reply_body
    );

    let server = spawn_one_shot_http_server(listener, reply);

    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("cache.json");
    let local_cache = std::sync::Arc::new(LocalCacheProvider::new(cache_path));

    let provider = VirusTotalProvider::new(local_cache);

    let secret = "SUPERSECRET_API_KEY_VALUE".to_string();
    provider.set_api_key(secret.clone());

    let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let state = provider.lookup_hash_sync(sha);
    assert!(matches!(state, LookupState::Hit(_)));

    let _ = server.join();

    restore_env_var("VT_BASE_URL", prev_vt);

    let logs = take_logs();
    assert!(
        !logs.contains(&secret),
        "logs unexpectedly contained API key value"
    );
}

#[test]
fn mb_get_info_does_not_log_api_key_value() {
    init_logger_once();
    clear_logs();

    // Avoid concurrent tests racing on env vars.
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // MalwareBazaar provider posts directly to the base endpoint.
    let prev_mb = set_env_var("MB_BASE_URL", format!("http://{}/api/v1/", addr));

    // Force a warning log path (401/403). Ensure body does not contain the secret.
    let reply_body = "unauthorized";
    let reply = format!(
        "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reply_body.as_bytes().len(),
        reply_body
    );
    let server = spawn_one_shot_http_server(listener, reply);

    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("cache.json");
    let local_cache = std::sync::Arc::new(LocalCacheProvider::new(cache_path));

    let secret = "SUPERSECRET_MB_API_KEY_VALUE".to_string();
    let provider = MalwareBazaarProvider::new(local_cache, Some(secret.clone()));

    let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let err = provider.get_info_verbose(sha).unwrap_err();
    // Unauthorized maps to NotConfigured.
    assert!(matches!(
        err,
        pmonnt_core::providers::MbApiError::NotConfigured
    ));

    let _ = server.join();

    restore_env_var("MB_BASE_URL", prev_mb);

    let logs = take_logs();
    assert!(
        !logs.contains(&secret),
        "logs unexpectedly contained API key value"
    );
}

#[test]
fn tf_search_hash_does_not_log_api_key_value() {
    init_logger_once();
    clear_logs();

    // Avoid concurrent tests racing on env vars.
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let prev_tf = set_env_var("TF_BASE_URL", format!("http://{}/api/v1/", addr));

    // Force the non-200 log path while still returning valid JSON.
    // Ensure body does not contain the secret.
    let reply_body = r#"{"query_status":"error","data":"not allowed"}"#;
    let reply = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reply_body.as_bytes().len(),
        reply_body
    );
    let server = spawn_one_shot_http_server(listener, reply);

    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("cache.json");
    let local_cache = std::sync::Arc::new(LocalCacheProvider::new(cache_path));

    let secret = "SUPERSECRET_TF_API_KEY_VALUE".to_string();
    let provider = ThreatFoxProvider::new(local_cache, Some(secret.clone()));

    let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let _ = provider.search_hash_verbose(sha).unwrap();

    let _ = server.join();

    restore_env_var("TF_BASE_URL", prev_tf);

    let logs = take_logs();
    assert!(
        !logs.contains(&secret),
        "logs unexpectedly contained API key value"
    );
}
