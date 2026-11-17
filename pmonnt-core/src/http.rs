//! Shared HTTP client construction.
//!
//! reqwest is built with `rustls-no-provider`, so the process must pick a rustls crypto
//! provider before the first client is created. Every client in PMonNT is created through
//! the builders here, which install the `ring` provider exactly once.

use std::sync::Once;
use std::time::Duration;

/// Default whole-request timeout for clients that do not set their own.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect timeout applied to every client.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Install the `ring` rustls crypto provider for the process (idempotent).
pub fn ensure_tls_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        // An error only means another provider was installed first, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn user_agent() -> String {
    format!("PMonNT/{}", env!("CARGO_PKG_VERSION"))
}

/// Builder for a blocking client with PMonNT defaults (TLS provider, user agent, timeouts).
pub fn blocking_client_builder() -> reqwest::blocking::ClientBuilder {
    ensure_tls_provider();
    reqwest::blocking::Client::builder()
        .user_agent(user_agent())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DEFAULT_TIMEOUT)
}

/// Builder for an async client with PMonNT defaults (TLS provider, user agent, timeouts).
pub fn client_builder() -> reqwest::ClientBuilder {
    ensure_tls_provider();
    reqwest::Client::builder()
        .user_agent(user_agent())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DEFAULT_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builders_produce_clients() {
        assert!(blocking_client_builder().build().is_ok());
        assert!(client_builder().build().is_ok());
    }
}
