// credentials.rs - Centralized API key management via Windows Credential Manager
//
// Add this as a new file: pmonnt-ui/src/credentials.rs
// Then add `mod credentials;` to main.rs

use log::{error, info, warn};

/// Windows Credential Manager service name
const KEYRING_SERVICE: &str = "PMonNT";

/// Credential entry names
const VT_KEY_NAME: &str = "VirusTotalApiKey";
const MB_KEY_NAME: &str = "MalwareBazaarApiKey";
const TF_KEY_NAME: &str = "ThreatFoxApiKey";

/// Result type for credential operations
pub type CredResult<T> = Result<T, String>;

/// All API keys loaded from credential store
#[derive(Default, Clone)]
pub struct ApiKeys {
    pub vt: Option<String>,
    pub mb: Option<String>,
    pub tf: Option<String>,
}

trait CredentialStore {
    fn load(&self, name: &str) -> CredResult<String>;
}

struct WindowsCredentialStore;

impl CredentialStore for WindowsCredentialStore {
    fn load(&self, name: &str) -> CredResult<String> {
        load_credential(name)
    }
}

impl ApiKeys {
    /// Load all API keys from Windows Credential Manager (with env var overrides)
    pub fn load() -> Self {
        let store = WindowsCredentialStore;
        Self::load_with_store(&store)
    }

    fn load_with_store(store: &dyn CredentialStore) -> Self {
        // VT: Check env var first, then credential store
        let vt_from_env = std::env::var("PMONNT_VT_API_KEY")
            .or_else(|_| std::env::var("VT_API_KEY"))
            .ok();
        let vt_from_store = if vt_from_env.is_some() {
            None
        } else {
            store.load(VT_KEY_NAME).ok()
        };
        let vt = vt_from_env.clone().or(vt_from_store);

        if vt.is_some() {
            if vt_from_env.is_some() {
                info!("VT API key loaded from environment variable");
            } else {
                info!("VT API key loaded from Windows Credential Manager");
            }
        } else {
            info!("No VT API key configured");
        }

        // MB: Check env var first, then credential store
        let mb_from_env = std::env::var("PMONNT_MB_API_KEY")
            .or_else(|_| std::env::var("PMONNT_MALWAREBAZAAR_KEY"))
            .ok();
        let mb_from_store = if mb_from_env.is_some() {
            None
        } else {
            store.load(MB_KEY_NAME).ok()
        };
        let mb = mb_from_env.clone().or(mb_from_store);

        if mb.is_some() {
            if mb_from_env.is_some() {
                info!("MB API key loaded from environment variable");
            } else {
                info!("MB API key loaded from Windows Credential Manager");
            }
        } else {
            info!("No MB API key configured");
        }

        // TF: Check env var first, then credential store, then fall back to MB key
        let tf_from_env = std::env::var("PMONNT_THREATFOX_KEY").ok();
        let tf_from_store = if tf_from_env.is_some() {
            None
        } else {
            store.load(TF_KEY_NAME).ok()
        };
        let tf_from_store_present = tf_from_store.is_some();
        let tf = tf_from_env.clone().or(tf_from_store).or_else(|| mb.clone());

        if tf.is_some() {
            if tf_from_env.is_some() {
                info!("TF API key loaded from environment variable");
            } else if tf_from_store_present {
                info!("TF API key loaded from Windows Credential Manager");
            } else {
                info!("TF API key using MB key (same abuse.ch account)");
            }
        } else {
            info!("No TF API key configured");
        }

        ApiKeys { vt, mb, tf }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    struct MockStore {
        values: HashMap<String, String>,
    }

    impl CredentialStore for MockStore {
        fn load(&self, name: &str) -> CredResult<String> {
            self.values
                .get(name)
                .cloned()
                .ok_or_else(|| "No entry found".to_string())
        }
    }

    fn clear_env() {
        for k in [
            "PMONNT_VT_API_KEY",
            "VT_API_KEY",
            "PMONNT_MB_API_KEY",
            "PMONNT_MALWAREBAZAAR_KEY",
            "PMONNT_THREATFOX_KEY",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn env_overrides_store_for_vt() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("PMONNT_VT_API_KEY", "vt_env");

        let store = MockStore {
            values: HashMap::from([(VT_KEY_NAME.to_string(), "vt_store".to_string())]),
        };

        let keys = ApiKeys::load_with_store(&store);
        assert_eq!(keys.vt.as_deref(), Some("vt_env"));
        assert!(keys.mb.is_none());
        assert!(keys.tf.is_none());
    }

    #[test]
    fn tf_falls_back_to_mb_when_tf_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("PMONNT_MB_API_KEY", "mb_env");

        let store = MockStore {
            values: HashMap::new(),
        };
        let keys = ApiKeys::load_with_store(&store);

        assert_eq!(keys.mb.as_deref(), Some("mb_env"));
        assert_eq!(keys.tf.as_deref(), Some("mb_env"));
    }

    #[test]
    fn tf_store_wins_over_mb_fallback() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("PMONNT_MB_API_KEY", "mb_env");

        let store = MockStore {
            values: HashMap::from([(TF_KEY_NAME.to_string(), "tf_store".to_string())]),
        };

        let keys = ApiKeys::load_with_store(&store);
        assert_eq!(keys.mb.as_deref(), Some("mb_env"));
        assert_eq!(keys.tf.as_deref(), Some("tf_store"));
    }
}

/// Load a single credential from Windows Credential Manager
fn load_credential(name: &str) -> CredResult<String> {
    match keyring::Entry::new(KEYRING_SERVICE, name) {
        Ok(entry) => match entry.get_password() {
            Ok(password) => Ok(password),
            Err(keyring::Error::NoEntry) => Err("No entry found".to_string()),
            Err(e) => {
                warn!("Failed to load credential '{}': {}", name, e);
                Err(format!("Keyring error: {}", e))
            }
        },
        Err(e) => {
            warn!("Failed to access keyring for '{}': {}", name, e);
            Err(format!("Keyring access error: {}", e))
        }
    }
}

/// Save a credential to Windows Credential Manager
pub fn save_credential(name: &str, value: &str) -> CredResult<()> {
    match keyring::Entry::new(KEYRING_SERVICE, name) {
        Ok(entry) => match entry.set_password(value) {
            Ok(_) => {
                info!("Saved credential '{}' to Windows Credential Manager", name);
                Ok(())
            }
            Err(e) => {
                error!("Failed to save credential '{}': {}", name, e);
                Err(format!("Failed to save: {}", e))
            }
        },
        Err(e) => {
            error!("Failed to create keyring entry for '{}': {}", name, e);
            Err(format!("Keyring error: {}", e))
        }
    }
}

/// Delete a credential from Windows Credential Manager
pub fn delete_credential(name: &str) -> CredResult<()> {
    match keyring::Entry::new(KEYRING_SERVICE, name) {
        Ok(entry) => {
            match entry.delete_credential() {
                Ok(_) => {
                    info!(
                        "Deleted credential '{}' from Windows Credential Manager",
                        name
                    );
                    Ok(())
                }
                Err(keyring::Error::NoEntry) => {
                    // Not an error - credential didn't exist
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to delete credential '{}': {}", name, e);
                    Err(format!("Failed to delete: {}", e))
                }
            }
        }
        Err(e) => {
            error!("Failed to access keyring for '{}': {}", name, e);
            Err(format!("Keyring error: {}", e))
        }
    }
}

// Public API for each key type

pub fn save_vt_key(key: &str) -> CredResult<()> {
    save_credential(VT_KEY_NAME, key)
}

pub fn delete_vt_key() -> CredResult<()> {
    delete_credential(VT_KEY_NAME)
}

pub fn save_mb_key(key: &str) -> CredResult<()> {
    save_credential(MB_KEY_NAME, key)
}

#[allow(dead_code)]
pub fn delete_mb_key() -> CredResult<()> {
    delete_credential(MB_KEY_NAME)
}

#[allow(dead_code)]
pub fn save_tf_key(key: &str) -> CredResult<()> {
    save_credential(TF_KEY_NAME, key)
}

#[allow(dead_code)]
pub fn delete_tf_key() -> CredResult<()> {
    delete_credential(TF_KEY_NAME)
}

/// Check if env var override is active for a key type
#[allow(dead_code)]
pub fn is_env_override_active(key_type: KeyType) -> bool {
    match key_type {
        KeyType::VirusTotal => {
            std::env::var("PMONNT_VT_API_KEY").is_ok() || std::env::var("VT_API_KEY").is_ok()
        }
        KeyType::MalwareBazaar => {
            std::env::var("PMONNT_MB_API_KEY").is_ok()
                || std::env::var("PMONNT_MALWAREBAZAAR_KEY").is_ok()
        }
        KeyType::ThreatFox => std::env::var("PMONNT_THREATFOX_KEY").is_ok(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum KeyType {
    VirusTotal,
    MalwareBazaar,
    ThreatFox,
}
