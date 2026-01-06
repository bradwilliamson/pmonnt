use std::sync::atomic::{AtomicU64, Ordering};

/// Rate-limiter for warnings: tracks last warning time in epoch millis
static LAST_WARN_TIME: AtomicU64 = AtomicU64::new(0);

/// Returns true if enough time has passed since last warning (30 seconds)
pub fn should_warn() -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let last = LAST_WARN_TIME.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= 30_000 {
        LAST_WARN_TIME.store(now, Ordering::Relaxed);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_warn_first_call() {
        // Reset the global state for this test
        LAST_WARN_TIME.store(0, Ordering::Relaxed);
        assert!(should_warn()); // First call should always warn
    }

    #[test]
    fn test_should_warn_rate_limits() {
        // Set last warn time to now
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        LAST_WARN_TIME.store(now, Ordering::Relaxed);

        // Immediate second call should be suppressed
        assert!(!should_warn());
    }
}
