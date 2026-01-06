//! Module/DLL information and cache for per-process module inspection

use std::collections::HashMap;
use std::time::Instant;

/// Information about a loaded module/DLL
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Module name (e.g., "kernel32.dll")
    pub name: String,
    /// Full path to the module file
    pub path: Option<String>,
    /// Base address where the module is loaded
    pub base_address: u64,
    /// Size of the module in bytes
    pub size: u32,
    /// Signature status: Some(true) = signed, Some(false) = unsigned, None = unknown
    pub signed: Option<bool>,
    /// Error message if inspection failed for this module
    pub error: Option<String>,
}

/// Result of module enumeration for a process
#[derive(Debug, Clone, Default)]
pub struct ModuleListResult {
    /// List of modules (empty if error occurred)
    pub modules: Vec<ModuleInfo>,
    /// Process-level error (e.g., access denied)
    pub error: Option<String>,
}

/// Cache for module information with expiration and LRU capacity
pub struct ModuleCache {
    ttl_secs: u64,
    capacity: usize,
    map: HashMap<u32, (Instant, ModuleListResult)>,
    access_order: Vec<u32>,
}

impl Default for ModuleCache {
    fn default() -> Self {
        Self {
            ttl_secs: 60,
            capacity: 50,
            map: HashMap::new(),
            access_order: Vec::new(),
        }
    }
}

impl ModuleCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            capacity: 50,
            map: HashMap::new(),
            access_order: Vec::new(),
        }
    }

    /// Get cached module list for a PID, returns None if not cached or expired
    pub fn get(&mut self, pid: u32) -> Option<&ModuleListResult> {
        let now = Instant::now();
        if let Some((fetched, _)) = self.map.get(&pid) {
            if now.duration_since(*fetched).as_secs() < self.ttl_secs {
                // Update access order (LRU)
                if let Some(pos) = self.access_order.iter().position(|&x| x == pid) {
                    self.access_order.remove(pos);
                    self.access_order.push(pid);
                }
                return self.map.get(&pid).map(|(_, r)| r);
            }
        }
        None
    }

    /// Insert module list into cache
    pub fn insert(&mut self, pid: u32, result: ModuleListResult) {
        // Remove existing to update position
        if self.map.contains_key(&pid) {
            if let Some(pos) = self.access_order.iter().position(|&x| x == pid) {
                self.access_order.remove(pos);
            }
        } else {
            // Enforce capacity
            if self.map.len() >= self.capacity && !self.access_order.is_empty() {
                let oldest = self.access_order.remove(0);
                self.map.remove(&oldest);
            }
        }

        self.access_order.push(pid);
        self.map.insert(pid, (Instant::now(), result));
    }

    /// Clean up expired entries
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let ttl = self.ttl_secs;
        self.map
            .retain(|_, (fetched, _)| now.duration_since(*fetched).as_secs() < ttl * 2);
        // Sync access order
        self.access_order.retain(|pid| self.map.contains_key(pid));
    }
}

/// Fetch modules for a process with signature checking
pub fn fetch_modules(pid: u32, check_signatures: bool) -> ModuleListResult {
    // Check for protected process first
    let (is_protected, protection_info) = crate::win::get_process_protection(pid);

    // Try to enumerate modules regardless of protection status
    // The PSAPI fallback may succeed even for some sandboxed processes
    match crate::win::module::list_modules(pid) {
        Ok(mut modules) if !modules.is_empty() => {
            if check_signatures {
                for module in &mut modules {
                    if let Some(path) = &module.path {
                        let (signed, err) = crate::win::module::check_signature(path);
                        module.signed = signed;
                        if module.error.is_none() {
                            module.error = err;
                        }
                    }
                }
            }
            ModuleListResult {
                modules,
                error: None,
            }
        }
        Ok(_) | Err(_) if is_protected => {
            // Only show protected process error if we couldn't get modules AND it's protected
            ModuleListResult {
                modules: Vec::new(),
                error: Some(format!(
                    "Protected Process: {} - Module enumeration blocked by Windows",
                    protection_info.unwrap_or_else(|| "PPL".to_string())
                )),
            }
        }
        Ok(_) => {
            // Empty result but not protected - might be a sandboxed or restricted process
            ModuleListResult {
                modules: Vec::new(),
                error: Some("Module enumeration returned empty (sandboxed process?)".to_string()),
            }
        }
        Err(e) => ModuleListResult {
            modules: Vec::new(),
            error: Some(e.to_string()),
        },
    }
}

/// Map a thread start address to the module that contains it
/// Returns (module_name, offset_in_module) if found
pub fn map_address_to_module(
    start_address: Option<u64>,
    modules: &[ModuleInfo],
) -> Option<(String, u64)> {
    let addr = start_address?;

    for module in modules {
        if module.size == 0 {
            continue;
        }

        let base = module.base_address;
        let end = base.saturating_add(module.size as u64);

        // Check if address is within [base, end)
        if addr >= base && addr < end {
            let offset = addr - base;
            return Some((module.name.clone(), offset));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_address_to_module_found() {
        let modules = vec![
            ModuleInfo {
                name: "kernel32.dll".to_string(),
                path: Some("C:\\Windows\\System32\\kernel32.dll".to_string()),
                base_address: 0x1000,
                size: 0x5000,
                signed: Some(true),
                error: None,
            },
            ModuleInfo {
                name: "ntdll.dll".to_string(),
                path: Some("C:\\Windows\\System32\\ntdll.dll".to_string()),
                base_address: 0x10000,
                size: 0x8000,
                signed: Some(true),
                error: None,
            },
        ];

        // Address at the start of kernel32
        assert_eq!(
            map_address_to_module(Some(0x1000), &modules),
            Some(("kernel32.dll".to_string(), 0))
        );

        // Address in the middle of kernel32
        assert_eq!(
            map_address_to_module(Some(0x3000), &modules),
            Some(("kernel32.dll".to_string(), 0x2000))
        );

        // Address at the last byte of kernel32 (base + size - 1)
        assert_eq!(
            map_address_to_module(Some(0x5fff), &modules),
            Some(("kernel32.dll".to_string(), 0x4fff))
        );

        // Address in ntdll
        assert_eq!(
            map_address_to_module(Some(0x10000), &modules),
            Some(("ntdll.dll".to_string(), 0))
        );
    }

    #[test]
    fn test_map_address_to_module_boundary() {
        let modules = vec![ModuleInfo {
            name: "test.dll".to_string(),
            path: None,
            base_address: 0x1000,
            size: 0x1000,
            signed: None,
            error: None,
        }];

        // At base: inside
        assert_eq!(
            map_address_to_module(Some(0x1000), &modules),
            Some(("test.dll".to_string(), 0))
        );

        // At end (base + size): outside
        assert_eq!(map_address_to_module(Some(0x2000), &modules), None);

        // Before base: outside
        assert_eq!(map_address_to_module(Some(0xfff), &modules), None);
    }

    #[test]
    fn test_map_address_to_module_not_found() {
        let modules = vec![ModuleInfo {
            name: "kernel32.dll".to_string(),
            path: None,
            base_address: 0x1000,
            size: 0x5000,
            signed: None,
            error: None,
        }];

        // Address outside any module range
        assert_eq!(map_address_to_module(Some(0x10000), &modules), None);

        // Address before any module
        assert_eq!(map_address_to_module(Some(0x100), &modules), None);
    }

    #[test]
    fn test_map_address_to_module_none() {
        let modules = vec![ModuleInfo {
            name: "test.dll".to_string(),
            path: None,
            base_address: 0x1000,
            size: 0x1000,
            signed: None,
            error: None,
        }];

        // None start_address returns None
        assert_eq!(map_address_to_module(None, &modules), None);
    }

    #[test]
    fn test_map_address_to_module_empty_modules() {
        let modules = vec![];
        assert_eq!(map_address_to_module(Some(0x1000), &modules), None);
    }

    #[test]
    fn test_map_address_to_module_zero_size() {
        let modules = vec![ModuleInfo {
            name: "zero.dll".to_string(),
            path: None,
            base_address: 0x1000,
            size: 0,
            signed: None,
            error: None,
        }];

        // Module with size 0 should be skipped
        assert_eq!(map_address_to_module(Some(0x1000), &modules), None);
    }
}
