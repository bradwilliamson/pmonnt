//! Raw handle table entries (platform-independent).

/// Raw handle entry from system enumeration
#[derive(Debug, Clone)]
pub struct HandleEntry {
    pub pid: u32,
    pub handle_value: usize,
    pub object_type_index: u16,
    pub granted_access: u32,
}

/// Map common Windows handle type indices to human-readable names
/// These indices are consistent on Windows 10 21H2+ and Windows 11
pub fn get_type_name(type_index: u16) -> String {
    match type_index {
        5 => "Token".to_string(),
        7 => "Process".to_string(),
        8 => "Thread".to_string(),
        12 => "Job".to_string(),
        15 => "Event".to_string(),
        17 => "Mutant".to_string(),
        19 => "Semaphore".to_string(),
        30 => "File".to_string(),
        37 => "Key".to_string(),
        40 => "Section".to_string(),
        42 => "IoCompletion".to_string(),
        _ => format!("TypeIndex{type_index}"),
    }
}
