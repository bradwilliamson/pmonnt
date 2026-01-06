#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ViewMode {
    #[default]
    Grouped,
    Tree,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum RightTab {
    #[default]
    Summary,
    PerformanceGraph,
    Details,
    Security,
    Services,
    Threads,
    Handles,
    Network,
    GPU,
    Version,
    Reputation,
    Scan,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum GroupSort {
    Name,
    VerifiedSigner,
    CPU,
    Memory,
    Disk,
    GPU,
    GPUMemory,
    Handles,
    PID,
    Threads,
}

/// Row in the virtualized process tree
#[derive(Clone)]
pub(crate) struct ProcRow {
    pub(crate) pid: u32,
    pub(crate) depth: usize,
    pub(crate) has_children: bool,
    pub(crate) is_expanded: bool,
    pub(crate) is_match: bool,
    pub(crate) is_selected: bool,
    pub(crate) label: String, // e.g. "explorer.exe (8860)"
}

/// Row in the grouped view (flat - no collapsing like Task Manager)
#[derive(Clone)]
pub(crate) struct GroupedRow {
    pub(crate) name: String,
    pub(crate) count: usize,
    pub(crate) is_match: bool,
    pub(crate) is_selected: bool,       // True if any member is selected
    pub(crate) representative_pid: u32, // "Best" PID to select when clicking group
    pub(crate) total_handles: u32,      // Aggregated handle count
    pub(crate) handles_any_available: bool, // At least one PID had handle data
    pub(crate) handles_all_available: bool, // All PIDs had handle data
    pub(crate) thread_count: usize,     // Aggregated thread count
    pub(crate) cpu_percent: f32,        // Total CPU % across group members (sum)
    pub(crate) memory_bytes: Option<u64>, // Sum of memory bytes across group members (None if unavailable for all members)
    pub(crate) disk_bytes_per_sec: f64,   // Sum of read+write bytes/sec across group members
    pub(crate) gpu_percent: f32,          // Max GPU % across group members (most useful)
    pub(crate) gpu_dedicated_bytes: u64,  // Sum of dedicated GPU memory across group members
    pub(crate) gpu_shared_bytes: u64,     // Sum of shared GPU memory across group members
    pub(crate) gpu_total_bytes: u64,      // Sum of total GPU memory across group members
    pub(crate) member_pids: Vec<u32>,     // All PIDs in this group
    // Process Explorer parity fields (aggregated from representative PID)
    #[allow(dead_code)]
    pub(crate) image_path: Option<String>,
    #[allow(dead_code)]
    pub(crate) command_line: Option<String>,
    #[allow(dead_code)]
    pub(crate) company_name: Option<String>,
    #[allow(dead_code)]
    pub(crate) file_description: Option<String>,
    #[allow(dead_code)]
    pub(crate) integrity_level: Option<String>,
    #[allow(dead_code)]
    pub(crate) user: Option<String>,
    #[allow(dead_code)]
    pub(crate) session_id: Option<u32>,
}
