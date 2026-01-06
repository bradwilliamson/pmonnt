// Process table column policy (responsive): used by both Grouped and Tree views.
// Keeping this as a helper makes it easy to unit-test and prevents regressions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessColumns {
    Wide,
    Medium,
    Narrow,
    ExtraNarrow,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProcessTablePolicy {
    pub(crate) columns: ProcessColumns,
    pub(crate) show_disk: bool,
    pub(crate) show_verified_signer: bool,
    pub(crate) show_gpu_percent: bool,
    pub(crate) show_gpu_total: bool,
    pub(crate) show_gpu_mem_detail: bool,
    pub(crate) show_handles: bool,
    pub(crate) show_threads: bool,
    pub(crate) name_w: f32,
    pub(crate) verified_signer_w: f32,
    pub(crate) cpu_w: f32,
    pub(crate) mem_w: f32,
    pub(crate) disk_w: f32,
    pub(crate) gpu_pct_w: f32,
    pub(crate) gpu_total_w: f32,
    pub(crate) gpu_mem_w: f32,
    pub(crate) handles_w: f32,
    pub(crate) threads_w: f32,
    pub(crate) pid_w: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum ProcessColumnId {
    Name,
    Leader,
    VerifiedSigner,
    CPU,
    Memory,
    Disk,
    GPU,
    GpuDedicated,
    GpuShared,
    GpuTotal,
    Handles,
    Threads,
    PID,
}

impl ProcessColumnId {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Leader => "leader",
            Self::VerifiedSigner => "verified_signer",
            Self::CPU => "cpu",
            Self::Memory => "memory",
            Self::Disk => "disk",
            Self::GPU => "gpu",
            Self::GpuDedicated => "gpu_dedicated",
            Self::GpuShared => "gpu_shared",
            Self::GpuTotal => "gpu_total",
            Self::Handles => "handles",
            Self::Threads => "threads",
            Self::PID => "pid",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Leader => "Leader",
            Self::VerifiedSigner => "Verified Signer",
            Self::CPU => "CPU",
            Self::Memory => "Memory",
            Self::Disk => "Disk",
            Self::GPU => "GPU",
            Self::GpuDedicated => "GPU Dedicated",
            Self::GpuShared => "GPU Shared",
            Self::GpuTotal => "GPU Total",
            Self::Handles => "Handles",
            Self::Threads => "Threads",
            Self::PID => "PID",
        }
    }

    pub(crate) fn from_key(s: &str) -> Option<Self> {
        match s.trim() {
            "name" => Some(Self::Name),
            // Back-compat for older saved UI layout configs.
            "leader" | "top_hint" => Some(Self::Leader),
            "verified_signer" => Some(Self::VerifiedSigner),
            "cpu" => Some(Self::CPU),
            "memory" => Some(Self::Memory),
            "disk" => Some(Self::Disk),
            "gpu" => Some(Self::GPU),
            "gpu_dedicated" => Some(Self::GpuDedicated),
            "gpu_shared" => Some(Self::GpuShared),
            "gpu_total" => Some(Self::GpuTotal),
            "handles" => Some(Self::Handles),
            "threads" => Some(Self::Threads),
            "pid" => Some(Self::PID),
            _ => None,
        }
    }

    pub(crate) fn default_order() -> Vec<Self> {
        vec![
            Self::Name,
            Self::Leader,
            Self::VerifiedSigner,
            Self::CPU,
            Self::Memory,
            Self::Disk,
            Self::GPU,
            Self::GpuDedicated,
            Self::GpuShared,
            Self::GpuTotal,
            Self::Handles,
            Self::Threads,
            Self::PID,
        ]
    }

    pub(crate) fn default_hidden() -> Vec<Self> {
        // Default hidden: keep the list layout stable on startup.
        // Grouped view can still expose full details via tooltip.
        vec![Self::Leader]
    }

    pub(crate) fn allowed_by_policy(self, policy: &ProcessTablePolicy) -> bool {
        match self {
            Self::Name => true,
            Self::Leader => policy.columns != ProcessColumns::ExtraNarrow,
            Self::VerifiedSigner => policy.show_verified_signer,
            Self::CPU => true,
            Self::Memory => true,
            Self::Disk => policy.show_disk,
            Self::GPU => policy.show_gpu_percent,
            Self::GpuDedicated | Self::GpuShared => policy.show_gpu_mem_detail,
            Self::GpuTotal => policy.show_gpu_total,
            Self::Handles => policy.show_handles,
            Self::Threads => policy.show_threads,
            Self::PID => true,
        }
    }

    pub(crate) fn width(self, policy: &ProcessTablePolicy) -> f32 {
        match self {
            Self::Name => policy.name_w,
            Self::Leader => 160.0,
            Self::VerifiedSigner => policy.verified_signer_w,
            Self::CPU => policy.cpu_w,
            Self::Memory => policy.mem_w,
            Self::Disk => policy.disk_w,
            Self::GPU => policy.gpu_pct_w,
            Self::GpuDedicated | Self::GpuShared => policy.gpu_mem_w,
            Self::GpuTotal => policy.gpu_total_w,
            Self::Handles => policy.handles_w,
            Self::Threads => policy.threads_w,
            Self::PID => policy.pid_w,
        }
    }
}

pub(crate) fn process_table_policy(process_panel_width: f32) -> ProcessTablePolicy {
    // Breakpoints are tuned for a left panel in split view.
    let columns = if process_panel_width < 520.0 {
        ProcessColumns::ExtraNarrow
    } else if process_panel_width < 760.0 {
        ProcessColumns::Narrow
    } else if process_panel_width < 1050.0 {
        ProcessColumns::Medium
    } else {
        ProcessColumns::Wide
    };

    // GPU visibility policy:
    // - ExtraNarrow: hide GPU entirely.
    // - Narrow: show GPU% only (keeps list useful without horizontal squeeze).
    // - Medium: show GPU% + GPU Total.
    // - Medium/Wide: show GPU% + Dedicated/Shared/Total.
    // Disk policy:
    // - ExtraNarrow: hide Disk.
    // - Narrow+: show Disk.
    let show_disk = columns != ProcessColumns::ExtraNarrow;
    // Verified Signer policy:
    // - Medium/Wide: show (text column; useful in wide layouts).
    // - Narrow/ExtraNarrow: hide to avoid horizontal squeeze.
    let show_verified_signer = matches!(columns, ProcessColumns::Medium | ProcessColumns::Wide);
    let show_gpu_percent = columns != ProcessColumns::ExtraNarrow;
    let show_gpu_total = matches!(columns, ProcessColumns::Medium | ProcessColumns::Wide);
    let show_gpu_mem_detail = matches!(columns, ProcessColumns::Medium | ProcessColumns::Wide);
    let show_handles = matches!(columns, ProcessColumns::Wide | ProcessColumns::Medium);
    let show_threads = columns != ProcessColumns::ExtraNarrow;

    let (
        name_w,
        mut verified_signer_w,
        cpu_w,
        mem_w,
        mut disk_w,
        mut gpu_pct_w,
        mut gpu_total_w,
        mut gpu_mem_w,
        handles_w,
        threads_w,
        pid_w,
    ) = match columns {
        ProcessColumns::Wide => (
            220.0, 170.0, 70.0, 85.0, 92.0, 62.0, 92.0, 95.0, 90.0, 100.0, 70.0,
        ),
        ProcessColumns::Medium => (
            200.0, 155.0, 65.0, 80.0, 90.0, 60.0, 90.0, 90.0, 80.0, 85.0, 65.0,
        ),
        ProcessColumns::Narrow => (
            170.0, 0.0, 58.0, 75.0, 85.0, 56.0, 0.0, 0.0, 0.0, 72.0, 60.0,
        ),
        ProcessColumns::ExtraNarrow => (160.0, 0.0, 56.0, 72.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 58.0),
    };

    if !show_disk {
        disk_w = 0.0;
    }
    if !show_verified_signer {
        verified_signer_w = 0.0;
    }
    if !show_gpu_percent {
        gpu_pct_w = 0.0;
    }
    if !show_gpu_total {
        gpu_total_w = 0.0;
    }
    if !show_gpu_mem_detail {
        gpu_mem_w = 0.0;
    }

    ProcessTablePolicy {
        columns,
        show_disk,
        show_verified_signer,
        show_gpu_percent,
        show_gpu_total,
        show_gpu_mem_detail,
        show_handles,
        show_threads,
        name_w,
        verified_signer_w,
        cpu_w,
        mem_w,
        disk_w,
        gpu_pct_w,
        gpu_total_w,
        gpu_mem_w,
        handles_w,
        threads_w,
        pid_w,
    }
}
