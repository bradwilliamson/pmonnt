use std::collections::HashMap;

#[cfg(windows)]
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

#[cfg(windows)]
pub(crate) fn try_get_main_hwnd(frame: &eframe::Frame) -> Option<isize> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let handle = frame.window_handle().ok()?;
    match handle.as_raw() {
        RawWindowHandle::Win32(h) => Some(h.hwnd.get() as isize),
        _ => None,
    }
}

#[cfg(not(windows))]
pub(crate) fn try_get_main_hwnd(_frame: &eframe::Frame) -> Option<isize> {
    None
}

// Format numbers with thousands separators (e.g., 15420 -> 15,420)
pub(crate) fn format_number_u64(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    let mut count = 0;
    for ch in s.chars().rev() {
        out.push(ch);
        count += 1;
        if count % 3 == 0 && count < s.len() {
            out.push(',');
        }
    }
    out.chars().rev().collect()
}

pub(crate) fn format_number_u32(n: u32) -> String {
    format_number_u64(n as u64)
}

pub(crate) fn format_number_usize(n: usize) -> String {
    format_number_u64(n as u64)
}

/// Format memory bytes as smart units (KB, MB, GB)
/// < 1 MB: "1,234 KB" (0 decimals)
/// 1-1000 MB: "123.4 MB" (1 decimal)
/// >= 1 GB: "1.2 GB" (1 decimal)
pub(crate) fn format_memory_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes == 0 {
        return "0 B".to_string();
    }

    if bytes < MB {
        let kb = bytes / KB;
        format!("{} KB", format_number_u64(kb))
    } else if bytes < GB {
        let mb = bytes as f64 / MB as f64;
        format!("{:.1} MB", mb)
    } else {
        let gb = bytes as f64 / GB as f64;
        format!("{:.1} GB", gb)
    }
}

pub(crate) fn format_bytes_per_sec(bytes_per_sec: f64) -> String {
    let mut v = bytes_per_sec.max(0.0);
    let units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
    let mut u = 0usize;
    while v >= 1024.0 && u + 1 < units.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{:.0} {}", v, units[u])
    } else {
        format!("{:.1} {}", v, units[u])
    }
}

pub(crate) fn clamp_percent(p: f32) -> f32 {
    p.clamp(0.0, 100.0)
}

pub(crate) fn sum_cpu_percent(cpu_memory_data: &HashMap<u32, (f32, Option<u64>)>) -> f32 {
    let sum: f32 = cpu_memory_data.values().map(|(cpu, _mem)| *cpu).sum();
    clamp_percent(sum)
}

pub(crate) fn sum_gpu_percent(gpu_data: &HashMap<u32, (f32, u64, u64, u64)>) -> f32 {
    let sum: f32 = gpu_data.values().map(|(gpu, _d, _s, _t)| *gpu).sum();
    clamp_percent(sum)
}

pub(crate) fn sum_gpu_mem_bytes(gpu_data: &HashMap<u32, (f32, u64, u64, u64)>) -> (u64, u64, u64) {
    let mut dedicated: u64 = 0;
    let mut shared: u64 = 0;
    let mut total: u64 = 0;
    for (_, d, s, t) in gpu_data.values() {
        dedicated = dedicated.saturating_add(*d);
        shared = shared.saturating_add(*s);
        total = total.saturating_add(*t);
    }
    (dedicated, shared, total)
}

pub(crate) fn percent_used(used: u64, total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    clamp_percent((used as f64 / total as f64 * 100.0) as f32)
}

#[cfg(windows)]
pub(crate) fn query_physical_memory_used_total() -> Option<(u64, u64)> {
    let mut ms = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    let ok = unsafe { GlobalMemoryStatusEx(&mut ms) }.is_ok();
    if !ok {
        return None;
    }

    let total = ms.ullTotalPhys;
    let avail = ms.ullAvailPhys;
    Some((total.saturating_sub(avail), total))
}

#[cfg(windows)]
pub(crate) fn query_gpu_memory_capacity_bytes() -> Option<(u64, u64)> {
    use windows::core::Interface;
    use windows::Win32::Graphics::Dxgi::{
        CreateDXGIFactory1, IDXGIAdapter3, IDXGIFactory1, DXGI_ADAPTER_DESC1,
        DXGI_ADAPTER_FLAG_SOFTWARE, DXGI_MEMORY_SEGMENT_GROUP_LOCAL,
        DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL, DXGI_QUERY_VIDEO_MEMORY_INFO,
    };

    let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1().ok()? };

    let mut dedicated: u64 = 0;
    let mut shared: u64 = 0;

    // Enumerate adapters and prefer WDDM "budget" (Task Manager-like) when available.
    // If budgets aren't available, fall back to adapter-reported capacities.
    for adapter_index in 0u32.. {
        let adapter = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Ok(a) => a,
            Err(_) => break,
        };

        let desc: DXGI_ADAPTER_DESC1 = unsafe { adapter.GetDesc1().ok()? };

        // Skip software adapters (WARP).
        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32) != 0 {
            continue;
        }

        // QueryVideoMemoryInfo gives a WDDM-managed "Budget" which is what Task Manager tends to
        // present as the usable total (can be < physical VRAM under system pressure).
        if let Ok(adapter3) = adapter.cast::<IDXGIAdapter3>() {
            // Most systems expose node 0; if this fails, we fall back to descriptor.
            let mut info_local = DXGI_QUERY_VIDEO_MEMORY_INFO::default();
            if unsafe {
                adapter3.QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &mut info_local)
            }
            .is_ok()
            {
                dedicated = dedicated.saturating_add(info_local.Budget);
            } else {
                dedicated = dedicated.saturating_add(desc.DedicatedVideoMemory as u64);
            }

            let mut info_nonlocal = DXGI_QUERY_VIDEO_MEMORY_INFO::default();
            if unsafe {
                adapter3.QueryVideoMemoryInfo(
                    0,
                    DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL,
                    &mut info_nonlocal,
                )
            }
            .is_ok()
            {
                shared = shared.saturating_add(info_nonlocal.Budget);
            } else {
                shared = shared.saturating_add(desc.SharedSystemMemory as u64);
            }
        } else {
            dedicated = dedicated.saturating_add(desc.DedicatedVideoMemory as u64);
            shared = shared.saturating_add(desc.SharedSystemMemory as u64);
        }
    }

    if dedicated == 0 && shared == 0 {
        None
    } else {
        Some((dedicated, shared))
    }
}

#[cfg(not(windows))]
pub(crate) fn query_gpu_memory_capacity_bytes() -> Option<(u64, u64)> {
    None
}

#[cfg(not(windows))]
pub(crate) fn query_physical_memory_used_total() -> Option<(u64, u64)> {
    None
}

/// Paint an inline usage bar for a cell (e.g., CPU%, Memory)
/// The bar is rendered behind the text with semi-transparency
/// to show magnitude without obscuring readability.
/// 
/// GUARDRAIL: This is called within a cell's ui context, so the bar respects
/// the cell's clip rect and will not bleed into adjacent cells or text.
pub(crate) fn paint_inline_usage_bar(ui: &egui::Ui, percentage: f32) {
    if percentage <= 0.0 {
        return;
    }
    
    let response = ui.interact(
        ui.available_rect_before_wrap(),
        egui::Id::new(ui.next_auto_id()),
        egui::Sense::hover(),
    );
    
    // Get the bar color based on percentage (theme-aware via visuals)
    let color = if percentage > 90.0 {
        // High usage: red tint
        egui::Color32::from_rgba_unmultiplied(255, 100, 100, 40)
    } else if percentage > 70.0 {
        // Medium-high usage: yellow tint
        egui::Color32::from_rgba_unmultiplied(255, 200, 0, 40)
    } else {
        // Low-medium usage: green tint
        egui::Color32::from_rgba_unmultiplied(100, 200, 100, 40)
    };
    
    // Paint bar from left to right, proportional to percentage
    let bar_rect = response.rect;
    let bar_width = (bar_rect.width() * (percentage / 100.0)).min(bar_rect.width());
    let bar_rect = egui::Rect {
        min: bar_rect.min,
        max: egui::Pos2::new(bar_rect.min.x + bar_width, bar_rect.max.y),
    };
    
    ui.painter().rect_filled(bar_rect, 0.0, color);
}

/// Truncate a path using middle-ellipsis format
/// E.g., "/very/long/path/to/file.exe" with max 30 chars becomes "/very/.../file.exe"
pub(crate) fn truncate_path_middle(path: &str, max_width: usize) -> String {
    if path.len() <= max_width {
        return path.to_string();
    }
    
    const ELLIPSIS: &str = "...";
    let available = max_width.saturating_sub(ELLIPSIS.len());
    if available < 4 {
        return format!("{}...", &path[..path.len().min(max_width)])
    }
    
    let start_len = available / 2;
    let end_len = available - start_len;
    
    format!(
        "{}{}{}",
        &path[..start_len],
        ELLIPSIS,
        &path[path.len() - end_len..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // format_number_* tests
    // ========================================================================

    #[test]
    fn test_format_number_u64_zero() {
        assert_eq!(format_number_u64(0), "0");
    }

    #[test]
    fn test_format_number_u64_no_separator() {
        assert_eq!(format_number_u64(1), "1");
        assert_eq!(format_number_u64(12), "12");
        assert_eq!(format_number_u64(123), "123");
    }

    #[test]
    fn test_format_number_u64_with_separator() {
        assert_eq!(format_number_u64(1_234), "1,234");
        assert_eq!(format_number_u64(12_345), "12,345");
        assert_eq!(format_number_u64(123_456), "123,456");
        assert_eq!(format_number_u64(1_234_567), "1,234,567");
    }

    #[test]
    fn test_format_number_u64_exactly_thousand() {
        assert_eq!(format_number_u64(1_000), "1,000");
        assert_eq!(format_number_u64(1_000_000), "1,000,000");
    }

    #[test]
    fn test_format_number_u64_large() {
        assert_eq!(format_number_u64(999_999_999), "999,999,999");
        assert_eq!(format_number_u64(1_234_567_890), "1,234,567,890");
    }

    #[test]
    fn test_format_number_u32_delegates() {
        assert_eq!(format_number_u32(1234), "1,234");
        assert_eq!(format_number_u32(u32::MAX), format_number_u64(u32::MAX as u64));
    }

    #[test]
    fn test_format_number_usize_delegates() {
        assert_eq!(format_number_usize(1234), "1,234");
    }

    // ========================================================================
    // format_memory_bytes tests
    // ========================================================================

    #[test]
    fn test_format_memory_bytes_zero() {
        assert_eq!(format_memory_bytes(0), "0 B");
    }

    #[test]
    fn test_format_memory_bytes_less_than_kb() {
        // Less than 1 KB still shows as KB (rounds down to 0 KB)
        assert_eq!(format_memory_bytes(512), "0 KB");
        assert_eq!(format_memory_bytes(1023), "0 KB");
    }

    #[test]
    fn test_format_memory_bytes_kb() {
        assert_eq!(format_memory_bytes(1024), "1 KB");
        assert_eq!(format_memory_bytes(1024 * 2), "2 KB");
        assert_eq!(format_memory_bytes(1024 * 500), "500 KB");
    }

    #[test]
    fn test_format_memory_bytes_mb() {
        assert_eq!(format_memory_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_memory_bytes(1024 * 1024 * 2), "2.0 MB");
        
        // 1.5 MB
        assert_eq!(format_memory_bytes(1024 * 1024 + 512 * 1024), "1.5 MB");
        
        // 123.4 MB
        let mb_123_4 = (1024.0 * 1024.0 * 123.4) as u64;
        assert!(format_memory_bytes(mb_123_4).starts_with("123."));
    }

    #[test]
    fn test_format_memory_bytes_gb() {
        assert_eq!(format_memory_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_memory_bytes(1024 * 1024 * 1024 * 2), "2.0 GB");
        
        // 16.5 GB
        let gb_16_5 = (1024.0 * 1024.0 * 1024.0 * 16.5) as u64;
        assert!(format_memory_bytes(gb_16_5).starts_with("16."));
    }

    #[test]
    fn test_format_memory_bytes_boundary_mb_to_gb() {
        // Just under 1 GB
        let almost_gb = 1024 * 1024 * 1024 - 1;
        assert!(format_memory_bytes(almost_gb).contains("MB"));
        
        // Exactly 1 GB
        assert!(format_memory_bytes(1024 * 1024 * 1024).contains("GB"));
    }

    // ========================================================================
    // format_bytes_per_sec tests
    // ========================================================================

    #[test]
    fn test_format_bytes_per_sec_zero() {
        assert_eq!(format_bytes_per_sec(0.0), "0 B/s");
    }

    #[test]
    fn test_format_bytes_per_sec_negative_clamped() {
        // Negative values are clamped to 0
        assert_eq!(format_bytes_per_sec(-100.0), "0 B/s");
    }

    #[test]
    fn test_format_bytes_per_sec_bytes() {
        assert_eq!(format_bytes_per_sec(123.0), "123 B/s");
        assert_eq!(format_bytes_per_sec(999.0), "999 B/s");
    }

    #[test]
    fn test_format_bytes_per_sec_kb() {
        assert_eq!(format_bytes_per_sec(1024.0), "1.0 KB/s");
        assert_eq!(format_bytes_per_sec(1024.0 * 2.5), "2.5 KB/s");
    }

    #[test]
    fn test_format_bytes_per_sec_mb() {
        assert_eq!(format_bytes_per_sec(1024.0 * 1024.0), "1.0 MB/s");
        assert_eq!(format_bytes_per_sec(1024.0 * 1024.0 * 10.7), "10.7 MB/s");
    }

    #[test]
    fn test_format_bytes_per_sec_gb() {
        assert_eq!(format_bytes_per_sec(1024.0 * 1024.0 * 1024.0), "1.0 GB/s");
    }

    #[test]
    fn test_format_bytes_per_sec_tb() {
        let tb = 1024.0 * 1024.0 * 1024.0 * 1024.0;
        assert!(format_bytes_per_sec(tb).contains("TB/s"));
    }

    #[test]
    fn test_format_bytes_per_sec_exactly_1024() {
        // Exactly 1024 B/s should format as 1.0 KB/s
        assert_eq!(format_bytes_per_sec(1024.0), "1.0 KB/s");
    }

    // ========================================================================
    // clamp_percent tests
    // ========================================================================

    #[test]
    fn test_clamp_percent_in_range() {
        assert_eq!(clamp_percent(0.0), 0.0);
        assert_eq!(clamp_percent(50.0), 50.0);
        assert_eq!(clamp_percent(100.0), 100.0);
    }

    #[test]
    fn test_clamp_percent_below_zero() {
        assert_eq!(clamp_percent(-10.0), 0.0);
        assert_eq!(clamp_percent(-0.1), 0.0);
    }

    #[test]
    fn test_clamp_percent_above_100() {
        assert_eq!(clamp_percent(101.0), 100.0);
        assert_eq!(clamp_percent(200.0), 100.0);
        assert_eq!(clamp_percent(1000.0), 100.0);
    }

    #[test]
    fn test_clamp_percent_fractional() {
        assert_eq!(clamp_percent(99.9), 99.9);
        assert_eq!(clamp_percent(0.1), 0.1);
    }

    // ========================================================================
    // percent_used tests
    // ========================================================================

    #[test]
    fn test_percent_used_zero_total() {
        assert_eq!(percent_used(100, 0), 0.0);
    }

    #[test]
    fn test_percent_used_zero_used() {
        assert_eq!(percent_used(0, 1000), 0.0);
    }

    #[test]
    fn test_percent_used_half() {
        assert_eq!(percent_used(50, 100), 50.0);
    }

    #[test]
    fn test_percent_used_full() {
        assert_eq!(percent_used(100, 100), 100.0);
    }

    #[test]
    fn test_percent_used_overflow_clamped() {
        // Used > total (shouldn't happen, but handles gracefully)
        assert_eq!(percent_used(150, 100), 100.0);
    }

    // ========================================================================
    // truncate_path_middle tests
    // ========================================================================

    #[test]
    fn test_truncate_path_middle_short() {
        let path = "short.exe";
        assert_eq!(truncate_path_middle(path, 20), "short.exe");
    }

    #[test]
    fn test_truncate_path_middle_exactly_max() {
        let path = "12345678901234567890"; // 20 chars
        assert_eq!(truncate_path_middle(path, 20), path);
    }

    #[test]
    fn test_truncate_path_middle_truncated() {
        let path = "c:\\windows\\system32\\notepad.exe";
        let result = truncate_path_middle(path, 20);
        
        assert!(result.len() <= 20);
        assert!(result.contains("..."));
        assert!(result.starts_with("c:\\wi"));
        assert!(result.ends_with(".exe"));
    }

    #[test]
    fn test_truncate_path_middle_very_long() {
        let path = "c:\\very\\long\\path\\that\\goes\\on\\and\\on\\forever\\file.txt";
        let result = truncate_path_middle(path, 30);
        
        assert!(result.len() <= 30);
        assert!(result.contains("..."));
    }

    #[test]
    fn test_truncate_path_middle_tiny_max() {
        let path = "long_filename.exe";
        let result = truncate_path_middle(path, 5);
        
        // Should still produce something reasonable
        assert!(result.len() <= 8); // "lo..." is 5, but might be slightly longer
        assert!(result.contains("..."));
    }

    #[test]
    fn test_truncate_path_middle_preserves_start_and_end() {
        let path = "/usr/local/bin/my_application";
        let result = truncate_path_middle(path, 20);
        
        assert!(result.starts_with("/usr"));
        assert!(result.ends_with("ation"));
        assert!(result.contains("..."));
    }

    // ========================================================================
    // sum_cpu_percent tests
    // ========================================================================

    #[test]
    fn test_sum_cpu_percent_empty() {
        let data = HashMap::new();
        assert_eq!(sum_cpu_percent(&data), 0.0);
    }

    #[test]
    fn test_sum_cpu_percent_single() {
        let mut data = HashMap::new();
        data.insert(1000, (25.5, Some(1024)));
        assert_eq!(sum_cpu_percent(&data), 25.5);
    }

    #[test]
    fn test_sum_cpu_percent_multiple() {
        let mut data = HashMap::new();
        data.insert(1000, (25.0, Some(1024)));
        data.insert(2000, (30.0, None));
        data.insert(3000, (15.0, Some(2048)));
        
        assert_eq!(sum_cpu_percent(&data), 70.0);
    }

    #[test]
    fn test_sum_cpu_percent_over_100_clamped() {
        let mut data = HashMap::new();
        data.insert(1000, (60.0, Some(1024)));
        data.insert(2000, (50.0, None));
        
        // Sum is 110, should clamp to 100
        assert_eq!(sum_cpu_percent(&data), 100.0);
    }

    // ========================================================================
    // sum_gpu_percent tests
    // ========================================================================

    #[test]
    fn test_sum_gpu_percent_empty() {
        let data = HashMap::new();
        assert_eq!(sum_gpu_percent(&data), 0.0);
    }

    #[test]
    fn test_sum_gpu_percent_single() {
        let mut data = HashMap::new();
        data.insert(1000, (45.5, 1024, 512, 1536));
        assert_eq!(sum_gpu_percent(&data), 45.5);
    }

    #[test]
    fn test_sum_gpu_percent_over_100_clamped() {
        let mut data = HashMap::new();
        data.insert(1000, (70.0, 1024, 512, 1536));
        data.insert(2000, (50.0, 2048, 1024, 3072));
        
        assert_eq!(sum_gpu_percent(&data), 100.0);
    }

    // ========================================================================
    // sum_gpu_mem_bytes tests
    // ========================================================================

    #[test]
    fn test_sum_gpu_mem_bytes_empty() {
        let data = HashMap::new();
        assert_eq!(sum_gpu_mem_bytes(&data), (0, 0, 0));
    }

    #[test]
    fn test_sum_gpu_mem_bytes_single() {
        let mut data = HashMap::new();
        data.insert(1000, (45.0, 1024, 512, 1536));
        
        assert_eq!(sum_gpu_mem_bytes(&data), (1024, 512, 1536));
    }

    #[test]
    fn test_sum_gpu_mem_bytes_multiple() {
        let mut data = HashMap::new();
        data.insert(1000, (45.0, 1024, 512, 1536));
        data.insert(2000, (30.0, 2048, 1024, 3072));
        
        assert_eq!(sum_gpu_mem_bytes(&data), (3072, 1536, 4608));
    }

    #[test]
    fn test_sum_gpu_mem_bytes_overflow_safe() {
        let mut data = HashMap::new();
        // Test saturation on overflow
        data.insert(1000, (0.0, u64::MAX, u64::MAX, u64::MAX));
        data.insert(2000, (0.0, 1, 1, 1));
        
        let (d, s, t) = sum_gpu_mem_bytes(&data);
        assert_eq!(d, u64::MAX); // Should saturate, not wrap
        assert_eq!(s, u64::MAX);
        assert_eq!(t, u64::MAX);
    }
}
