//! Sort keys for the process list, computed once per PID instead of inside comparators.
//!
//! The comparators used to look every value up in hash maps (and lowercase both names) on
//! each of the O(n log n) comparisons. Here each PID's key is extracted once and the sort
//! compares plain values. Float keys go through [`num`] so the order is total: NaN counts
//! as "no data" and -0.0 as 0.0 (a comparator that is not a total order can make
//! `sort_by` panic since Rust 1.81).

use std::cmp::Ordering;
use std::collections::HashMap;

use crate::handles::HandleSummary;
use crate::snapshot::ProcessSnapshot;
use crate::{SignatureInfo, SignatureStatus};

use super::{GroupSort, RowMetrics};

/// Normalize a metric for ordering: NaN becomes "no data", -0.0 becomes 0.0.
pub(crate) fn num(v: f64) -> Option<f64> {
    if v.is_nan() { None } else { Some(v + 0.0) }
}

/// Fresh handle summaries, read once per frame (see `HandleCache::fresh_summaries`).
pub(crate) type Handles<'a> = Option<&'a HashMap<u32, HandleSummary>>;

/// The single per-PID metric a numeric sort mode orders by.
pub(crate) fn metric_value(
    pid: u32,
    sort: GroupSort,
    metrics: &RowMetrics<'_>,
    handles: Handles<'_>,
) -> Option<f64> {
    match sort {
        GroupSort::Handles => handles
            .and_then(|m| m.get(&pid))
            .map(|s| f64::from(s.total)),
        GroupSort::Threads => metrics.global_thread_counts.get(&pid).map(|&c| c as f64),
        GroupSort::CPU => metrics
            .cpu_memory_data
            .get(&pid)
            .map(|(cpu, _)| f64::from(*cpu)),
        GroupSort::Memory => metrics
            .cpu_memory_data
            .get(&pid)
            .and_then(|(_, mem)| *mem)
            .map(|m| m as f64),
        GroupSort::Disk => metrics
            .io_rate_by_pid
            .get(&pid)
            .map(|r| r.read_bytes_per_sec + r.write_bytes_per_sec),
        GroupSort::GPU => metrics.gpu_data.get(&pid).map(|(pct, ..)| f64::from(*pct)),
        GroupSort::GPUMemory => metrics.gpu_data.get(&pid).map(|(.., total)| *total as f64),
        GroupSort::Name | GroupSort::PID | GroupSort::VerifiedSigner => None,
    }
    .and_then(num)
}

/// (rank, lowercased signer) used by the "Verified Signer" sort. Unknown sorts last.
pub(crate) fn signer_key(
    path: Option<&String>,
    signatures: &HashMap<String, SignatureInfo>,
) -> (u8, String) {
    let Some(path) = path else {
        return (5, String::new());
    };
    let Some(info) = signatures.get(path) else {
        return (4, String::new());
    };
    match info.status() {
        SignatureStatus::Valid => (
            0,
            info.signer_name
                .as_deref()
                .map_or_else(|| "verified".to_string(), crate::snapshot::lowercase),
        ),
        SignatureStatus::CatalogSigned => (
            1,
            info.signer_name.as_deref().map_or_else(
                || "verified (catalog)".to_string(),
                crate::snapshot::lowercase,
            ),
        ),
        SignatureStatus::NotSigned => (3, "not signed".to_string()),
        SignatureStatus::Untrusted => (2, "untrusted".to_string()),
        SignatureStatus::Expired => (2, "expired".to_string()),
        SignatureStatus::Invalid => (2, "invalid".to_string()),
    }
}

/// Order `pids` the way the tree view orders roots and siblings.
///
/// Numeric modes put PIDs with data first (in either direction), then break ties by PID.
/// Name and PID modes reverse the whole order when descending.
pub(crate) fn sort_tree_pids(
    pids: &mut [u32],
    snapshot: &ProcessSnapshot,
    sort: GroupSort,
    desc: bool,
    metrics: &RowMetrics<'_>,
    handles: Handles<'_>,
) {
    let flip = |o: Ordering| if desc { o.reverse() } else { o };
    match sort {
        GroupSort::Name => {
            pids.sort_unstable_by(|&a, &b| {
                flip(
                    snapshot
                        .lower_name(a)
                        .cmp(snapshot.lower_name(b))
                        .then(a.cmp(&b)),
                )
            });
        }
        GroupSort::PID => pids.sort_unstable_by(|a, b| flip(a.cmp(b))),
        GroupSort::VerifiedSigner => {
            let mut keyed: Vec<((u8, String), u32)> = pids
                .iter()
                .map(|&pid| {
                    let path = metrics
                        .pid_to_image_path
                        .get(&pid)
                        .or_else(|| snapshot.get_process(pid).and_then(|p| p.path.as_ref()));
                    (signer_key(path, metrics.signature_cache_by_path), pid)
                })
                .collect();
            keyed.sort_unstable_by(|(ka, a), (kb, b)| {
                flip(
                    ka.cmp(kb)
                        .then_with(|| snapshot.lower_name(*a).cmp(snapshot.lower_name(*b)))
                        .then(a.cmp(b)),
                )
            });
            for (slot, (_, pid)) in pids.iter_mut().zip(keyed) {
                *slot = pid;
            }
        }
        _ => {
            let mut keyed: Vec<(Option<f64>, u32)> = pids
                .iter()
                .map(|&pid| (metric_value(pid, sort, metrics, handles), pid))
                .collect();
            keyed.sort_unstable_by(|(va, a), (vb, b)| match (va, vb) {
                (Some(x), Some(y)) => flip(x.total_cmp(y)).then(a.cmp(b)),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => a.cmp(b),
            });
            for (slot, (_, pid)) in pids.iter_mut().zip(keyed) {
                *slot = pid;
            }
        }
    }
}

/// Whether the decimal form of `pid` contains `needle`, without allocating.
pub(crate) fn pid_contains(pid: u32, needle: &str) -> bool {
    let mut buf = [0u8; 10];
    let mut n = pid;
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let digits = &buf[i..];
    let needle = needle.as_bytes();
    needle.is_empty()
        || (needle.len() <= digits.len() && digits.windows(needle.len()).any(|w| w == needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_contains_matches_to_string_contains() {
        for pid in [0u32, 4, 10, 1234, 40_000, u32::MAX] {
            for needle in [
                "",
                "0",
                "4",
                "12",
                "234",
                "999",
                "4294967295",
                "42949672950",
            ] {
                assert_eq!(
                    pid_contains(pid, needle),
                    pid.to_string().contains(needle),
                    "{pid} / {needle}"
                );
            }
        }
    }

    #[test]
    fn num_makes_floats_totally_ordered() {
        assert_eq!(num(f64::NAN), None);
        assert_eq!(num(-0.0).map(f64::to_bits), Some(0.0f64.to_bits()));
        assert_eq!(num(1.5), Some(1.5));
    }
}
