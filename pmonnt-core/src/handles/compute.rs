use super::HandleSummary;
use crate::snapshot::PidMap;

use std::collections::HashMap;

/// Compute handle summaries for all processes from raw handle list
///
/// `NtQuerySystemInformation` lists each process's handles contiguously, so this counts
/// each run of one PID in a small array indexed by type and touches the per-PID map once
/// per run instead of hashing twice per handle (100k+ handles per scan). Interleaved
/// input still produces correct totals; it is just slower.
pub fn compute_summaries(
    handles: &[crate::handles::entry::HandleEntry],
) -> HashMap<u32, HandleSummary> {
    summaries_from_counts(&count_handle_types(handles))
}

/// Per-PID `(type index, count)` pairs, in first-seen order. One pass over the handle table;
/// see [`compute_summaries`] for why it counts runs.
pub fn count_handle_types(
    handles: &[crate::handles::entry::HandleEntry],
) -> PidMap<Vec<(u16, u32)>> {
    let mut per_pid: PidMap<Vec<(u16, u32)>> = PidMap::default();
    let mut counts: Vec<u32> = Vec::new();
    let mut touched: Vec<u16> = Vec::new();

    for run in handles.chunk_by(|a, b| a.pid == b.pid) {
        for handle in run {
            let t = usize::from(handle.object_type_index);
            if t >= counts.len() {
                counts.resize(t + 1, 0);
            }
            if counts[t] == 0 {
                touched.push(handle.object_type_index);
            }
            counts[t] += 1;
        }
        let entry = per_pid.entry(run[0].pid).or_default();
        for t in touched.drain(..) {
            let c = std::mem::take(&mut counts[usize::from(t)]);
            match entry.iter_mut().find(|(ty, _)| *ty == t) {
                Some(existing) => existing.1 += c,
                None => entry.push((t, c)),
            }
        }
    }
    per_pid
}

/// Build summaries from [`count_handle_types`] output.
pub fn summaries_from_counts(counts: &PidMap<Vec<(u16, u32)>>) -> HashMap<u32, HandleSummary> {
    counts
        .iter()
        .map(|(&pid, entries)| (pid, HandleSummary::from_entries(entries)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaved_pids_are_merged() {
        let h = |pid, ty| crate::handles::entry::HandleEntry {
            pid,
            handle_value: 4,
            object_type_index: ty,
            granted_access: 0,
        };
        let handles = vec![h(1, 30), h(2, 7), h(1, 30), h(1, 7), h(2, 7)];
        let s = compute_summaries(&handles);
        assert_eq!(s[&1].total, 3);
        assert_eq!(
            s[&1].by_type,
            vec![("File".to_string(), 2), ("Process".to_string(), 1)]
        );
        assert_eq!(s[&2].total, 2);
        assert_eq!(s[&2].by_type, vec![("Process".to_string(), 2)]);
    }

    #[test]
    fn compute_summaries_groups_by_pid_and_counts_types() {
        let handles = vec![
            crate::handles::entry::HandleEntry {
                pid: 10,
                handle_value: 1,
                object_type_index: 30,
                granted_access: 0,
            },
            crate::handles::entry::HandleEntry {
                pid: 10,
                handle_value: 2,
                object_type_index: 30,
                granted_access: 0,
            },
            crate::handles::entry::HandleEntry {
                pid: 10,
                handle_value: 3,
                object_type_index: 7,
                granted_access: 0,
            },
            crate::handles::entry::HandleEntry {
                pid: 20,
                handle_value: 4,
                object_type_index: 7,
                granted_access: 0,
            },
        ];

        let summaries = compute_summaries(&handles);
        assert_eq!(summaries.len(), 2);

        let s10 = summaries.get(&10).expect("pid 10");
        assert_eq!(s10.total, 3);
        assert_eq!(s10.by_type[0], ("File".to_string(), 2));
        assert_eq!(s10.by_type[1], ("Process".to_string(), 1));

        let s20 = summaries.get(&20).expect("pid 20");
        assert_eq!(s20.total, 1);
        assert_eq!(s20.by_type, vec![("Process".to_string(), 1)]);
    }
}
