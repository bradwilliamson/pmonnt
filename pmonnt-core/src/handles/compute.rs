use super::HandleSummary;

use std::collections::HashMap;

/// Compute handle summaries for all processes from raw handle list
pub fn compute_summaries(
    handles: &[crate::win::handles::HandleEntry],
) -> HashMap<u32, HandleSummary> {
    let mut per_pid: HashMap<u32, HashMap<u16, u32>> = HashMap::new();

    for handle in handles {
        let type_counts = per_pid.entry(handle.pid).or_default();
        *type_counts.entry(handle.object_type_index).or_insert(0) += 1;
    }

    per_pid
        .into_iter()
        .map(|(pid, type_counts)| {
            let entries: Vec<(u16, u32)> = type_counts.into_iter().collect();
            (pid, HandleSummary::from_entries(&entries))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_summaries_groups_by_pid_and_counts_types() {
        let handles = vec![
            crate::win::handles::HandleEntry {
                pid: 10,
                handle_value: 1,
                object_type_index: 30,
                granted_access: 0,
            },
            crate::win::handles::HandleEntry {
                pid: 10,
                handle_value: 2,
                object_type_index: 30,
                granted_access: 0,
            },
            crate::win::handles::HandleEntry {
                pid: 10,
                handle_value: 3,
                object_type_index: 7,
                granted_access: 0,
            },
            crate::win::handles::HandleEntry {
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
