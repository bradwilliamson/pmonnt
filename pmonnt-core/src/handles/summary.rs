use std::time::Instant;

/// Summary of handles for a process
#[derive(Debug, Clone)]
pub struct HandleSummary {
    pub total: u32,
    pub by_type: Vec<(String, u32)>, // sorted desc by count
    pub timestamp: Instant,
}

impl HandleSummary {
    /// Create a new empty handle summary
    pub fn empty() -> Self {
        Self {
            total: 0,
            by_type: Vec::new(),
            timestamp: Instant::now(),
        }
    }

    /// Create from handle entries
    pub fn from_entries(entries: &[(u16, u32)]) -> Self {
        let total = entries.iter().map(|(_, count)| count).sum();

        let mut by_type: Vec<(String, u32)> = entries
            .iter()
            .map(|(type_idx, count)| (crate::win::handles::get_type_name(*type_idx), *count))
            .collect();

        // Sort by count descending
        by_type.sort_by(|a, b| b.1.cmp(&a.1));

        Self {
            total,
            by_type,
            timestamp: Instant::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_entries_computes_total_and_sorts_desc() {
        let entries = vec![(30u16, 2u32), (7u16, 1u32), (999u16, 5u32)];
        let s = HandleSummary::from_entries(&entries);

        assert_eq!(s.total, 8);
        assert_eq!(s.by_type.len(), 3);

        // Sorted by count descending.
        assert_eq!(s.by_type[0], ("TypeIndex999".to_string(), 5));
        assert_eq!(s.by_type[1], ("File".to_string(), 2));
        assert_eq!(s.by_type[2], ("Process".to_string(), 1));
    }
}
