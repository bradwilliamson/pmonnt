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

pub(crate) use pmonnt_core::view::{GroupSort, GroupedRow, ProcRow};
