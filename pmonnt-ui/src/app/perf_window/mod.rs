mod history;
mod sampling;
mod sparkline;
mod tabs;
mod ui;

pub(crate) const PERF_SAMPLE_INTERVAL_SECS: f32 = 0.5;
pub(crate) const PERF_HISTORY_LEN: usize = 480; // ~4 minutes at 0.5s sampling

pub(crate) use history::{PerfStats, ProcessPerfWindow};

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use history::push_with_cap;
