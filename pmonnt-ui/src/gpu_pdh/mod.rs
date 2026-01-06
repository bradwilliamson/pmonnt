#[cfg(windows)]
mod pdh;
#[cfg(windows)]
mod sampler;
#[cfg(windows)]
mod warnings;

#[cfg(windows)]
pub use sampler::GpuPdhSampler;
#[cfg(windows)]
pub use warnings::should_warn;
