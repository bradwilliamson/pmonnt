use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct GpuSnapshot {
    pub gpu_percent: HashMap<u32, f32>,
    pub gpu_dedicated_bytes: HashMap<u32, u64>,
    pub gpu_shared_bytes: HashMap<u32, u64>,
    pub gpu_total_bytes: HashMap<u32, u64>,
    pub sample_timestamp: std::time::Instant,
}

impl Default for GpuSnapshot {
    fn default() -> Self {
        Self {
            gpu_percent: HashMap::new(),
            gpu_dedicated_bytes: HashMap::new(),
            gpu_shared_bytes: HashMap::new(),
            gpu_total_bytes: HashMap::new(),
            sample_timestamp: std::time::Instant::now(),
        }
    }
}

#[cfg(windows)]
pub enum GpuSampler {
    Windows(super::gpu_pdh::GpuPdhSampler),
    None,
}

#[cfg(not(windows))]
pub enum GpuSampler {
    None,
}

impl Default for GpuSampler {
    fn default() -> Self {
        #[cfg(windows)]
        {
            match super::gpu_pdh::GpuPdhSampler::new() {
                Ok(sampler) => GpuSampler::Windows(sampler),
                Err(err) => {
                    log::warn!("GPU PDH sampler init failed: {err}");
                    GpuSampler::None
                }
            }
        }
        #[cfg(not(windows))]
        {
            GpuSampler::None
        }
    }
}

impl GpuSampler {
    #[allow(dead_code)]
    pub fn is_available(&self) -> bool {
        #[cfg(windows)]
        {
            matches!(self, GpuSampler::Windows(_))
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    pub fn rebuild_counters(&mut self) {
        #[cfg(windows)]
        {
            if let GpuSampler::Windows(inner) = self {
                if let Err(err) = inner.rebuild_counters() {
                    log::warn!("GPU PDH rebuild failed: {err}");
                }
            }
        }
    }

    pub fn sample(&mut self) -> Option<GpuSnapshot> {
        #[cfg(windows)]
        {
            match self {
                GpuSampler::Windows(inner) => match inner.sample() {
                    Ok(snap) => Some(snap),
                    Err(err) => {
                        log::warn!("GPU PDH sample failed: {err}");
                        None
                    }
                },
                GpuSampler::None => None,
            }
        }
        #[cfg(not(windows))]
        {
            None
        }
    }
}
