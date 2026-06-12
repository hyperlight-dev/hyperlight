//! CPU core discovery and pool management for benchmark isolation.
//!
//! Discovers performance cores (P-cores) on the system and provides a pool
//! that allows benchmarks to be pinned to specific cores, avoiding interference
//! from concurrent workloads.

use std::sync::{Arc, LazyLock};

use anyhow::{Result, bail};
use cpu_pin::CpuInfo;
use simple_pool::{ResourcePool, ResourcePoolGuard};

/// Lazily discovered list of performance cores on the system.
///
/// Filters for cores that are marked as `Performance` type and have the maximum
/// number of logical processors (i.e., full-featured P-cores with hyperthreading,
/// excluding any asymmetric E-cores).
static PERFORMANCE_CORES: LazyLock<Vec<&'static CpuInfo>> = LazyLock::new(|| {
    cpu_pin::topology()
        .expect("failed to detect CPU topology")
        .best_cores()
});

/// A pool of performance cores that can be claimed by benchmark tasks.
///
/// Each benchmark acquires a core from the pool before running, ensuring
/// no two benchmarks share the same physical core simultaneously.
#[derive(Clone)]
pub struct PerformanceCoresPool {
    pool: Arc<ResourcePool<CpuInfo>>,
}

impl PerformanceCoresPool {
    /// Returns the total number of performance cores available on the system.
    pub fn num_cores() -> usize {
        PERFORMANCE_CORES.len()
    }

    /// Creates a new pool with up to `size` performance cores.
    ///
    /// Returns an error if `size` exceeds the number of available performance cores.
    pub fn new(size: usize) -> Result<Self> {
        if size > PERFORMANCE_CORES.len() {
            bail!(
                "Requested more performance cores than available: requested {size}, available {}",
                PERFORMANCE_CORES.len()
            );
        }

        let pool = Arc::new(ResourcePool::new());
        for core in PERFORMANCE_CORES.iter().take(size) {
            pool.append((*core).clone());
        }

        Ok(Self { pool })
    }

    /// Acquires a performance core from the pool, waiting if none are available.
    ///
    /// The core is returned to the pool when the guard is dropped.
    pub async fn get(&self) -> ResourcePoolGuard<CpuInfo> {
        self.pool.get().await
    }
}

impl Default for PerformanceCoresPool {
    /// Creates a pool containing all available performance cores.
    fn default() -> Self {
        Self::new(Self::num_cores()).unwrap()
    }
}
