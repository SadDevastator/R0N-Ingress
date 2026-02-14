//! Benchmark harness utilities.
//!
//! Provides helpers for setting up Tokio runtimes, measuring operations,
//! and running async benchmarks within Criterion groups.

use std::time::{Duration, Instant};

/// Create a multi-threaded Tokio runtime for async benchmarks.
pub fn bench_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime for benchmarks")
}

/// Create a current-thread Tokio runtime (for single-threaded benchmarks).
pub fn bench_runtime_single() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build single-thread Tokio runtime")
}

/// Measure wall-clock time for a synchronous operation.
pub fn measure<F, R>(f: F) -> (R, Duration)
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed();
    (result, elapsed)
}

/// Measure wall-clock time for an async operation using the given runtime.
pub fn measure_async<F, Fut, R>(rt: &tokio::runtime::Runtime, f: F) -> (R, Duration)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = R>,
{
    let start = Instant::now();
    let result = rt.block_on(f());
    let elapsed = start.elapsed();
    (result, elapsed)
}

/// Standard benchmark iteration counts.
pub struct BenchSizes;

impl BenchSizes {
    /// Small iteration count for expensive operations.
    pub const SMALL: usize = 100;
    /// Medium iteration count.
    pub const MEDIUM: usize = 1_000;
    /// Large iteration count for cheap operations.
    pub const LARGE: usize = 10_000;
    /// Very large count for micro-benchmarks.
    pub const XLARGE: usize = 100_000;
}
