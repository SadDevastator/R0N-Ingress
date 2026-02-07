//! # Performance Optimization
//!
//! Production-ready performance utilities for R0N Gateway.
//!
//! ## Features
//!
//! - **Benchmarking**: Comprehensive benchmark suite for measuring throughput and latency
//! - **Memory**: Memory optimization utilities including pools and arena allocators
//! - **Connection Pooling**: Tuned connection pool with adaptive sizing
//! - **Zero-Copy**: Zero-copy buffer utilities for efficient data transfer
//!
//! ## Example
//!
//! ```rust,ignore
//! use r0n_gateway::perf::{Benchmark, BenchmarkConfig, MemoryPool};
//!
//! // Run a benchmark
//! let config = BenchmarkConfig::default()
//!     .with_duration(Duration::from_secs(10))
//!     .with_concurrency(100);
//!
//! let results = Benchmark::new("http_throughput")
//!     .with_config(config)
//!     .run(|| async { /* test code */ })
//!     .await;
//!
//! println!("Throughput: {} req/s", results.throughput());
//! ```

pub mod benchmark;
pub mod connection_pool;
pub mod memory;
pub mod zero_copy;

pub use benchmark::{
    Benchmark, BenchmarkConfig, BenchmarkResult, BenchmarkRunner, BenchmarkSuite, LatencyHistogram,
    LatencyStats, ThroughputMetrics,
};
pub use connection_pool::{
    AdaptivePool, ConnectionPool, PoolConfig, PoolMetrics, PooledConnection,
};
pub use memory::{
    Arena, ArenaAllocator, BufferPool, MemoryPool, PoolStats, PooledBuffer, Slab, SlabAllocator,
};
pub use zero_copy::{
    BufferChain, ByteCursor, IoVec, ReadBuffer, SharedBuffer, WriteBuffer, ZeroCopyRead,
    ZeroCopyStats, ZeroCopyWrite,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible
        let _ = BenchmarkConfig::default();
        let _ = PoolConfig::default();
    }
}
