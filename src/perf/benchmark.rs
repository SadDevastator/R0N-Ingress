//! Benchmarking framework.
//!
//! Provides tools for measuring performance characteristics of gateway components.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Benchmark configuration.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Benchmark duration.
    pub duration: Duration,
    /// Warmup duration before measurement.
    pub warmup: Duration,
    /// Number of concurrent workers.
    pub concurrency: usize,
    /// Target operations per second (0 = unlimited).
    pub target_ops_per_sec: u64,
    /// Collect latency histogram.
    pub collect_latency: bool,
    /// Histogram resolution in microseconds.
    pub histogram_resolution_us: u64,
    /// Maximum latency to track in histogram.
    pub max_latency_us: u64,
    /// Name of the benchmark.
    pub name: String,
    /// Description.
    pub description: Option<String>,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(10),
            warmup: Duration::from_secs(2),
            concurrency: 1,
            target_ops_per_sec: 0,
            collect_latency: true,
            histogram_resolution_us: 10,
            max_latency_us: 10_000_000, // 10 seconds
            name: "benchmark".to_string(),
            description: None,
        }
    }
}

impl BenchmarkConfig {
    /// Create a new benchmark configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Set benchmark duration.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// Set warmup duration.
    pub fn with_warmup(mut self, warmup: Duration) -> Self {
        self.warmup = warmup;
        self
    }

    /// Set concurrency level.
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    /// Set target operations per second.
    pub fn with_target_ops(mut self, ops: u64) -> Self {
        self.target_ops_per_sec = ops;
        self
    }

    /// Set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Disable latency collection.
    pub fn without_latency(mut self) -> Self {
        self.collect_latency = false;
        self
    }
}

/// Benchmark result.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Benchmark name.
    pub name: String,
    /// Total operations completed.
    pub total_ops: u64,
    /// Total errors.
    pub total_errors: u64,
    /// Actual duration of the benchmark.
    pub duration: Duration,
    /// Throughput in operations per second.
    pub throughput: f64,
    /// Latency statistics.
    pub latency: Option<LatencyStats>,
    /// Per-second throughput samples.
    pub throughput_samples: Vec<u64>,
    /// Configuration used.
    pub config: BenchmarkConfig,
    /// Start time.
    pub started_at: Instant,
    /// End time.
    pub ended_at: Instant,
}

impl BenchmarkResult {
    /// Get throughput in operations per second.
    pub fn throughput(&self) -> f64 {
        self.throughput
    }

    /// Get total operations.
    pub fn total_ops(&self) -> u64 {
        self.total_ops
    }

    /// Get error rate.
    pub fn error_rate(&self) -> f64 {
        if self.total_ops == 0 {
            0.0
        } else {
            self.total_errors as f64 / (self.total_ops + self.total_errors) as f64
        }
    }

    /// Get success rate.
    pub fn success_rate(&self) -> f64 {
        1.0 - self.error_rate()
    }

    /// Get mean latency.
    pub fn mean_latency(&self) -> Option<Duration> {
        self.latency.as_ref().map(|l| l.mean)
    }

    /// Get p50 latency.
    pub fn p50_latency(&self) -> Option<Duration> {
        self.latency.as_ref().map(|l| l.p50)
    }

    /// Get p99 latency.
    pub fn p99_latency(&self) -> Option<Duration> {
        self.latency.as_ref().map(|l| l.p99)
    }

    /// Format as a summary string.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "{}: {:.2} ops/s, {} total, {:.2}% success",
            self.name,
            self.throughput,
            self.total_ops,
            self.success_rate() * 100.0
        );

        if let Some(ref latency) = self.latency {
            s.push_str(&format!(
                ", latency: p50={:.2}ms, p99={:.2}ms, max={:.2}ms",
                latency.p50.as_secs_f64() * 1000.0,
                latency.p99.as_secs_f64() * 1000.0,
                latency.max.as_secs_f64() * 1000.0
            ));
        }

        s
    }
}

/// Latency statistics.
#[derive(Debug, Clone)]
pub struct LatencyStats {
    /// Minimum latency.
    pub min: Duration,
    /// Maximum latency.
    pub max: Duration,
    /// Mean latency.
    pub mean: Duration,
    /// Median (p50) latency.
    pub p50: Duration,
    /// 90th percentile latency.
    pub p90: Duration,
    /// 95th percentile latency.
    pub p95: Duration,
    /// 99th percentile latency.
    pub p99: Duration,
    /// 99.9th percentile latency.
    pub p999: Duration,
    /// Standard deviation.
    pub std_dev: Duration,
    /// Total samples.
    pub count: u64,
}

/// Latency histogram for collecting timing data.
#[derive(Debug)]
pub struct LatencyHistogram {
    /// Bucket counts.
    buckets: Vec<AtomicU64>,
    /// Resolution in microseconds.
    resolution_us: u64,
    /// Maximum trackable value.
    max_us: u64,
    /// Total count.
    count: AtomicU64,
    /// Sum for mean calculation.
    sum_us: AtomicU64,
    /// Minimum value.
    min_us: AtomicU64,
    /// Maximum value.
    max_us_recorded: AtomicU64,
}

impl LatencyHistogram {
    /// Create a new histogram.
    pub fn new(resolution_us: u64, max_us: u64) -> Self {
        let bucket_count = (max_us / resolution_us) as usize + 1;
        let mut buckets = Vec::with_capacity(bucket_count);
        for _ in 0..bucket_count {
            buckets.push(AtomicU64::new(0));
        }

        Self {
            buckets,
            resolution_us,
            max_us,
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
            min_us: AtomicU64::new(u64::MAX),
            max_us_recorded: AtomicU64::new(0),
        }
    }

    /// Record a latency value.
    pub fn record(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        let bucket = (us / self.resolution_us).min(self.buckets.len() as u64 - 1) as usize;

        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(us, Ordering::Relaxed);

        // Update min
        let mut current_min = self.min_us.load(Ordering::Relaxed);
        while us < current_min {
            match self.min_us.compare_exchange_weak(
                current_min,
                us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => current_min = c,
            }
        }

        // Update max
        let mut current_max = self.max_us_recorded.load(Ordering::Relaxed);
        while us > current_max {
            match self.max_us_recorded.compare_exchange_weak(
                current_max,
                us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => current_max = c,
            }
        }
    }

    /// Get total count.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Calculate statistics.
    pub fn stats(&self) -> Option<LatencyStats> {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return None;
        }

        let min_us = self.min_us.load(Ordering::Relaxed);
        let max_us = self.max_us_recorded.load(Ordering::Relaxed);
        let sum_us = self.sum_us.load(Ordering::Relaxed);
        let mean_us = sum_us / count;

        // Collect bucket values for percentile calculation
        let buckets: Vec<u64> = self
            .buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect();

        // Calculate percentiles
        let p50 = self.percentile(&buckets, count, 0.50);
        let p90 = self.percentile(&buckets, count, 0.90);
        let p95 = self.percentile(&buckets, count, 0.95);
        let p99 = self.percentile(&buckets, count, 0.99);
        let p999 = self.percentile(&buckets, count, 0.999);

        // Calculate standard deviation (approximate)
        let variance = self.calculate_variance(&buckets, count, mean_us);
        let std_dev_us = (variance as f64).sqrt() as u64;

        Some(LatencyStats {
            min: Duration::from_micros(min_us),
            max: Duration::from_micros(max_us),
            mean: Duration::from_micros(mean_us),
            p50: Duration::from_micros(p50),
            p90: Duration::from_micros(p90),
            p95: Duration::from_micros(p95),
            p99: Duration::from_micros(p99),
            p999: Duration::from_micros(p999),
            std_dev: Duration::from_micros(std_dev_us),
            count,
        })
    }

    fn percentile(&self, buckets: &[u64], total: u64, percentile: f64) -> u64 {
        let target = (total as f64 * percentile) as u64;
        let mut cumulative = 0u64;

        for (i, &count) in buckets.iter().enumerate() {
            cumulative += count;
            if cumulative >= target {
                return (i as u64 + 1) * self.resolution_us;
            }
        }

        self.max_us
    }

    fn calculate_variance(&self, buckets: &[u64], total: u64, mean_us: u64) -> u64 {
        let mut sum_sq_diff = 0u64;

        for (i, &count) in buckets.iter().enumerate() {
            if count > 0 {
                let bucket_value = (i as u64) * self.resolution_us + self.resolution_us / 2;
                let diff = bucket_value.abs_diff(mean_us);
                sum_sq_diff += diff * diff * count;
            }
        }

        sum_sq_diff / total
    }

    /// Reset the histogram.
    pub fn reset(&self) {
        for bucket in &self.buckets {
            bucket.store(0, Ordering::Relaxed);
        }
        self.count.store(0, Ordering::Relaxed);
        self.sum_us.store(0, Ordering::Relaxed);
        self.min_us.store(u64::MAX, Ordering::Relaxed);
        self.max_us_recorded.store(0, Ordering::Relaxed);
    }
}

/// Throughput metrics collector.
#[derive(Debug)]
pub struct ThroughputMetrics {
    /// Operations counter.
    ops: AtomicU64,
    /// Error counter.
    errors: AtomicU64,
    /// Bytes processed.
    bytes: AtomicU64,
    /// Per-second samples.
    samples: std::sync::Mutex<Vec<u64>>,
}

impl Default for ThroughputMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ThroughputMetrics {
    /// Create new metrics collector.
    pub fn new() -> Self {
        Self {
            ops: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            samples: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Record a successful operation.
    pub fn record_op(&self) {
        self.ops.fetch_add(1, Ordering::Relaxed);
    }

    /// Record multiple operations.
    pub fn record_ops(&self, count: u64) {
        self.ops.fetch_add(count, Ordering::Relaxed);
    }

    /// Record an error.
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes processed.
    pub fn record_bytes(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get total operations.
    pub fn total_ops(&self) -> u64 {
        self.ops.load(Ordering::Relaxed)
    }

    /// Get total errors.
    pub fn total_errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Get total bytes.
    pub fn total_bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Take a sample of current ops count.
    pub fn sample(&self) {
        let current = self.ops.load(Ordering::Relaxed);
        if let Ok(mut samples) = self.samples.lock() {
            samples.push(current);
        }
    }

    /// Get samples.
    pub fn get_samples(&self) -> Vec<u64> {
        self.samples.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Reset counters.
    pub fn reset(&self) {
        self.ops.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
        if let Ok(mut samples) = self.samples.lock() {
            samples.clear();
        }
    }
}

/// Benchmark runner.
#[derive(Debug)]
pub struct Benchmark {
    /// Configuration.
    config: BenchmarkConfig,
}

impl Benchmark {
    /// Create a new benchmark.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            config: BenchmarkConfig::new(name),
        }
    }

    /// Set configuration.
    pub fn with_config(mut self, config: BenchmarkConfig) -> Self {
        self.config = config;
        self
    }

    /// Set duration.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.config.duration = duration;
        self
    }

    /// Set concurrency.
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.config.concurrency = concurrency.max(1);
        self
    }

    /// Run the benchmark with a synchronous function.
    pub fn run_sync<F, R>(&self, f: F) -> BenchmarkResult
    where
        F: Fn() -> R + Send + Sync + Clone + 'static,
        R: Send,
    {
        let metrics = Arc::new(ThroughputMetrics::new());
        let histogram = if self.config.collect_latency {
            Some(Arc::new(LatencyHistogram::new(
                self.config.histogram_resolution_us,
                self.config.max_latency_us,
            )))
        } else {
            None
        };

        let started_at = Instant::now();

        // Warmup phase
        if self.config.warmup > Duration::ZERO {
            let warmup_end = Instant::now() + self.config.warmup;
            while Instant::now() < warmup_end {
                let _ = f();
            }
            metrics.reset();
            if let Some(ref h) = histogram {
                h.reset();
            }
        }

        let benchmark_start = Instant::now();
        let benchmark_end = benchmark_start + self.config.duration;

        // Run benchmark
        let mut handles = Vec::new();
        for _ in 0..self.config.concurrency {
            let f = f.clone();
            let metrics = Arc::clone(&metrics);
            let histogram = histogram.clone();
            let duration = self.config.duration;

            let handle = std::thread::spawn(move || {
                let end = Instant::now() + duration;
                while Instant::now() < end {
                    let op_start = Instant::now();
                    let _ = f();
                    let elapsed = op_start.elapsed();

                    metrics.record_op();
                    if let Some(ref h) = histogram {
                        h.record(elapsed);
                    }
                }
            });
            handles.push(handle);
        }

        // Sample throughput
        let sample_interval = Duration::from_secs(1);
        while Instant::now() < benchmark_end {
            std::thread::sleep(sample_interval.min(benchmark_end - Instant::now()));
            metrics.sample();
        }

        // Wait for workers
        for handle in handles {
            let _ = handle.join();
        }

        let ended_at = Instant::now();
        let actual_duration = ended_at - benchmark_start;

        let total_ops = metrics.total_ops();
        let throughput = total_ops as f64 / actual_duration.as_secs_f64();

        // Calculate per-second throughput from samples
        let samples = metrics.get_samples();
        let throughput_samples: Vec<u64> = samples
            .windows(2)
            .map(|w| w[1].saturating_sub(w[0]))
            .collect();

        BenchmarkResult {
            name: self.config.name.clone(),
            total_ops,
            total_errors: metrics.total_errors(),
            duration: actual_duration,
            throughput,
            latency: histogram.and_then(|h| h.stats()),
            throughput_samples,
            config: self.config.clone(),
            started_at,
            ended_at,
        }
    }

    /// Run the benchmark with an async function.
    pub async fn run_async<F, Fut, R>(&self, f: F) -> BenchmarkResult
    where
        F: Fn() -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = R> + Send,
        R: Send,
    {
        let metrics = Arc::new(ThroughputMetrics::new());
        let histogram = if self.config.collect_latency {
            Some(Arc::new(LatencyHistogram::new(
                self.config.histogram_resolution_us,
                self.config.max_latency_us,
            )))
        } else {
            None
        };

        let started_at = Instant::now();

        // Warmup phase
        if self.config.warmup > Duration::ZERO {
            let warmup_end = Instant::now() + self.config.warmup;
            while Instant::now() < warmup_end {
                let _ = f().await;
            }
            metrics.reset();
            if let Some(ref h) = histogram {
                h.reset();
            }
        }

        let benchmark_start = Instant::now();
        let duration = self.config.duration;

        // Create worker tasks
        let mut handles = Vec::new();
        for _ in 0..self.config.concurrency {
            let f = f.clone();
            let metrics = Arc::clone(&metrics);
            let histogram = histogram.clone();

            let handle = tokio::spawn(async move {
                let end = Instant::now() + duration;
                while Instant::now() < end {
                    let op_start = Instant::now();
                    let _ = f().await;
                    let elapsed = op_start.elapsed();

                    metrics.record_op();
                    if let Some(ref h) = histogram {
                        h.record(elapsed);
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all workers
        for handle in handles {
            let _ = handle.await;
        }

        let ended_at = Instant::now();
        let actual_duration = ended_at - benchmark_start;

        let total_ops = metrics.total_ops();
        let throughput = total_ops as f64 / actual_duration.as_secs_f64();

        BenchmarkResult {
            name: self.config.name.clone(),
            total_ops,
            total_errors: metrics.total_errors(),
            duration: actual_duration,
            throughput,
            latency: histogram.and_then(|h| h.stats()),
            throughput_samples: Vec::new(),
            config: self.config.clone(),
            started_at,
            ended_at,
        }
    }
}

/// Benchmark runner for multiple benchmarks.
#[derive(Debug, Default)]
pub struct BenchmarkRunner {
    /// Registered benchmarks.
    benchmarks: Vec<(String, BenchmarkConfig)>,
    /// Results.
    results: HashMap<String, BenchmarkResult>,
}

impl BenchmarkRunner {
    /// Create a new runner.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a benchmark.
    pub fn register(&mut self, name: impl Into<String>, config: BenchmarkConfig) {
        let name = name.into();
        self.benchmarks.push((name, config));
    }

    /// Get results.
    pub fn results(&self) -> &HashMap<String, BenchmarkResult> {
        &self.results
    }

    /// Store a result.
    pub fn store_result(&mut self, result: BenchmarkResult) {
        self.results.insert(result.name.clone(), result);
    }

    /// Generate a report.
    pub fn report(&self) -> String {
        let mut report = String::new();
        report.push_str("=== Benchmark Report ===\n\n");

        for (name, result) in &self.results {
            report.push_str(&format!("{}\n", name));
            report.push_str(&format!("  Throughput: {:.2} ops/s\n", result.throughput));
            report.push_str(&format!("  Total Ops:  {}\n", result.total_ops));
            report.push_str(&format!("  Errors:     {}\n", result.total_errors));
            report.push_str(&format!(
                "  Duration:   {:.2}s\n",
                result.duration.as_secs_f64()
            ));

            if let Some(ref latency) = result.latency {
                report.push_str("  Latency:\n");
                report.push_str(&format!(
                    "    min:   {:.2}ms\n",
                    latency.min.as_secs_f64() * 1000.0
                ));
                report.push_str(&format!(
                    "    mean:  {:.2}ms\n",
                    latency.mean.as_secs_f64() * 1000.0
                ));
                report.push_str(&format!(
                    "    p50:   {:.2}ms\n",
                    latency.p50.as_secs_f64() * 1000.0
                ));
                report.push_str(&format!(
                    "    p90:   {:.2}ms\n",
                    latency.p90.as_secs_f64() * 1000.0
                ));
                report.push_str(&format!(
                    "    p99:   {:.2}ms\n",
                    latency.p99.as_secs_f64() * 1000.0
                ));
                report.push_str(&format!(
                    "    max:   {:.2}ms\n",
                    latency.max.as_secs_f64() * 1000.0
                ));
            }
            report.push('\n');
        }

        report
    }
}

/// Benchmark suite for organizing related benchmarks.
#[derive(Debug)]
pub struct BenchmarkSuite {
    /// Suite name.
    name: String,
    /// Suite description.
    description: Option<String>,
    /// Runner.
    runner: BenchmarkRunner,
}

impl BenchmarkSuite {
    /// Create a new suite.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            runner: BenchmarkRunner::new(),
        }
    }

    /// Set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Add a benchmark.
    pub fn add(&mut self, config: BenchmarkConfig) {
        self.runner.register(config.name.clone(), config);
    }

    /// Get runner.
    pub fn runner(&self) -> &BenchmarkRunner {
        &self.runner
    }

    /// Get mutable runner.
    pub fn runner_mut(&mut self) -> &mut BenchmarkRunner {
        &mut self.runner
    }

    /// Get suite name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Generate report.
    pub fn report(&self) -> String {
        let mut report = format!("=== {} ===\n", self.name);
        if let Some(ref desc) = self.description {
            report.push_str(&format!("{}\n", desc));
        }
        report.push('\n');
        report.push_str(&self.runner.report());
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_config_default() {
        let config = BenchmarkConfig::default();
        assert_eq!(config.duration, Duration::from_secs(10));
        assert_eq!(config.concurrency, 1);
    }

    #[test]
    fn test_benchmark_config_builder() {
        let config = BenchmarkConfig::new("test")
            .with_duration(Duration::from_secs(5))
            .with_concurrency(4)
            .with_warmup(Duration::from_secs(1))
            .with_description("Test benchmark");

        assert_eq!(config.name, "test");
        assert_eq!(config.duration, Duration::from_secs(5));
        assert_eq!(config.concurrency, 4);
        assert_eq!(config.warmup, Duration::from_secs(1));
    }

    #[test]
    fn test_latency_histogram() {
        let histogram = LatencyHistogram::new(10, 1_000_000);

        histogram.record(Duration::from_micros(100));
        histogram.record(Duration::from_micros(200));
        histogram.record(Duration::from_micros(150));

        assert_eq!(histogram.count(), 3);

        let stats = histogram.stats().unwrap();
        assert_eq!(stats.count, 3);
        assert!(stats.min <= stats.mean);
        assert!(stats.mean <= stats.max);
    }

    #[test]
    fn test_latency_histogram_percentiles() {
        let histogram = LatencyHistogram::new(1, 10_000);

        // Add 100 samples from 1-100 microseconds
        for i in 1..=100 {
            histogram.record(Duration::from_micros(i));
        }

        let stats = histogram.stats().unwrap();
        assert_eq!(stats.count, 100);
        // p50 should be around 50us
        assert!(stats.p50 >= Duration::from_micros(40));
        assert!(stats.p50 <= Duration::from_micros(60));
    }

    #[test]
    fn test_throughput_metrics() {
        let metrics = ThroughputMetrics::new();

        metrics.record_op();
        metrics.record_op();
        metrics.record_error();
        metrics.record_bytes(1024);

        assert_eq!(metrics.total_ops(), 2);
        assert_eq!(metrics.total_errors(), 1);
        assert_eq!(metrics.total_bytes(), 1024);
    }

    #[test]
    fn test_throughput_metrics_reset() {
        let metrics = ThroughputMetrics::new();

        metrics.record_ops(100);
        metrics.reset();

        assert_eq!(metrics.total_ops(), 0);
    }

    #[test]
    fn test_benchmark_sync() {
        let result = Benchmark::new("test")
            .with_duration(Duration::from_millis(100))
            .with_concurrency(1)
            .run_sync(|| {
                std::thread::sleep(Duration::from_micros(100));
                42
            });

        assert_eq!(result.name, "test");
        assert!(result.total_ops > 0);
        assert!(result.throughput > 0.0);
    }

    #[test]
    fn test_benchmark_result_error_rate() {
        let result = BenchmarkResult {
            name: "test".to_string(),
            total_ops: 90,
            total_errors: 10,
            duration: Duration::from_secs(1),
            throughput: 90.0,
            latency: None,
            throughput_samples: Vec::new(),
            config: BenchmarkConfig::default(),
            started_at: Instant::now(),
            ended_at: Instant::now(),
        };

        assert!((result.error_rate() - 0.1).abs() < 0.01);
        assert!((result.success_rate() - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_benchmark_result_summary() {
        let result = BenchmarkResult {
            name: "test".to_string(),
            total_ops: 1000,
            total_errors: 0,
            duration: Duration::from_secs(1),
            throughput: 1000.0,
            latency: Some(LatencyStats {
                min: Duration::from_micros(100),
                max: Duration::from_micros(1000),
                mean: Duration::from_micros(500),
                p50: Duration::from_micros(450),
                p90: Duration::from_micros(800),
                p95: Duration::from_micros(900),
                p99: Duration::from_micros(950),
                p999: Duration::from_micros(990),
                std_dev: Duration::from_micros(200),
                count: 1000,
            }),
            throughput_samples: Vec::new(),
            config: BenchmarkConfig::default(),
            started_at: Instant::now(),
            ended_at: Instant::now(),
        };

        let summary = result.summary();
        assert!(summary.contains("1000.00 ops/s"));
        assert!(summary.contains("100.00% success"));
    }

    #[test]
    fn test_benchmark_runner() {
        let mut runner = BenchmarkRunner::new();

        runner.register("bench1", BenchmarkConfig::new("bench1"));
        runner.register("bench2", BenchmarkConfig::new("bench2"));

        assert_eq!(runner.benchmarks.len(), 2);
    }

    #[test]
    fn test_benchmark_suite() {
        let mut suite = BenchmarkSuite::new("HTTP Benchmarks")
            .with_description("Performance tests for HTTP handling");

        suite.add(BenchmarkConfig::new("http_get"));
        suite.add(BenchmarkConfig::new("http_post"));

        assert_eq!(suite.name(), "HTTP Benchmarks");
    }

    #[test]
    fn test_histogram_reset() {
        let histogram = LatencyHistogram::new(10, 1000);

        histogram.record(Duration::from_micros(100));
        assert_eq!(histogram.count(), 1);

        histogram.reset();
        assert_eq!(histogram.count(), 0);
    }

    #[test]
    fn test_throughput_samples() {
        let metrics = ThroughputMetrics::new();

        metrics.record_ops(10);
        metrics.sample();
        metrics.record_ops(20);
        metrics.sample();

        let samples = metrics.get_samples();
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0], 10);
        assert_eq!(samples[1], 30);
    }
}
