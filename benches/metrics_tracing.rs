#![allow(clippy::all)]
//! Benchmarks for Metrics Collector, Tracing, and Logging modules.
//!
//! Tests: Metric registration/recording, Prometheus export, span creation,
//! trace context propagation, structured logging overhead.

use criterion::{criterion_group, criterion_main, Criterion};
use r0n_ingress::module::MetricsPayload;
use std::hint::black_box;

// ---------------------------------------------------------------------------
// MetricsPayload (used by all modules)
// ---------------------------------------------------------------------------

fn bench_metrics_payload(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics/payload");

    group.bench_function("create_empty", |b| {
        b.iter(|| {
            black_box(MetricsPayload::new());
        });
    });

    group.bench_function("add_counter", |b| {
        b.iter(|| {
            let mut m = MetricsPayload::new();
            m.counter("requests_total", 42);
            black_box(&m);
        });
    });

    group.bench_function("add_gauge", |b| {
        b.iter(|| {
            let mut m = MetricsPayload::new();
            m.gauge("cpu_usage", 0.75);
            black_box(&m);
        });
    });

    group.bench_function("add_histogram", |b| {
        b.iter(|| {
            let mut m = MetricsPayload::new();
            m.histogram("request_duration", vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0]);
            black_box(&m);
        });
    });

    // Full metrics collection
    group.bench_function("full_metrics", |b| {
        b.iter(|| {
            let mut m = MetricsPayload::new();
            m.counter("requests_total", 100_000);
            m.counter("errors_total", 50);
            m.counter("bytes_in", 1_234_567);
            m.counter("bytes_out", 2_345_678);
            m.gauge("connections_active", 150.0);
            m.gauge("cpu_usage", 0.45);
            m.gauge("memory_mb", 256.5);
            m.histogram(
                "request_latency_ms",
                vec![0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 50.0, 100.0],
            );
            m.histogram(
                "response_size_bytes",
                vec![128.0, 256.0, 512.0, 1024.0, 4096.0],
            );
            black_box(&m);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Prometheus export
// ---------------------------------------------------------------------------

fn bench_prometheus_export(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics/prometheus_export");

    // Small metrics set
    group.bench_function("export_small", |b| {
        let mut m = MetricsPayload::new();
        m.counter("requests", 42);
        m.gauge("latency", 1.5);
        b.iter(|| {
            black_box(m.to_prometheus("ingress"));
        });
    });

    // Medium metrics set
    group.bench_function("export_medium", |b| {
        let mut m = MetricsPayload::new();
        for i in 0..20 {
            m.counter(format!("counter_{i}"), i as u64 * 100);
        }
        for i in 0..10 {
            m.gauge(format!("gauge_{i}"), i as f64 * 1.5);
        }
        for i in 0..5 {
            m.histogram(format!("hist_{i}"), vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0]);
        }
        b.iter(|| {
            black_box(m.to_prometheus("ingress"));
        });
    });

    // Large metrics set (simulating a busy gateway)
    group.bench_function("export_large", |b| {
        let mut m = MetricsPayload::new();
        for i in 0..100 {
            m.counter(format!("module_{}_requests", i), i as u64 * 1000);
        }
        for i in 0..50 {
            m.gauge(format!("module_{}_connections", i), i as f64 * 10.5);
        }
        for i in 0..25 {
            m.histogram(
                format!("module_{}_latency", i),
                (0..100).map(|j| j as f64 * 0.1).collect(),
            );
        }
        b.iter(|| {
            black_box(m.to_prometheus("r0n_ingress"));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Using R0N-Ingress built-in benchmark framework
// ---------------------------------------------------------------------------

fn bench_builtin_benchmark_framework(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics/builtin_framework");

    // LatencyHistogram
    group.bench_function("latency_histogram_record", |b| {
        let hist = r0n_ingress::perf::LatencyHistogram::new(1, 1_000_000);
        b.iter(|| {
            hist.record(std::time::Duration::from_micros(150));
        });
    });

    group.bench_function("latency_histogram_stats", |b| {
        let hist = r0n_ingress::perf::LatencyHistogram::new(1, 1_000_000);
        for i in 0..10_000 {
            hist.record(std::time::Duration::from_micros(i % 1000));
        }
        b.iter(|| {
            black_box(hist.stats());
        });
    });

    group.bench_function("latency_histogram_count", |b| {
        let hist = r0n_ingress::perf::LatencyHistogram::new(1, 1_000_000);
        for _ in 0..1000 {
            hist.record(std::time::Duration::from_micros(100));
        }
        b.iter(|| {
            black_box(hist.count());
        });
    });

    // ThroughputMetrics
    group.bench_function("throughput_record_op", |b| {
        let tm = r0n_ingress::perf::ThroughputMetrics::new();
        b.iter(|| {
            tm.record_op();
        });
    });

    group.bench_function("throughput_record_ops", |b| {
        let tm = r0n_ingress::perf::ThroughputMetrics::new();
        b.iter(|| {
            tm.record_ops(100);
        });
    });

    group.bench_function("throughput_record_bytes", |b| {
        let tm = r0n_ingress::perf::ThroughputMetrics::new();
        b.iter(|| {
            tm.record_bytes(4096);
        });
    });

    group.bench_function("throughput_record_error", |b| {
        let tm = r0n_ingress::perf::ThroughputMetrics::new();
        b.iter(|| {
            tm.record_error();
        });
    });

    group.bench_function("throughput_sample", |b| {
        let tm = r0n_ingress::perf::ThroughputMetrics::new();
        for _ in 0..1000 {
            tm.record_op();
        }
        b.iter(|| {
            tm.sample();
        });
    });

    group.bench_function("throughput_get_samples", |b| {
        let tm = r0n_ingress::perf::ThroughputMetrics::new();
        for _ in 0..100 {
            tm.record_op();
            tm.sample();
        }
        b.iter(|| {
            black_box(tm.get_samples());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// BenchmarkConfig / BenchmarkResult (meta-benchmarks)
// ---------------------------------------------------------------------------

fn bench_benchmark_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics/benchmark_config");

    group.bench_function("config_creation", |b| {
        b.iter(|| {
            black_box(
                r0n_ingress::perf::BenchmarkConfig::new("test-bench")
                    .with_duration(std::time::Duration::from_secs(5))
                    .with_warmup(std::time::Duration::from_secs(1))
                    .with_concurrency(4)
                    .with_target_ops(100_000)
                    .with_description("A test benchmark"),
            );
        });
    });

    group.bench_function("suite_creation", |b| {
        b.iter(|| {
            let mut suite = r0n_ingress::perf::BenchmarkSuite::new("test-suite")
                .with_description("Suite for testing");
            for i in 0..10 {
                suite.add(
                    r0n_ingress::perf::BenchmarkConfig::new(format!("bench-{i}"))
                        .with_duration(std::time::Duration::from_secs(1)),
                );
            }
            black_box(suite.name());
        });
    });

    group.bench_function("runner_report", |b| {
        let mut runner = r0n_ingress::perf::BenchmarkRunner::new();
        runner.register(
            "test",
            r0n_ingress::perf::BenchmarkConfig::new("test")
                .with_duration(std::time::Duration::from_secs(1)),
        );
        b.iter(|| {
            black_box(runner.report());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_metrics_payload,
    bench_prometheus_export,
    bench_builtin_benchmark_framework,
    bench_benchmark_config,
);
criterion_main!(benches);
