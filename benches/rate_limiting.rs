#![allow(clippy::all)]
//! Benchmarks for the Rate Limiting module.
//!
//! Tests: TokenBucket throughput (lock-free atomics), RateLimiter check,
//! distributed state, cleanup, burst handling.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use r0n_ingress::modules::rate_limiting::{
    DistributedState, LimitScope, LocalState, RateLimitConfig, RateLimitDecision, RateLimitRule,
    RateLimiter, TokenBucket,
};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// TokenBucket benchmarks
// ---------------------------------------------------------------------------

fn bench_token_bucket(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting/token_bucket");

    group.bench_function("try_consume_single", |b| {
        let bucket = TokenBucket::with_rate(1_000_000, 100_000.0);
        b.iter(|| {
            black_box(bucket.try_consume(1));
        });
    });

    group.bench_function("available_tokens", |b| {
        let bucket = TokenBucket::with_rate(10_000, 1000.0);
        b.iter(|| {
            black_box(bucket.available_tokens());
        });
    });

    group.bench_function("fill_ratio", |b| {
        let bucket = TokenBucket::with_rate(10_000, 1000.0);
        b.iter(|| {
            black_box(bucket.fill_ratio());
        });
    });

    group.bench_function("time_until_available", |b| {
        let bucket = TokenBucket::with_rate(100, 10.0);
        // Drain the bucket
        for _ in 0..100 {
            let _ = bucket.try_consume(1);
        }
        b.iter(|| {
            black_box(bucket.time_until_available(1));
        });
    });

    group.bench_function("reset", |b| {
        let bucket = TokenBucket::with_rate(10_000, 1000.0);
        b.iter(|| {
            bucket.reset();
            black_box(&bucket);
        });
    });

    // Throughput under burst
    for burst_size in [10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("burst_consume", burst_size),
            &burst_size,
            |b, &size| {
                let bucket = TokenBucket::with_rate(1_000_000, 1_000_000.0);
                b.iter(|| {
                    for _ in 0..size {
                        black_box(bucket.try_consume(1));
                    }
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// RateLimiter check benchmarks
// ---------------------------------------------------------------------------

fn bench_rate_limiter(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting/limiter");

    let config = RateLimitConfig::new().with_default_limit(RateLimitRule::new(10_000, 1000.0));
    let limiter = RateLimiter::new(config);

    // Note: RateLimitContext is not publicly exported, so we benchmark
    // the other public methods instead.

    group.bench_function("active_bucket_count", |b| {
        b.iter(|| {
            black_box(limiter.active_bucket_count());
        });
    });

    group.bench_function("cleanup", |b| {
        b.iter(|| {
            limiter.cleanup(Duration::from_secs(300));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Distributed state benchmarks
// ---------------------------------------------------------------------------

fn bench_distributed_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting/distributed_state");

    let state = Arc::new(LocalState::new());

    group.bench_function("get_tokens", |b| {
        b.iter(|| {
            let _ = black_box(state.get_tokens("test_key"));
        });
    });

    group.bench_function("set_tokens", |b| {
        b.iter(|| {
            let _ = black_box(state.set_tokens("test_key", 100.0, Duration::from_secs(60)));
        });
    });

    group.bench_function("consume_tokens", |b| {
        let _ = state.set_tokens("consume_key", 1_000_000.0, Duration::from_secs(60));
        b.iter(|| {
            let _ = black_box(state.consume_tokens(
                "consume_key",
                1,
                1_000_000,
                100_000.0,
                Duration::from_secs(60),
            ));
        });
    });

    group.bench_function("is_healthy", |b| {
        b.iter(|| {
            black_box(state.is_healthy());
        });
    });

    group.bench_function("cleanup_expired", |b| {
        b.iter(|| {
            state.cleanup_expired();
        });
    });

    group.bench_function("entry_count", |b| {
        b.iter(|| {
            black_box(state.entry_count());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Decision inspection
// ---------------------------------------------------------------------------

fn bench_rate_limit_decision(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting/decision");

    group.bench_function("decision_creation_allowed", |b| {
        b.iter(|| {
            black_box(RateLimitDecision::allowed(
                999,
                1000,
                "test".to_string(),
                LimitScope::Global,
            ));
        });
    });

    group.bench_function("decision_creation_denied", |b| {
        b.iter(|| {
            black_box(RateLimitDecision::denied(
                0,
                1000,
                Duration::from_secs(42),
                "test".to_string(),
                LimitScope::PerIp,
            ));
        });
    });

    group.bench_function("retry_after_secs", |b| {
        let decision = RateLimitDecision::denied(
            0,
            1000,
            Duration::from_secs(42),
            "test".to_string(),
            LimitScope::PerIp,
        );
        b.iter(|| {
            black_box(decision.retry_after_secs());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_token_bucket,
    bench_rate_limiter,
    bench_distributed_state,
    bench_rate_limit_decision,
);
criterion_main!(benches);
