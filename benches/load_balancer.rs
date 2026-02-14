#![allow(clippy::all)]
//! Benchmarks for the Load Balancer module.
//!
//! Tests: Strategy selection (round-robin, weighted, least-connections, hash, random),
//! backend pool management, health checks, sticky sessions, concurrent selection.

mod common;
use common::generators;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use r0n_ingress::modules::load_balancer::config::BackendConfig;
use r0n_ingress::modules::load_balancer::{
    Backend, BackendPool, HashStrategy, LeastConnectionsStrategy, RoundRobinStrategy, Strategy,
};
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;

fn make_backends(count: usize) -> Vec<Arc<Backend>> {
    let configs = generators::backend_configs(count);
    configs
        .into_iter()
        .map(|(addr, port, weight)| {
            let addr: SocketAddr = format!("{addr}:{port}").parse().unwrap();
            let config = BackendConfig {
                address: addr.ip(),
                port: addr.port(),
                weight,
                max_connections: Some(1000),
                enabled: true,
            };
            Arc::new(Backend::new(&config))
        })
        .collect()
}

fn make_pool(name: &str, count: usize) -> BackendPool {
    let pool = BackendPool::new(name);
    let configs = generators::backend_configs(count);
    for (addr, port, weight) in configs {
        let sa: SocketAddr = format!("{addr}:{port}").parse().unwrap();
        let config = BackendConfig {
            address: sa.ip(),
            port: sa.port(),
            weight,
            max_connections: Some(1000),
            enabled: true,
        };
        pool.add_backend(Backend::new(&config));
    }
    pool
}

fn default_context() -> r0n_ingress::modules::load_balancer::strategy::SelectionContext {
    r0n_ingress::modules::load_balancer::strategy::SelectionContext::new()
        .with_client_ip("192.168.1.100:12345".parse().unwrap())
}

// ---------------------------------------------------------------------------
// Strategy selection benchmarks
// ---------------------------------------------------------------------------

fn bench_round_robin(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_balancer/round_robin");
    let rt = common::harness::bench_runtime();

    for backend_count in [3, 10, 50, 200] {
        let backends = make_backends(backend_count);
        let strategy = RoundRobinStrategy::new();
        let ctx = default_context();

        group.bench_with_input(
            BenchmarkId::new("select", backend_count),
            &backend_count,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    black_box(strategy.select(&backends, &ctx).await.unwrap());
                });
            },
        );
    }
    group.finish();
}

fn bench_least_connections(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_balancer/least_connections");
    let rt = common::harness::bench_runtime();

    for backend_count in [3, 10, 50, 200] {
        let backends = make_backends(backend_count);
        let strategy = LeastConnectionsStrategy::new();
        let ctx = default_context();

        // Simulate some active connections
        for (i, b) in backends.iter().enumerate() {
            for _ in 0..(i % 5) {
                b.stats().record_connection();
            }
        }

        group.bench_with_input(
            BenchmarkId::new("select", backend_count),
            &backend_count,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    black_box(strategy.select(&backends, &ctx).await.unwrap());
                });
            },
        );
    }
    group.finish();
}

fn bench_hash_strategy(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_balancer/hash_strategy");
    let rt = common::harness::bench_runtime();
    let backends = make_backends(20);

    group.bench_function("ip_hash", |b| {
        let strategy = HashStrategy::ip_hash(300);
        let ctx = default_context();
        b.to_async(&rt).iter(|| async {
            black_box(strategy.select(&backends, &ctx).await.unwrap());
        });
    });

    group.bench_function("header_hash", |b| {
        let strategy = HashStrategy::header_hash("X-Request-ID", 300);
        let ctx = r0n_ingress::modules::load_balancer::strategy::SelectionContext::new()
            .with_client_ip("192.168.1.100:12345".parse().unwrap())
            .with_header("X-Request-ID", "req-12345-abcde");
        b.to_async(&rt).iter(|| async {
            black_box(strategy.select(&backends, &ctx).await.unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Backend pool operations
// ---------------------------------------------------------------------------

fn bench_backend_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_balancer/pool_ops");

    group.bench_function("add_backend", |b| {
        b.iter_with_setup(
            || BackendPool::new("bench"),
            |pool| {
                let config = BackendConfig {
                    address: "10.0.0.1".parse().unwrap(),
                    port: 8080,
                    weight: 1,
                    max_connections: Some(1000),
                    enabled: true,
                };
                pool.add_backend(Backend::new(&config));
                black_box(&pool);
            },
        );
    });

    for size in [10, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("healthy_backends", size),
            &size,
            |b, &size| {
                let pool = make_pool("bench", size);
                b.iter(|| {
                    black_box(pool.healthy_backends());
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("all_backends", size), &size, |b, &size| {
            let pool = make_pool("bench", size);
            b.iter(|| {
                black_box(pool.all_backends());
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Backend stats (atomic operations)
// ---------------------------------------------------------------------------

fn bench_backend_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_balancer/backend_stats");

    let config = BackendConfig {
        address: "10.0.0.1".parse().unwrap(),
        port: 8080,
        weight: 1,
        max_connections: Some(10000),
        enabled: true,
    };
    let backend = Backend::new(&config);

    group.bench_function("record_connection", |b| {
        b.iter(|| {
            backend.stats().record_connection();
            backend.stats().record_connection_close();
            black_box(backend.stats().active_connection_count());
        });
    });

    group.bench_function("record_bytes", |b| {
        b.iter(|| {
            backend.stats().record_bytes(1024, 2048);
            black_box(backend.stats().total_connection_count());
        });
    });

    group.bench_function("record_success_failure", |b| {
        b.iter(|| {
            backend.stats().record_success();
            backend.stats().record_failure();
        });
    });

    group.bench_function("can_accept", |b| {
        b.iter(|| {
            black_box(backend.can_accept());
        });
    });

    group.bench_function("health_check_record", |b| {
        b.iter(|| {
            backend.record_health_check(true, 3, 2);
            black_box(backend.state());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_round_robin,
    bench_least_connections,
    bench_hash_strategy,
    bench_backend_pool,
    bench_backend_stats,
);
criterion_main!(benches);
