#![allow(clippy::all)]
//! Benchmarks for TCP Router module.
//!
//! Tests: Connection pool stats, route config construction, listener stats.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use r0n_ingress::modules::tcp_router::{
    BackendConfig, MatchCriteria, RouteConfig, TcpRouterConfig,
};
use r0n_ingress::modules::tcp_router::{ConnectionPool, PoolSettings, TcpRouter};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

// ---------------------------------------------------------------------------
// TCP Router config & construction
// ---------------------------------------------------------------------------

fn bench_router_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_router/construction");

    for route_count in [5, 20, 100] {
        group.bench_with_input(
            BenchmarkId::new("build_router", route_count),
            &route_count,
            |b, &count| {
                b.iter(|| {
                    let routes: Vec<RouteConfig> = (0..count)
                        .map(|i| RouteConfig {
                            name: format!("route-{i}"),
                            match_criteria: MatchCriteria {
                                port: Some(8000 + i as u16),
                                address: Some(format!("10.0.{}.0", i % 256)),
                                source_cidr: None,
                                catch_all: false,
                            },
                            backends: vec![BackendConfig::new(
                                IpAddr::V4(Ipv4Addr::new(
                                    10,
                                    1,
                                    (i / 256) as u8,
                                    ((i % 254) + 1) as u8,
                                )),
                                9000 + i as u16,
                            )],
                            load_balance: Default::default(),
                        })
                        .collect();

                    let _config = TcpRouterConfig {
                        listeners: vec![],
                        routes,
                        pool: PoolSettings::default(),
                        health_check: Default::default(),
                        max_connections: 10000,
                        connect_timeout_secs: 5,
                        io_timeout_secs: 30,
                        buffer_size: 16384,
                    };
                    black_box(TcpRouter::new());
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// MatchCriteria construction
// ---------------------------------------------------------------------------

fn bench_match_criteria(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_router/match_criteria");

    group.bench_function("construct_port_match", |b| {
        b.iter(|| {
            black_box(MatchCriteria::port(8080));
        });
    });

    group.bench_function("construct_catch_all", |b| {
        b.iter(|| {
            black_box(MatchCriteria::catch_all());
        });
    });

    group.bench_function("construct_full", |b| {
        b.iter(|| {
            black_box(MatchCriteria {
                port: Some(8080),
                address: Some("10.0.0.1".to_string()),
                source_cidr: Some("192.168.0.0/16".to_string()),
                catch_all: false,
            });
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Router stats
// ---------------------------------------------------------------------------

fn bench_router_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_router/stats");

    let router = TcpRouter::new();

    group.bench_function("get_stats", |b| {
        b.iter(|| {
            black_box(router.stats());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Connection pool
// ---------------------------------------------------------------------------

fn bench_connection_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_router/connection_pool");

    group.bench_function("pool_stats", |b| {
        let pool = ConnectionPool::new(PoolSettings {
            enabled: true,
            min_idle: 2,
            max_size: 100,
            idle_timeout_secs: 300,
        });
        b.iter(|| {
            let _ = black_box(pool.stats());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_router_construction,
    bench_match_criteria,
    bench_router_stats,
    bench_connection_pool,
);
criterion_main!(benches);
