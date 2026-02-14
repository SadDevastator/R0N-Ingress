#![allow(clippy::all)]
//! Benchmarks for the L4 Passthrough module.
//!
//! Tests: Connection tracking, connection state transitions,
//! connection info construction.

use criterion::{criterion_group, criterion_main, Criterion};
use r0n_ingress::modules::l4_passthrough::{ConnectionInfo, ConnectionState, ConnectionTracker};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// ---------------------------------------------------------------------------
// Connection tracking
// ---------------------------------------------------------------------------

fn bench_connection_tracker(c: &mut Criterion) {
    let mut group = c.benchmark_group("l4_passthrough/connection_tracker");

    let tracker = ConnectionTracker::new();

    group.bench_function("track_connection", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            idx += 1;
            let client = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, ((idx % 254) + 1) as u8)),
                (10000 + (idx % 50000)) as u16,
            );
            let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
            black_box(tracker.track_connection(client, backend, "default".to_string()));
        });
    });

    group.bench_function("get_connection", |b| {
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let id = tracker.track_connection(client, backend, "default".to_string());
        b.iter(|| {
            black_box(tracker.get_connection(id));
        });
    });

    group.bench_function("active_connections", |b| {
        b.iter(|| {
            black_box(tracker.active_connections());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Connection state transitions
// ---------------------------------------------------------------------------

fn bench_connection_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("l4_passthrough/connection_state");

    group.bench_function("state_transitions", |b| {
        b.iter(|| {
            black_box(ConnectionState::Connecting);
            black_box(ConnectionState::Active);
            black_box(ConnectionState::Idle);
            black_box(ConnectionState::Closing);
            black_box(ConnectionState::Closed);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ConnectionInfo construction
// ---------------------------------------------------------------------------

fn bench_connection_info(c: &mut Criterion) {
    let mut group = c.benchmark_group("l4_passthrough/connection_info");

    group.bench_function("create_info", |b| {
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345);
        let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        b.iter(|| {
            black_box(ConnectionInfo::new(
                1,
                client,
                backend,
                "default".to_string(),
            ));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_connection_tracker,
    bench_connection_state,
    bench_connection_info,
);
criterion_main!(benches);
