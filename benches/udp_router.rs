#![allow(clippy::all)]
//! Benchmarks for UDP Router module.
//!
//! Tests: Session creation/lookup/cleanup, datagram forwarding stats,
//! session manager throughput.

use criterion::{criterion_group, criterion_main, Criterion};
use r0n_ingress::modules::udp_router::{SessionId, SessionManager, SessionSettings};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// ---------------------------------------------------------------------------
// Session manager
// ---------------------------------------------------------------------------

fn bench_session_manager(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_router/session_manager");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let settings = SessionSettings::default();
    let manager = SessionManager::new(settings);

    // Session creation (async)
    group.bench_function("create_session", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            idx += 1;
            let client = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, ((idx % 254) + 1) as u8)),
                (10000 + (idx % 50000)) as u16,
            );
            let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);
            let id = SessionId::new(client, local);
            let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9090);
            black_box(rt.block_on(manager.create_session(id, backend, "default".to_string())));
        });
    });

    // Session lookup (existing)
    group.bench_function("get_session_existing", |b| {
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);
        let id = SessionId::new(client, local);
        let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9090);
        rt.block_on(manager.create_session(id.clone(), backend, "default".to_string()));
        b.iter(|| {
            black_box(rt.block_on(manager.get_session(&id)));
        });
    });

    // Session lookup (missing)
    group.bench_function("get_session_missing", |b| {
        let missing_id = SessionId::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 65535),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080),
        );
        b.iter(|| {
            black_box(rt.block_on(manager.get_session(&missing_id)));
        });
    });

    // Cleanup
    group.bench_function("cleanup", |b| {
        b.iter(|| {
            black_box(rt.block_on(manager.cleanup()));
        });
    });

    // Session count
    group.bench_function("session_count", |b| {
        b.iter(|| {
            black_box(rt.block_on(manager.session_count()));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// UDP router construction
// ---------------------------------------------------------------------------

fn bench_udp_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_router/construction");

    group.bench_function("session_settings_default", |b| {
        b.iter(|| {
            black_box(SessionSettings::default());
        });
    });

    group.bench_function("session_id_new", |b| {
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);
        b.iter(|| {
            black_box(SessionId::new(client, local));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_session_manager, bench_udp_construction);
criterion_main!(benches);
