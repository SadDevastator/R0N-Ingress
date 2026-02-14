#![allow(clippy::all)]
//! Benchmarks for the TLS Terminator module.
//!
//! Note: The TLS Terminator module does not publicly export CertificateConfig
//! or other necessary types to fully test certificate loading and SNI routing
//! from external code. This benchmark tests the limited public API available.

use criterion::{criterion_group, criterion_main, Criterion};
use r0n_ingress::modules::tls_terminator::{CertificateStore, SniRouter};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// SNI Router (basic operations)
// ---------------------------------------------------------------------------

fn bench_sni_router(c: &mut Criterion) {
    let mut group = c.benchmark_group("tls_terminator/sni_router");

    group.bench_function("create_router", |b| {
        b.iter(|| {
            black_box(SniRouter::new());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Certificate Store (basic operations)
// ---------------------------------------------------------------------------

fn bench_certificate_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("tls_terminator/certificate_store");

    group.bench_function("create_store", |b| {
        b.iter(|| {
            black_box(CertificateStore::new());
        });
    });

    let store = CertificateStore::new();

    group.bench_function("get_nonexistent", |b| {
        b.iter(|| {
            black_box(store.get("nonexistent"));
        });
    });

    group.bench_function("find_by_sni_empty", |b| {
        b.iter(|| {
            black_box(store.find_by_sni("example.com"));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_sni_router, bench_certificate_store);
criterion_main!(benches);
