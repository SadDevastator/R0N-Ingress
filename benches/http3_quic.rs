#![allow(clippy::all)]
//! Benchmarks for HTTP/3 and QUIC modules.
//!
//! Tests: Frame encoding/decoding, settings construction, frame type handling.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use r0n_ingress::modules::http3::frame::{DataPayload, HeadersPayload};
use r0n_ingress::modules::http3::{Frame, FrameType, Settings};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// Frame encoding / decoding
// ---------------------------------------------------------------------------

fn bench_frame_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("http3/frame_encoding");

    group.bench_function("encode_data_frame", |b| {
        let payload = vec![0u8; 1024];
        let frame = Frame::Data(DataPayload { data: payload });
        b.iter(|| {
            black_box(frame.encode());
        });
    });

    group.bench_function("encode_headers_frame", |b| {
        let headers = vec![0u8; 256]; // Simulated QPACK-encoded headers
        let frame = Frame::Headers(HeadersPayload {
            encoded_headers: headers,
        });
        b.iter(|| {
            black_box(frame.encode());
        });
    });

    group.bench_function("encode_settings_frame", |b| {
        let settings = Settings::default();
        let frame = Frame::Settings(settings);
        b.iter(|| {
            black_box(frame.encode());
        });
    });

    // Varying payload sizes
    for size in [64, 256, 1024, 4096, 16384, 65536] {
        group.bench_with_input(BenchmarkId::new("encode_data", size), &size, |b, &size| {
            let payload = vec![0u8; size];
            let frame = Frame::Data(DataPayload { data: payload });
            b.iter(|| {
                black_box(frame.encode());
            });
        });
    }

    group.finish();
}

fn bench_frame_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("http3/frame_decoding");

    for size in [64, 256, 1024, 4096] {
        group.bench_with_input(BenchmarkId::new("decode_data", size), &size, |b, &size| {
            let payload = vec![0u8; size];
            let frame = Frame::Data(DataPayload { data: payload });
            let encoded = frame.encode();
            b.iter(|| {
                let _ = black_box(Frame::decode(&encoded));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

fn bench_settings(c: &mut Criterion) {
    let mut group = c.benchmark_group("http3/settings");

    group.bench_function("default_settings", |b| {
        b.iter(|| {
            black_box(Settings::default());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Frame type checks
// ---------------------------------------------------------------------------

fn bench_frame_type(c: &mut Criterion) {
    let mut group = c.benchmark_group("http3/frame_type");

    group.bench_function("type_checks", |b| {
        let types = vec![
            FrameType::Data,
            FrameType::Headers,
            FrameType::Settings,
            FrameType::GoAway,
        ];
        b.iter(|| {
            for ft in &types {
                black_box(ft);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_frame_encoding,
    bench_frame_decoding,
    bench_settings,
    bench_frame_type,
);
criterion_main!(benches);
