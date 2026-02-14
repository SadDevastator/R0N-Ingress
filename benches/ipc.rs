#![allow(clippy::all)]
//! Benchmarks for the IPC system.
//!
//! Tests: MessagePack serialization/deserialization, ControlMessage construction,
//! ControlResponse creation, frame encoding/decoding.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use r0n_ingress::ipc::{ControlCommand, ControlMessage, ControlResponse, ResponseStatus};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// ControlMessage serialization
// ---------------------------------------------------------------------------

fn bench_message_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/message_serialization");

    let commands = vec![
        ("start", ControlCommand::Start),
        ("stop", ControlCommand::Stop),
        ("status", ControlCommand::Status),
        ("metrics", ControlCommand::Metrics),
        ("heartbeat", ControlCommand::Heartbeat),
        ("version", ControlCommand::Version),
        ("shutdown", ControlCommand::Shutdown),
        ("pause", ControlCommand::Pause),
        ("resume", ControlCommand::Resume),
    ];

    for (name, cmd) in &commands {
        let msg = ControlMessage::new(1, cmd.clone());

        group.bench_function(format!("serialize_{name}"), |b| {
            b.iter(|| {
                black_box(msg.to_bytes().unwrap());
            });
        });
    }

    // Init with config payload
    group.bench_function("serialize_init_small", |b| {
        let config = vec![0u8; 256];
        let msg = ControlMessage::new(1, ControlCommand::Init { config });
        b.iter(|| {
            black_box(msg.to_bytes().unwrap());
        });
    });

    group.bench_function("serialize_init_large", |b| {
        let config = vec![0u8; 65536];
        let msg = ControlMessage::new(1, ControlCommand::Init { config });
        b.iter(|| {
            black_box(msg.to_bytes().unwrap());
        });
    });

    // Reload with config
    group.bench_function("serialize_reload", |b| {
        let config = vec![0u8; 1024];
        let msg = ControlMessage::new(1, ControlCommand::Reload { config });
        b.iter(|| {
            black_box(msg.to_bytes().unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ControlMessage deserialization
// ---------------------------------------------------------------------------

fn bench_message_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/message_deserialization");

    let commands = vec![
        ("start", ControlCommand::Start),
        ("status", ControlCommand::Status),
        ("heartbeat", ControlCommand::Heartbeat),
    ];

    for (name, cmd) in &commands {
        let msg = ControlMessage::new(42, cmd.clone());
        let bytes = msg.to_bytes().unwrap();

        group.bench_function(format!("deserialize_{name}"), |b| {
            b.iter(|| {
                black_box(ControlMessage::from_bytes(&bytes).unwrap());
            });
        });
    }

    // Large init payload
    group.bench_function("deserialize_init_large", |b| {
        let config = vec![0u8; 65536];
        let msg = ControlMessage::new(1, ControlCommand::Init { config });
        let bytes = msg.to_bytes().unwrap();
        b.iter(|| {
            black_box(ControlMessage::from_bytes(&bytes).unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ControlResponse serialization
// ---------------------------------------------------------------------------

fn bench_response_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/response_serialization");

    group.bench_function("serialize_ok", |b| {
        let resp = ControlResponse::ok(1);
        b.iter(|| {
            black_box(resp.to_bytes().unwrap());
        });
    });

    group.bench_function("serialize_ok_with_payload", |b| {
        let payload = vec![0u8; 1024];
        let resp = ControlResponse::ok_with_payload(1, payload);
        b.iter(|| {
            black_box(resp.to_bytes().unwrap());
        });
    });

    group.bench_function("serialize_error", |b| {
        let resp = ControlResponse::error(1, "Something went wrong");
        b.iter(|| {
            black_box(resp.to_bytes().unwrap());
        });
    });

    group.bench_function("serialize_with_status", |b| {
        let resp = ControlResponse::with_status(1, ResponseStatus::Busy);
        b.iter(|| {
            black_box(resp.to_bytes().unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ControlResponse deserialization
// ---------------------------------------------------------------------------

fn bench_response_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/response_deserialization");

    group.bench_function("deserialize_ok", |b| {
        let bytes = ControlResponse::ok(1).to_bytes().unwrap();
        b.iter(|| {
            black_box(ControlResponse::from_bytes(&bytes).unwrap());
        });
    });

    group.bench_function("deserialize_with_payload", |b| {
        let payload = vec![0u8; 4096];
        let bytes = ControlResponse::ok_with_payload(1, payload)
            .to_bytes()
            .unwrap();
        b.iter(|| {
            black_box(ControlResponse::from_bytes(&bytes).unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ResponseStatus checks
// ---------------------------------------------------------------------------

fn bench_response_status(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/response_status");

    group.bench_function("is_success", |b| {
        let statuses = [
            ResponseStatus::Ok,
            ResponseStatus::Error,
            ResponseStatus::Busy,
            ResponseStatus::NotSupported,
            ResponseStatus::Timeout,
        ];
        b.iter(|| {
            for s in &statuses {
                black_box(s.is_success());
            }
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Message construction throughput
// ---------------------------------------------------------------------------

fn bench_message_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/throughput");

    for batch_size in [10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("roundtrip_batch", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    for i in 0..size as u64 {
                        let msg = ControlMessage::new(i, ControlCommand::Heartbeat);
                        let bytes = msg.to_bytes().unwrap();
                        let decoded = ControlMessage::from_bytes(&bytes).unwrap();
                        let resp = ControlResponse::ok(decoded.id);
                        let resp_bytes = resp.to_bytes().unwrap();
                        let _ = ControlResponse::from_bytes(&resp_bytes).unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

#[cfg(unix)]
criterion_group!(
    benches,
    bench_message_serialization,
    bench_message_deserialization,
    bench_response_serialization,
    bench_response_deserialization,
    bench_response_status,
    bench_message_throughput,
);

#[cfg(not(unix))]
criterion_group!(
    benches,
    bench_message_serialization,
    bench_message_deserialization,
    bench_response_serialization,
    bench_response_deserialization,
    bench_response_status,
    bench_message_throughput,
);

criterion_main!(benches);
