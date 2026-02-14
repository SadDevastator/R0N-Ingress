#![allow(clippy::all)]
//! Benchmarks for the WebSocket Handler module.
//!
//! Tests: Message construction, opcode handling, message serialization.

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion};
use r0n_ingress::modules::websocket_handler::{Message, OpCode};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// Message construction & inspection
// ---------------------------------------------------------------------------

fn bench_message_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("websocket/message");

    group.bench_function("create_text", |b| {
        b.iter(|| {
            black_box(Message::Text("Hello, WebSocket!".into()));
        });
    });

    group.bench_function("create_binary", |b| {
        let data: Bytes = vec![0u8; 1024].into();
        b.iter(|| {
            black_box(Message::Binary(data.clone()));
        });
    });

    group.bench_function("create_ping", |b| {
        b.iter(|| {
            black_box(Message::Ping(vec![1u8, 2, 3, 4].into()));
        });
    });

    group.bench_function("create_pong", |b| {
        b.iter(|| {
            black_box(Message::Pong(vec![1u8, 2, 3, 4].into()));
        });
    });

    group.bench_function("create_close", |b| {
        b.iter(|| {
            black_box(Message::Close(None));
        });
    });

    group.bench_function("large_text_message", |b| {
        let text = "x".repeat(65536);
        b.iter(|| {
            black_box(Message::Text(text.clone().into()));
        });
    });

    group.bench_function("large_binary_message", |b| {
        let data: Bytes = vec![0u8; 65536].into();
        b.iter(|| {
            black_box(Message::Binary(data.clone()));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// OpCode operations
// ---------------------------------------------------------------------------

fn bench_opcode(c: &mut Criterion) {
    let mut group = c.benchmark_group("websocket/opcode");

    group.bench_function("opcode_checks", |b| {
        let opcodes = [
            OpCode::Continuation,
            OpCode::Text,
            OpCode::Binary,
            OpCode::Close,
            OpCode::Ping,
            OpCode::Pong,
        ];
        b.iter(|| {
            for op in &opcodes {
                black_box(op);
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_message_ops, bench_opcode);
criterion_main!(benches);
