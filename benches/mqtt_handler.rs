#![allow(clippy::all)]
//! Benchmarks for the MQTT Handler module.
//!
//! Tests: Packet construction, topic matching (exact, single-level +, multi-level #),
//! QoS handling, session overhead.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use r0n_ingress::modules::mqtt_handler::packet::Publish;
use r0n_ingress::modules::mqtt_handler::{MqttPacket, QoS, TopicFilter, TopicName};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// Topic matching
// ---------------------------------------------------------------------------

fn bench_topic_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("mqtt/topic_matching");

    // Exact match
    group.bench_function("exact_match", |b| {
        let filter = TopicFilter::new("home/livingroom/temperature").unwrap();
        let topic = TopicName::new("home/livingroom/temperature").unwrap();
        b.iter(|| {
            black_box(filter.matches(&topic));
        });
    });

    // Single-level wildcard
    group.bench_function("single_wildcard", |b| {
        let filter = TopicFilter::new("home/+/temperature").unwrap();
        let topic = TopicName::new("home/livingroom/temperature").unwrap();
        b.iter(|| {
            black_box(filter.matches(&topic));
        });
    });

    // Multi-level wildcard
    group.bench_function("multi_wildcard", |b| {
        let filter = TopicFilter::new("home/#").unwrap();
        let topic = TopicName::new("home/livingroom/temperature/celsius").unwrap();
        b.iter(|| {
            black_box(filter.matches(&topic));
        });
    });

    // No match
    group.bench_function("no_match", |b| {
        let filter = TopicFilter::new("home/kitchen/temperature").unwrap();
        let topic = TopicName::new("home/livingroom/temperature").unwrap();
        b.iter(|| {
            black_box(filter.matches(&topic));
        });
    });

    // Complex topic hierarchy
    group.bench_function("deep_topic", |b| {
        let filter = TopicFilter::new("a/+/c/+/e/+/g").unwrap();
        let topic = TopicName::new("a/b/c/d/e/f/g").unwrap();
        b.iter(|| {
            black_box(filter.matches(&topic));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Topic construction
// ---------------------------------------------------------------------------

fn bench_topic_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("mqtt/topic_construction");

    group.bench_function("topic_name_new", |b| {
        b.iter(|| {
            black_box(TopicName::new("home/livingroom/temperature").unwrap());
        });
    });

    group.bench_function("topic_filter_new", |b| {
        b.iter(|| {
            black_box(TopicFilter::new("home/+/temperature").unwrap());
        });
    });

    group.bench_function("topic_filter_complex", |b| {
        b.iter(|| {
            black_box(TopicFilter::new("sensor/+/data/+/raw/#").unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Packet construction
// ---------------------------------------------------------------------------

fn bench_packet_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("mqtt/packet");

    group.bench_function("create_publish_qos0", |b| {
        b.iter(|| {
            black_box(MqttPacket::Publish(Publish::new(
                "sensor/temperature",
                &b"22.5"[..],
            )));
        });
    });

    group.bench_function("create_publish_qos1", |b| {
        b.iter(|| {
            black_box(MqttPacket::Publish(
                Publish::new("sensor/temperature", &b"22.5"[..]).with_qos(QoS::AtLeastOnce, 1),
            ));
        });
    });

    group.bench_function("create_publish_qos2", |b| {
        b.iter(|| {
            black_box(MqttPacket::Publish(
                Publish::new("sensor/temperature", &b"22.5"[..]).with_qos(QoS::ExactlyOnce, 1),
            ));
        });
    });

    group.bench_function("create_publish_large_payload", |b| {
        b.iter_with_setup(
            || vec![0u8; 65536],
            |payload| {
                black_box(MqttPacket::Publish(
                    Publish::new("data/bulk", payload).with_qos(QoS::AtLeastOnce, 1),
                ));
            },
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// QoS operations
// ---------------------------------------------------------------------------

fn bench_qos(c: &mut Criterion) {
    let mut group = c.benchmark_group("mqtt/qos");

    group.bench_function("qos_comparison", |b| {
        let levels = [QoS::AtMostOnce, QoS::AtLeastOnce, QoS::ExactlyOnce];
        b.iter(|| {
            for qos in &levels {
                black_box(qos);
            }
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Batch topic matching (throughput)
// ---------------------------------------------------------------------------

fn bench_topic_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("mqtt/throughput");

    let filters: Vec<TopicFilter> = vec![
        TopicFilter::new("home/+/temperature").unwrap(),
        TopicFilter::new("sensor/#").unwrap(),
        TopicFilter::new("device/+/status").unwrap(),
        TopicFilter::new("alert/+/+/critical").unwrap(),
        TopicFilter::new("data/raw/#").unwrap(),
    ];
    let topics: Vec<TopicName> = vec![
        TopicName::new("home/livingroom/temperature").unwrap(),
        TopicName::new("sensor/gps/location/lat").unwrap(),
        TopicName::new("device/thermostat/status").unwrap(),
        TopicName::new("data/raw/csv/stream").unwrap(),
    ];

    for batch_size in [10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("batch_match", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    for i in 0..size {
                        let filter = &filters[i % filters.len()];
                        let topic = &topics[i % topics.len()];
                        black_box(filter.matches(topic));
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_topic_matching,
    bench_topic_construction,
    bench_packet_construction,
    bench_qos,
    bench_topic_throughput,
);
criterion_main!(benches);
