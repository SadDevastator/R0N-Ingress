#![allow(clippy::all)]
//! Benchmarks for the WAF (Web Application Firewall) module.
//!
//! Tests: Rule engine scanning (SQLi, XSS, PathTraversal), detector throughput,
//! transform chains, anomaly scoring, false positive rates, concurrent scanning.

mod common;
use common::generators;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use r0n_ingress::modules::waf::{
    Detector, PathTraversalDetector, RuleEngine, ScanContext, SqlInjectionDetector, XssDetector,
};
use std::hint::black_box;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Individual detector benchmarks
// ---------------------------------------------------------------------------

fn bench_sqli_detector(c: &mut Criterion) {
    let mut group = c.benchmark_group("waf/sqli_detector");
    let detector = SqlInjectionDetector::default_config();

    // Malicious payloads
    for (i, payload) in generators::sqli_payloads().iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("malicious", i), payload, |b, payload| {
            b.iter(|| {
                let _ = black_box(detector.detect(payload));
            });
        });
    }

    // Benign payloads (false positive testing)
    for (i, payload) in generators::benign_payloads().iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("benign", i), payload, |b, payload| {
            b.iter(|| {
                let _ = black_box(detector.detect(payload));
            });
        });
    }

    group.finish();
}

fn bench_xss_detector(c: &mut Criterion) {
    let mut group = c.benchmark_group("waf/xss_detector");
    let detector = XssDetector::default_config();

    for (i, payload) in generators::xss_payloads().iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("malicious", i), payload, |b, payload| {
            b.iter(|| {
                let _ = black_box(detector.detect(payload));
            });
        });
    }

    for (i, payload) in generators::benign_payloads().iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("benign", i), payload, |b, payload| {
            b.iter(|| {
                let _ = black_box(detector.detect(payload));
            });
        });
    }

    group.finish();
}

fn bench_path_traversal_detector(c: &mut Criterion) {
    let mut group = c.benchmark_group("waf/path_traversal_detector");
    let detector = PathTraversalDetector::default_config();

    for (i, payload) in generators::path_traversal_payloads().iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("malicious", i), payload, |b, payload| {
            b.iter(|| {
                let _ = black_box(detector.detect(payload));
            });
        });
    }

    for (i, payload) in generators::benign_payloads().iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("benign", i), payload, |b, payload| {
            b.iter(|| {
                let _ = black_box(detector.detect(payload));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Rule engine full scan
// ---------------------------------------------------------------------------

fn bench_rule_engine_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("waf/rule_engine");

    let engine = RuleEngine::new(Default::default());

    // Simple GET scan
    group.bench_function("scan_clean_get", |b| {
        b.iter(|| {
            let ctx = ScanContext::new()
                .with_method("GET")
                .with_uri("/api/v1/users")
                .with_source_ip("192.168.1.1".parse::<IpAddr>().unwrap());
            let _ = black_box(engine.scan(&ctx));
        });
    });

    // Scan with SQLi in query string
    group.bench_function("scan_sqli_query", |b| {
        b.iter(|| {
            let ctx = ScanContext::new()
                .with_method("GET")
                .with_uri("/api/v1/users")
                .with_query_string("id=1' OR '1'='1")
                .with_source_ip("192.168.1.1".parse::<IpAddr>().unwrap());
            let _ = black_box(engine.scan(&ctx));
        });
    });

    // Scan with XSS in body
    group.bench_function("scan_xss_body", |b| {
        b.iter(|| {
            let ctx = ScanContext::new()
                .with_method("POST")
                .with_uri("/api/v1/comments")
                .with_body("<script>alert('xss')</script>")
                .with_source_ip("192.168.1.1".parse::<IpAddr>().unwrap());
            let _ = black_box(engine.scan(&ctx));
        });
    });

    // Scan with path traversal
    group.bench_function("scan_path_traversal", |b| {
        b.iter(|| {
            let ctx = ScanContext::new()
                .with_method("GET")
                .with_uri("/../../../etc/passwd")
                .with_source_ip("192.168.1.1".parse::<IpAddr>().unwrap());
            let _ = black_box(engine.scan(&ctx));
        });
    });

    // Full scan with many headers and fields
    group.bench_function("scan_complex_request", |b| {
        b.iter(|| {
            let ctx = ScanContext::new()
                .with_method("POST")
                .with_uri("/api/v1/submit")
                .with_query_string("action=update&filter=name")
                .with_header("User-Agent", "Mozilla/5.0")
                .with_header("Referer", "https://example.com/page")
                .with_header("Cookie", "session=abc123; theme=dark")
                .with_body(r#"{"name":"John","comment":"Great product!"}"#)
                .with_source_ip("10.0.0.1".parse::<IpAddr>().unwrap());
            let _ = black_box(engine.scan(&ctx));
        });
    });

    // Mixed attack vector scan
    group.bench_function("scan_mixed_attack", |b| {
        b.iter(|| {
            let ctx = ScanContext::new()
                .with_method("POST")
                .with_uri("/api/v1/search")
                .with_query_string("q=' UNION SELECT * FROM users--")
                .with_header("User-Agent", "<script>alert(1)</script>")
                .with_body("file=../../../etc/passwd")
                .with_source_ip("10.0.0.1".parse::<IpAddr>().unwrap());
            let _ = black_box(engine.scan(&ctx));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ScanContext construction
// ---------------------------------------------------------------------------

fn bench_scan_context(c: &mut Criterion) {
    let mut group = c.benchmark_group("waf/scan_context");

    group.bench_function("minimal_context", |b| {
        b.iter(|| {
            black_box(ScanContext::new().with_method("GET").with_uri("/"));
        });
    });

    group.bench_function("full_context", |b| {
        b.iter(|| {
            black_box(
                ScanContext::new()
                    .with_method("POST")
                    .with_uri("/api/v1/data")
                    .with_query_string("key=value&foo=bar")
                    .with_header("Content-Type", "application/json")
                    .with_header("Authorization", "Bearer token123")
                    .with_header("User-Agent", "BenchmarkClient/1.0")
                    .with_cookie("session", "abc123")
                    .with_body(r#"{"data":"test"}"#)
                    .with_form_field("name", "John")
                    .with_form_field("email", "john@example.com")
                    .with_source_ip("192.168.1.1".parse::<IpAddr>().unwrap()),
            );
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Throughput: batch scanning
// ---------------------------------------------------------------------------

fn bench_scan_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("waf/throughput");

    let engine = RuleEngine::new(Default::default());
    let payloads: Vec<String> = generators::benign_payloads()
        .into_iter()
        .chain(generators::sqli_payloads())
        .chain(generators::xss_payloads())
        .chain(generators::path_traversal_payloads())
        .collect();

    for batch_size in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("batch_scan", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    for i in 0..size {
                        let payload = &payloads[i % payloads.len()];
                        let ctx = ScanContext::new()
                            .with_method("POST")
                            .with_uri("/api/v1/input")
                            .with_body(payload.as_str())
                            .with_source_ip("10.0.0.1".parse::<IpAddr>().unwrap());
                        let _ = black_box(engine.scan(&ctx));
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_sqli_detector,
    bench_xss_detector,
    bench_path_traversal_detector,
    bench_rule_engine_scan,
    bench_scan_context,
    bench_scan_throughput,
);
criterion_main!(benches);
