#![allow(clippy::all)]
//! End-to-End Proxy Benchmark
//!
//! Simulates a full ingress pipeline:
//!   Parse HTTP → ACL check → Rate limit → WAF scan → Route → Middleware → Response
//!
//! Variants:
//!   - TCP proxy (no WAF)
//!   - TLS termination + routing
//!   - WAF enabled with real HTTP payloads
//!   - Full pipeline (all layers)

mod common;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use common::generators;

use r0n_ingress::modules::access_control::{
    IpFilter, IpFilterConfig, IpRule, RuleAction as AclAction,
};
use r0n_ingress::modules::http_handler::request::Request;
use r0n_ingress::modules::http_handler::HttpHandler;
use r0n_ingress::modules::l4_passthrough::{ConnectionState, ConnectionTracker};
use r0n_ingress::modules::rate_limiting::TokenBucket;
use r0n_ingress::modules::tls_terminator::{CertificateStore, SniRouter};
use r0n_ingress::modules::waf::{RuleEngine, ScanContext};

// ─── Reusable pipeline components ────────────────────────────────────────────

/// Pre-built pipeline for benchmarks.
struct ProxyPipeline {
    ip_filter: IpFilter,
    rate_bucket: TokenBucket,
    waf_engine: RuleEngine,
    http_handler: HttpHandler,
    tracker: ConnectionTracker,
    sni_router: SniRouter,
}

impl ProxyPipeline {
    fn new() -> Self {
        // ACL: allow everything except 10.66.0.0/16
        let ip_config = IpFilterConfig {
            enabled: true,
            rules: vec![
                IpRule::deny(vec!["10.66.0.0/16".to_string()]).with_priority(10),
                IpRule::allow(vec!["0.0.0.0/0".to_string()]).with_priority(0),
            ],
            default_action: AclAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: vec![],
        };

        Self {
            ip_filter: IpFilter::new(ip_config).unwrap(),
            rate_bucket: TokenBucket::with_defaults(),
            waf_engine: RuleEngine::default_config(),
            http_handler: HttpHandler::new(),
            tracker: ConnectionTracker::new(),
            sni_router: SniRouter::new(),
        }
    }

    fn with_large_acl() -> Self {
        let cidrs = generators::cidr_ranges(500);
        let ip_config = IpFilterConfig {
            enabled: true,
            rules: cidrs
                .into_iter()
                .enumerate()
                .map(|(i, cidr)| IpRule {
                    name: None,
                    addresses: vec![cidr],
                    action: if i % 5 == 0 {
                        AclAction::Deny
                    } else {
                        AclAction::Allow
                    },
                    priority: i as i32,
                })
                .collect(),
            default_action: AclAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: vec![],
        };

        Self {
            ip_filter: IpFilter::new(ip_config).unwrap(),
            rate_bucket: TokenBucket::with_defaults(),
            waf_engine: RuleEngine::default_config(),
            http_handler: HttpHandler::new(),
            tracker: ConnectionTracker::new(),
            sni_router: SniRouter::new(),
        }
    }
}

// ─── Test payload sets ───────────────────────────────────────────────────────

struct TrafficMix {
    benign_requests: Vec<Vec<u8>>,
    malicious_requests: Vec<Vec<u8>>,
    client_ips: Vec<String>,
}

impl TrafficMix {
    fn generate(benign_count: usize) -> Self {
        let benign_requests = generators::http_request_batch(benign_count);

        let sqli = generators::sqli_payloads();
        let xss = generators::xss_payloads();
        let traversal = generators::path_traversal_payloads();

        let mut malicious_requests = Vec::new();
        for payload in sqli.iter().chain(xss.iter()).chain(traversal.iter()) {
            malicious_requests.push(generators::http_post_request(
                "/api/v1/login",
                "api.example.com",
                payload,
            ));
        }

        Self {
            benign_requests,
            malicious_requests,
            client_ips: generators::random_ipv4_addresses(200),
        }
    }

    fn request_at(&self, idx: usize) -> &[u8] {
        let total = self.benign_requests.len() + self.malicious_requests.len();
        let i = idx % total;
        if i < self.benign_requests.len() {
            &self.benign_requests[i]
        } else {
            &self.malicious_requests[i - self.benign_requests.len()]
        }
    }

    fn ip_at(&self, idx: usize) -> &str {
        &self.client_ips[idx % self.client_ips.len()]
    }
}

// ─── TCP proxy (no WAF) ─────────────────────────────────────────────────────

fn bench_tcp_proxy_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("e2e/tcp_proxy");
    group.measurement_time(Duration::from_secs(10));

    let pipeline = ProxyPipeline::new();
    let mix = TrafficMix::generate(200);

    // Parse → ACL check → Track connection → Route
    group.bench_function("parse_acl_track_route", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let raw = mix.request_at(idx);
            let ip = mix.ip_at(idx);
            idx += 1;

            // 1. ACL check
            let _ = black_box(pipeline.ip_filter.check(ip));

            // 2. Track connection
            let client = SocketAddr::new(
                ip.parse::<IpAddr>()
                    .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                10000 + (idx as u16 % 50000),
            );
            let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
            let conn_id = pipeline
                .tracker
                .track_connection(client, backend, "default".to_string());

            // 3. Parse HTTP request
            if let Ok((req, _)) = Request::parse(raw) {
                // 4. Route
                let _ = black_box(pipeline.http_handler.router().route(&req));
            }

            // 5. Teardown
            pipeline
                .tracker
                .update_state(conn_id, ConnectionState::Active);
            pipeline
                .tracker
                .update_bytes(conn_id, raw.len() as u64, 256);
            pipeline.tracker.remove_connection(conn_id);
        });
    });

    group.bench_function("parse_acl_ratelimit_route", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let raw = mix.request_at(idx);
            let ip = mix.ip_at(idx);
            idx += 1;

            // 1. ACL
            let _ = black_box(pipeline.ip_filter.check(ip));

            // 2. Rate limit
            let _ = black_box(pipeline.rate_bucket.try_consume(1));

            // 3. Parse + route
            if let Ok((req, _)) = Request::parse(raw) {
                let _ = black_box(pipeline.http_handler.router().route(&req));
            }
        });
    });

    group.finish();
}

// ─── TLS termination pipeline ────────────────────────────────────────────────

fn bench_tls_termination_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("e2e/tls_termination");
    group.measurement_time(Duration::from_secs(10));

    let pipeline = ProxyPipeline::new();
    let mix = TrafficMix::generate(200);
    let domains = [
        "api.example.com",
        "web.example.com",
        "cdn.example.com",
        "admin.example.com",
    ];
    let cert_store = CertificateStore::new();

    group.bench_function("sni_resolve_acl_parse_route", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let raw = mix.request_at(idx);
            let ip = mix.ip_at(idx);
            let domain = domains[idx % domains.len()];
            idx += 1;

            // 1. SNI resolution
            let _ = black_box(pipeline.sni_router.resolve(domain));

            // 2. Certificate lookup
            let _ = black_box(cert_store.find_by_sni(domain));

            // 3. ACL check
            let _ = black_box(pipeline.ip_filter.check(ip));

            // 4. Parse HTTP
            if let Ok((req, _)) = Request::parse(raw) {
                let _ = black_box(pipeline.http_handler.router().route(&req));
            }
        });
    });

    group.finish();
}

// ─── WAF-enabled pipeline ────────────────────────────────────────────────────

fn bench_waf_enabled_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("e2e/waf_enabled");
    group.measurement_time(Duration::from_secs(15));

    let pipeline = ProxyPipeline::new();
    let mix = TrafficMix::generate(200);

    // Full pipeline: ACL → Rate limit → Parse → WAF → Route
    group.bench_function("full_pipeline_benign", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let raw = &mix.benign_requests[idx % mix.benign_requests.len()];
            let ip = mix.ip_at(idx);
            idx += 1;

            // 1. ACL
            let _ = pipeline.ip_filter.check(ip);

            // 2. Rate limit
            let _ = pipeline.rate_bucket.try_consume(1);

            // 3. Parse
            if let Ok((req, _)) = Request::parse(raw) {
                // 4. WAF scan
                let scan_ctx = ScanContext::new()
                    .with_method(req.method().as_str())
                    .with_uri(req.path());
                let _ = black_box(pipeline.waf_engine.scan(&scan_ctx));

                // 5. Route
                let _ = black_box(pipeline.http_handler.router().route(&req));
            }
        });
    });

    group.bench_function("full_pipeline_malicious", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let raw = &mix.malicious_requests[idx % mix.malicious_requests.len()];
            let ip = mix.ip_at(idx);
            idx += 1;

            let _ = pipeline.ip_filter.check(ip);

            let _ = pipeline.rate_bucket.try_consume(1);

            if let Ok((req, _)) = Request::parse(raw) {
                let body_str = String::from_utf8_lossy(req.body());
                let scan_ctx = ScanContext::new()
                    .with_method(req.method().as_str())
                    .with_uri(req.path())
                    .with_body(body_str.as_ref());
                let scan_result = pipeline.waf_engine.scan(&scan_ctx);
                black_box(&scan_result);

                // Only route if WAF allows
                if let Ok(ref result) = scan_result {
                    if !result.blocked {
                        let _ = black_box(pipeline.http_handler.router().route(&req));
                    }
                }
            }
        });
    });

    // Mixed traffic: 80% benign, 20% malicious
    group.bench_function("full_pipeline_mixed_80_20", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let is_malicious = idx % 5 == 0;
            let raw = if is_malicious {
                &mix.malicious_requests[idx % mix.malicious_requests.len()]
            } else {
                &mix.benign_requests[idx % mix.benign_requests.len()]
            };
            let ip = mix.ip_at(idx);
            idx += 1;

            let _ = pipeline.ip_filter.check(ip);

            let _ = pipeline.rate_bucket.try_consume(1);

            if let Ok((req, _)) = Request::parse(raw) {
                let body_str = String::from_utf8_lossy(req.body());
                let scan_ctx = ScanContext::new()
                    .with_method(req.method().as_str())
                    .with_uri(req.path())
                    .with_body(body_str.as_ref());
                let scan_result = pipeline.waf_engine.scan(&scan_ctx);

                if let Ok(ref result) = scan_result {
                    if !result.blocked {
                        let _ = black_box(pipeline.http_handler.router().route(&req));
                    }
                }
            }
        });
    });

    // Large ACL (500 rules) + WAF
    group.bench_function("large_acl_waf_pipeline", |b| {
        let big_pipeline = ProxyPipeline::with_large_acl();
        let mut idx = 0usize;
        b.iter(|| {
            let raw = mix.request_at(idx);
            let ip = mix.ip_at(idx);
            idx += 1;

            let _ = big_pipeline.ip_filter.check(ip);

            if let Ok((req, _)) = Request::parse(raw) {
                let scan_ctx = ScanContext::new()
                    .with_method(req.method().as_str())
                    .with_uri(req.path());
                let _ = black_box(big_pipeline.waf_engine.scan(&scan_ctx));
                let _ = black_box(big_pipeline.http_handler.router().route(&req));
            }
        });
    });

    group.finish();
}

// ─── Throughput measurement ──────────────────────────────────────────────────

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("e2e/throughput");
    group.measurement_time(Duration::from_secs(15));

    let pipeline = ProxyPipeline::new();

    for batch_size in [100, 500, 1000] {
        let requests = generators::http_request_batch(batch_size);
        let ips = generators::random_ipv4_addresses(batch_size);

        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("batch_full_pipeline", batch_size),
            &batch_size,
            |b, &_size| {
                b.iter(|| {
                    for (i, raw) in requests.iter().enumerate() {
                        let ip = &ips[i];
                        let _ = pipeline.ip_filter.check(ip);

                        if let Ok((req, _)) = Request::parse(raw) {
                            let scan_ctx = ScanContext::new()
                                .with_method(req.method().as_str())
                                .with_uri(req.path());
                            let _ = pipeline.waf_engine.scan(&scan_ctx);
                            let _ = black_box(pipeline.http_handler.router().route(&req));
                        }
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_tcp_proxy_pipeline,
    bench_tls_termination_pipeline,
    bench_waf_enabled_pipeline,
    bench_throughput,
);
criterion_main!(benches);
