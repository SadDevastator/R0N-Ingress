#![allow(clippy::all)]
//! Concurrency Test Benchmark
//!
//! Tests the full proxy pipeline under concurrent load:
//!   - 1k simultaneous connections
//!   - 10k simultaneous connections
//!   - Keep-alive connection reuse
//!   - Mixed benign + malicious traffic under contention
//!   - RwLock/cache contention on IpFilter
//!   - Rate limiter contention across threads

mod common;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::generators;
use common::harness::bench_runtime;

use r0n_ingress::modules::access_control::{
    IpFilter, IpFilterConfig, IpRule, RuleAction as AclAction,
};
use r0n_ingress::modules::http_handler::request::Request;
use r0n_ingress::modules::http_handler::HttpHandler;
use r0n_ingress::modules::l4_passthrough::{ConnectionState, ConnectionTracker};
use r0n_ingress::modules::rate_limiting::TokenBucket;
use r0n_ingress::modules::waf::{RuleEngine, ScanContext};

// ─── Shared pipeline for concurrent tests ────────────────────────────────────

struct SharedPipeline {
    ip_filter: Arc<IpFilter>,
    rate_bucket: Arc<TokenBucket>,
    waf_engine: Arc<RuleEngine>,
    http_handler: Arc<HttpHandler>,
    tracker: Arc<ConnectionTracker>,
}

impl SharedPipeline {
    fn new(acl_rules: usize) -> Self {
        let cidrs = generators::cidr_ranges(acl_rules);
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
            ip_filter: Arc::new(IpFilter::new(ip_config).unwrap()),
            rate_bucket: Arc::new(TokenBucket::with_defaults()),
            waf_engine: Arc::new(RuleEngine::default_config()),
            http_handler: Arc::new(HttpHandler::new()),
            tracker: Arc::new(ConnectionTracker::new()),
        }
    }
}

// ─── Connection lifecycle under concurrency ──────────────────────────────────

fn bench_concurrent_connections(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrency/connections");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    let pipeline = SharedPipeline::new(200);

    for conn_count in [1_000, 10_000] {
        let ips = Arc::new(generators::random_ipv4_addresses(conn_count));
        let requests = Arc::new(generators::http_request_batch(conn_count.min(500)));

        // Pure connection tracking: track + ACL + teardown
        group.throughput(Throughput::Elements(conn_count as u64));
        group.bench_with_input(
            BenchmarkId::new("track_acl_teardown", conn_count),
            &conn_count,
            |b, &count| {
                let rt = bench_runtime();
                let tracker = Arc::clone(&pipeline.tracker);
                let filter = Arc::clone(&pipeline.ip_filter);
                let addrs = Arc::clone(&ips);
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(count);
                        for t in 0..count {
                            let trk = Arc::clone(&tracker);
                            let flt = Arc::clone(&filter);
                            let all_ips = Arc::clone(&addrs);
                            handles.push(tokio::spawn(async move {
                                let ip = &all_ips[t];
                                let _ = flt.check(ip);
                                let client = SocketAddr::new(
                                    ip.parse::<IpAddr>()
                                        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                                    10000 + (t as u16 % 55000),
                                );
                                let backend = SocketAddr::new(
                                    IpAddr::V4(Ipv4Addr::new(
                                        10,
                                        0,
                                        (t / 256) as u8,
                                        (t % 254 + 1) as u8,
                                    )),
                                    8080,
                                );
                                let id = trk.track_connection(client, backend, "default".into());
                                trk.update_state(id, ConnectionState::Active);
                                trk.update_bytes(id, 1024, 512);
                                trk.update_state(id, ConnectionState::Closed);
                                trk.remove_connection(id);
                            }));
                        }
                        for h in handles {
                            let _ = h.await;
                        }
                    });
                });
            },
        );

        // Full pipeline: ACL → rate limit → parse → WAF → route → teardown
        group.bench_with_input(
            BenchmarkId::new("full_pipeline", conn_count),
            &conn_count,
            |b, &count| {
                let rt = bench_runtime();
                let pl = SharedPipeline::new(200);
                let addrs = Arc::clone(&ips);
                let reqs = Arc::clone(&requests);
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(count);
                        for t in 0..count {
                            let flt = Arc::clone(&pl.ip_filter);
                            let rl = Arc::clone(&pl.rate_bucket);
                            let waf = Arc::clone(&pl.waf_engine);
                            let hh = Arc::clone(&pl.http_handler);
                            let trk = Arc::clone(&pl.tracker);
                            let all_ips = Arc::clone(&addrs);
                            let all_reqs = Arc::clone(&reqs);
                            handles.push(tokio::spawn(async move {
                                let ip = &all_ips[t];

                                // ACL
                                let _ = flt.check(ip);

                                // Rate limit
                                let _ = rl.try_consume(1);

                                // Parse
                                let raw = &all_reqs[t % all_reqs.len()];
                                if let Ok((req, _)) = Request::parse(raw) {
                                    // WAF
                                    let scan_ctx = ScanContext::new()
                                        .with_method(req.method().as_str())
                                        .with_uri(req.path());
                                    let _ = waf.scan(&scan_ctx);

                                    // Route
                                    let _ = black_box(hh.router().route(&req));
                                }

                                // Connection lifecycle
                                let client = SocketAddr::new(
                                    ip.parse::<IpAddr>()
                                        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                                    10000 + (t as u16 % 55000),
                                );
                                let backend =
                                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
                                let id = trk.track_connection(client, backend, "default".into());
                                trk.update_state(id, ConnectionState::Active);
                                trk.update_bytes(id, 1024, 256);
                                trk.update_state(id, ConnectionState::Closed);
                                trk.remove_connection(id);
                            }));
                        }
                        for h in handles {
                            let _ = h.await;
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

// ─── Keep-alive connection reuse ─────────────────────────────────────────────

fn bench_keepalive(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrency/keepalive");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(15));

    let pipeline = SharedPipeline::new(100);

    // Simulate keep-alive: same connection serves N requests
    for requests_per_conn in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("reqs_per_conn", requests_per_conn),
            &requests_per_conn,
            |b, &rpc| {
                let requests = generators::http_request_batch(rpc);
                let ip = "192.168.1.50";
                let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 45000);
                let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
                let filter = Arc::clone(&pipeline.ip_filter);
                let waf = Arc::clone(&pipeline.waf_engine);
                let hh = Arc::clone(&pipeline.http_handler);
                let tracker = Arc::clone(&pipeline.tracker);

                b.iter(|| {
                    // 1. Track connection once (keep-alive)
                    let conn_id = tracker.track_connection(client, backend, "default".into());
                    tracker.update_state(conn_id, ConnectionState::Active);

                    // 2. ACL check once per connection
                    let _ = filter.check(ip);

                    // 3. Serve N requests over the same connection
                    for raw in &requests {
                        if let Ok((req, _)) = Request::parse(raw) {
                            // WAF per request
                            let scan_ctx = ScanContext::new()
                                .with_method(req.method().as_str())
                                .with_uri(req.path());
                            let _ = waf.scan(&scan_ctx);

                            // Route
                            let _ = black_box(hh.router().route(&req));

                            // Update bytes
                            tracker.update_bytes(conn_id, raw.len() as u64, 256);
                        }
                    }

                    // 4. Teardown
                    tracker.update_state(conn_id, ConnectionState::Closed);
                    tracker.remove_connection(conn_id);
                });
            },
        );
    }

    // Concurrent keep-alive connections
    for concurrent_conns in [100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("concurrent_keepalive", concurrent_conns),
            &concurrent_conns,
            |b, &conns| {
                let rt = bench_runtime();
                let rpc = 20; // requests per connection
                let all_requests = Arc::new(generators::http_request_batch(rpc));
                let all_ips = Arc::new(generators::random_ipv4_addresses(conns));
                let pl = SharedPipeline::new(100);

                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(conns);
                        for t in 0..conns {
                            let flt = Arc::clone(&pl.ip_filter);
                            let waf = Arc::clone(&pl.waf_engine);
                            let hh = Arc::clone(&pl.http_handler);
                            let trk = Arc::clone(&pl.tracker);
                            let reqs = Arc::clone(&all_requests);
                            let ips = Arc::clone(&all_ips);
                            handles.push(tokio::spawn(async move {
                                let ip = &ips[t];
                                let client = SocketAddr::new(
                                    ip.parse::<IpAddr>()
                                        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                                    10000 + t as u16,
                                );
                                let backend =
                                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);

                                let id = trk.track_connection(client, backend, "default".into());
                                trk.update_state(id, ConnectionState::Active);
                                let _ = flt.check(ip);

                                for raw in reqs.iter() {
                                    if let Ok((req, _)) = Request::parse(raw) {
                                        let scan_ctx = ScanContext::new()
                                            .with_method(req.method().as_str())
                                            .with_uri(req.path());
                                        let _ = waf.scan(&scan_ctx);
                                        let _ = black_box(hh.router().route(&req));
                                    }
                                    trk.update_bytes(id, raw.len() as u64, 256);
                                }

                                trk.update_state(id, ConnectionState::Closed);
                                trk.remove_connection(id);
                            }));
                        }
                        for h in handles {
                            let _ = h.await;
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

// ─── Mixed traffic under contention ──────────────────────────────────────────

fn bench_mixed_traffic_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrency/mixed_traffic");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    let benign_payloads = generators::benign_payloads();
    let sqli_payloads = generators::sqli_payloads();
    let xss_payloads = generators::xss_payloads();

    let mut all_bodies: Vec<(String, bool)> = Vec::new();
    for p in &benign_payloads {
        all_bodies.push((p.clone(), false));
    }
    for p in &sqli_payloads {
        all_bodies.push((p.clone(), true));
    }
    for p in &xss_payloads {
        all_bodies.push((p.clone(), true));
    }
    let all_bodies = Arc::new(all_bodies);

    for concurrency in [64, 256, 1024] {
        group.throughput(Throughput::Elements(concurrency as u64));
        group.bench_with_input(
            BenchmarkId::new("waf_contention", concurrency),
            &concurrency,
            |b, &tasks| {
                let rt = bench_runtime();
                let pl = SharedPipeline::new(200);
                let ips = Arc::new(generators::random_ipv4_addresses(tasks));
                let bodies = Arc::clone(&all_bodies);

                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(tasks);
                        for t in 0..tasks {
                            let flt = Arc::clone(&pl.ip_filter);
                            let rl = Arc::clone(&pl.rate_bucket);
                            let waf = Arc::clone(&pl.waf_engine);
                            let all_ips = Arc::clone(&ips);
                            let all_b = Arc::clone(&bodies);
                            handles.push(tokio::spawn(async move {
                                let ip = &all_ips[t];
                                let (body, _is_malicious) = &all_b[t % all_b.len()];

                                let _ = flt.check(ip);

                                let _ = rl.try_consume(1);

                                let scan_ctx = ScanContext::new()
                                    .with_method("POST")
                                    .with_uri("/api/v1/submit")
                                    .with_body(body.as_str());
                                let _ = black_box(waf.scan(&scan_ctx));
                            }));
                        }
                        for h in handles {
                            let _ = h.await;
                        }
                    });
                });
            },
        );
    }

    // IpFilter cache contention: many threads hitting the same RwLock
    for concurrency in [64, 256, 1024] {
        group.bench_with_input(
            BenchmarkId::new("cache_contention", concurrency),
            &concurrency,
            |b, &tasks| {
                let rt = bench_runtime();
                // Small working set → high cache hit ratio → RwLock reader contention
                let filter = {
                    let config = IpFilterConfig {
                        enabled: true,
                        rules: generators::cidr_ranges(100)
                            .into_iter()
                            .enumerate()
                            .map(|(i, cidr)| IpRule {
                                name: None,
                                addresses: vec![cidr],
                                action: AclAction::Allow,
                                priority: i as i32,
                            })
                            .collect(),
                        default_action: AclAction::Allow,
                        trust_proxy_headers: false,
                        trusted_proxies: vec![],
                    };
                    Arc::new(IpFilter::new(config).unwrap())
                };
                // Warm cache
                let hot_ips: Vec<String> = generators::random_ipv4_addresses(20);
                for ip in &hot_ips {
                    let _ = filter.check(ip);
                }
                let hot_ips = Arc::new(hot_ips);

                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(tasks);
                        for t in 0..tasks {
                            let f = Arc::clone(&filter);
                            let ips = Arc::clone(&hot_ips);
                            handles.push(tokio::spawn(async move {
                                let ip = &ips[t % ips.len()];
                                let _ = black_box(f.check(ip));
                            }));
                        }
                        for h in handles {
                            let _ = h.await;
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_concurrent_connections,
    bench_keepalive,
    bench_mixed_traffic_contention,
);
criterion_main!(benches);
