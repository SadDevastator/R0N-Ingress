#![allow(clippy::all)]
//! CPU Saturation Curve Benchmark
//!
//! Sweeps concurrency levels (1 → 256 tasks) to find:
//!   - Where mean latency starts to climb (inflection point)
//!   - Where p99 / p999 tail latency explodes
//!   - Per-component breakdown under load
//!
//! Collects per-iteration `Instant` timings inside the Criterion harness,
//! then computes percentiles manually for the saturation report.

mod common;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

// ─── Percentile calculation ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct LatencyProfile {
    p50: Duration,
    p90: Duration,
    p95: Duration,
    p99: Duration,
    p999: Duration,
    max: Duration,
    mean: Duration,
}

fn compute_percentiles(mut durations: Vec<Duration>) -> LatencyProfile {
    durations.sort();
    let n = durations.len();
    if n == 0 {
        return LatencyProfile {
            p50: Duration::ZERO,
            p90: Duration::ZERO,
            p95: Duration::ZERO,
            p99: Duration::ZERO,
            p999: Duration::ZERO,
            max: Duration::ZERO,
            mean: Duration::ZERO,
        };
    }
    let pct = |p: f64| durations[((n as f64 * p) as usize).min(n - 1)];
    let total: Duration = durations.iter().sum();
    let mean = total / n as u32;

    LatencyProfile {
        p50: pct(0.50),
        p90: pct(0.90),
        p95: pct(0.95),
        p99: pct(0.99),
        p999: pct(0.999),
        max: durations[n - 1],
        mean,
    }
}

// ─── Shared pipeline ─────────────────────────────────────────────────────────

struct SaturationPipeline {
    ip_filter: Arc<IpFilter>,
    rate_bucket: Arc<TokenBucket>,
    waf_engine: Arc<RuleEngine>,
    http_handler: Arc<HttpHandler>,
    tracker: Arc<ConnectionTracker>,
}

impl SaturationPipeline {
    fn new(acl_rules: usize) -> Self {
        let cidrs = generators::cidr_ranges(acl_rules);
        let config = IpFilterConfig {
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
            ip_filter: Arc::new(IpFilter::new(config).unwrap()),
            rate_bucket: Arc::new(TokenBucket::with_defaults()),
            waf_engine: Arc::new(RuleEngine::default_config()),
            http_handler: Arc::new(HttpHandler::new()),
            tracker: Arc::new(ConnectionTracker::new()),
        }
    }
}

// ─── Concurrency sweep: full pipeline ────────────────────────────────────────

fn bench_saturation_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("saturation/full_pipeline");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    let pipeline = SaturationPipeline::new(200);
    let requests = Arc::new(generators::http_request_batch(200));
    let ips = Arc::new(generators::random_ipv4_addresses(1024));

    let concurrency_levels: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

    for &concurrency in concurrency_levels {
        group.throughput(Throughput::Elements(concurrency as u64));
        group.bench_with_input(
            BenchmarkId::new("sweep", concurrency),
            &concurrency,
            |b, &tasks| {
                let rt = bench_runtime();
                let flt = Arc::clone(&pipeline.ip_filter);
                let rl = Arc::clone(&pipeline.rate_bucket);
                let waf = Arc::clone(&pipeline.waf_engine);
                let hh = Arc::clone(&pipeline.http_handler);
                let trk = Arc::clone(&pipeline.tracker);
                let reqs = Arc::clone(&requests);
                let all_ips = Arc::clone(&ips);

                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(tasks);
                        for t in 0..tasks {
                            let flt = Arc::clone(&flt);
                            let rl = Arc::clone(&rl);
                            let waf = Arc::clone(&waf);
                            let hh = Arc::clone(&hh);
                            let trk = Arc::clone(&trk);
                            let reqs = Arc::clone(&reqs);
                            let all_ips = Arc::clone(&all_ips);
                            handles.push(tokio::spawn(async move {
                                let ip = &all_ips[t % all_ips.len()];

                                let _ = flt.check(ip);

                                let _ = rl.try_consume(1);

                                let raw = &reqs[t % reqs.len()];
                                if let Ok((req, _)) = Request::parse(raw) {
                                    let scan_ctx = ScanContext::new()
                                        .with_method(req.method().as_str())
                                        .with_uri(req.path());
                                    let _ = waf.scan(&scan_ctx);
                                    let _ = black_box(hh.router().route(&req));
                                }

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

// ─── Per-component latency under contention ──────────────────────────────────

fn bench_saturation_per_component(c: &mut Criterion) {
    let mut group = c.benchmark_group("saturation/per_component");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let pipeline = SaturationPipeline::new(200);
    let requests = Arc::new(generators::http_request_batch(200));
    let ips = Arc::new(generators::random_ipv4_addresses(256));
    let concurrency_levels: &[usize] = &[1, 4, 16, 64, 256];

    // === ACL only ===
    for &concurrency in concurrency_levels {
        group.bench_with_input(
            BenchmarkId::new("acl_only", concurrency),
            &concurrency,
            |b, &tasks| {
                let rt = bench_runtime();
                let flt = Arc::clone(&pipeline.ip_filter);
                let all_ips = Arc::clone(&ips);
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(tasks);
                        for t in 0..tasks {
                            let f = Arc::clone(&flt);
                            let addrs = Arc::clone(&all_ips);
                            handles.push(tokio::spawn(async move {
                                let ip = &addrs[t % addrs.len()];
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

    // === Rate limiter only ===
    for &concurrency in concurrency_levels {
        group.bench_with_input(
            BenchmarkId::new("rate_bucket_only", concurrency),
            &concurrency,
            |b, &tasks| {
                let rt = bench_runtime();
                let rl = Arc::clone(&pipeline.rate_bucket);
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(tasks);
                        for _t in 0..tasks {
                            let r = Arc::clone(&rl);
                            handles.push(tokio::spawn(async move {
                                let _ = black_box(r.try_consume(1));
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

    // === WAF only ===
    let payloads: Vec<String> = {
        let mut v = generators::benign_payloads();
        v.extend(generators::sqli_payloads());
        v.extend(generators::xss_payloads());
        v
    };
    let payloads = Arc::new(payloads);

    for &concurrency in concurrency_levels {
        group.bench_with_input(
            BenchmarkId::new("waf_only", concurrency),
            &concurrency,
            |b, &tasks| {
                let rt = bench_runtime();
                let waf = Arc::clone(&pipeline.waf_engine);
                let bodies = Arc::clone(&payloads);
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(tasks);
                        for t in 0..tasks {
                            let w = Arc::clone(&waf);
                            let bd = Arc::clone(&bodies);
                            handles.push(tokio::spawn(async move {
                                let body = &bd[t % bd.len()];
                                let scan_ctx = ScanContext::new()
                                    .with_method("POST")
                                    .with_uri("/api/v1/data")
                                    .with_body(body.as_str());
                                let _ = black_box(w.scan(&scan_ctx));
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

    // === HTTP parse + route only ===
    for &concurrency in concurrency_levels {
        group.bench_with_input(
            BenchmarkId::new("http_parse_route_only", concurrency),
            &concurrency,
            |b, &tasks| {
                let rt = bench_runtime();
                let hh = Arc::clone(&pipeline.http_handler);
                let reqs = Arc::clone(&requests);
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(tasks);
                        for t in 0..tasks {
                            let h = Arc::clone(&hh);
                            let r = Arc::clone(&reqs);
                            handles.push(tokio::spawn(async move {
                                let raw = &r[t % r.len()];
                                if let Ok((req, _)) = Request::parse(raw) {
                                    let _ = black_box(h.router().route(&req));
                                }
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

// ─── Manual tail-latency profiling (collected inside Criterion) ──────────────

fn bench_tail_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("saturation/tail_latency");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    let pipeline = SaturationPipeline::new(200);
    let requests = Arc::new(generators::http_request_batch(200));
    let ips = Arc::new(generators::random_ipv4_addresses(1024));

    // Run N iterations at a given concurrency, collect per-task latencies,
    // then compute percentiles and print them.
    let concurrency_levels: &[usize] = &[1, 8, 32, 128, 256];
    let iters_per_level = 50;

    for &concurrency in concurrency_levels {
        group.bench_with_input(
            BenchmarkId::new("profile", concurrency),
            &concurrency,
            |b, &tasks| {
                let rt = bench_runtime();
                let flt = Arc::clone(&pipeline.ip_filter);
                let rl = Arc::clone(&pipeline.rate_bucket);
                let waf = Arc::clone(&pipeline.waf_engine);
                let hh = Arc::clone(&pipeline.http_handler);
                let trk = Arc::clone(&pipeline.tracker);
                let reqs = Arc::clone(&requests);
                let all_ips = Arc::clone(&ips);

                // Collect latencies outside the Criterion iteration
                let latencies = Arc::new(std::sync::Mutex::new(Vec::with_capacity(
                    tasks * iters_per_level,
                )));

                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(tasks);
                        for t in 0..tasks {
                            let flt = Arc::clone(&flt);
                            let rl = Arc::clone(&rl);
                            let waf = Arc::clone(&waf);
                            let hh = Arc::clone(&hh);
                            let trk = Arc::clone(&trk);
                            let reqs = Arc::clone(&reqs);
                            let all_ips = Arc::clone(&all_ips);
                            let lats = Arc::clone(&latencies);
                            handles.push(tokio::spawn(async move {
                                let start = Instant::now();

                                let ip = &all_ips[t % all_ips.len()];
                                let _ = flt.check(ip);

                                let _ = rl.try_consume(1);

                                let raw = &reqs[t % reqs.len()];
                                if let Ok((req, _)) = Request::parse(raw) {
                                    let scan_ctx = ScanContext::new()
                                        .with_method(req.method().as_str())
                                        .with_uri(req.path());
                                    let _ = waf.scan(&scan_ctx);
                                    let _ = black_box(hh.router().route(&req));
                                }

                                let client = SocketAddr::new(
                                    ip.parse::<IpAddr>()
                                        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                                    10000 + (t as u16 % 55000),
                                );
                                let backend = SocketAddr::new(
                                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                                    8080,
                                );
                                let id = trk.track_connection(client, backend, "default".into());
                                trk.update_state(id, ConnectionState::Active);
                                trk.update_bytes(id, 1024, 256);
                                trk.update_state(id, ConnectionState::Closed);
                                trk.remove_connection(id);

                                let elapsed = start.elapsed();
                                if let Ok(mut guard) = lats.lock() {
                                    guard.push(elapsed);
                                }
                            }));
                        }
                        for h in handles {
                            let _ = h.await;
                        }
                    });
                });

                // Print percentile report at end of this concurrency level
                if let Ok(guard) = latencies.lock() {
                    if guard.len() > 0 {
                        let profile = compute_percentiles(guard.clone());
                        eprintln!(
                            "\n[saturation c={}] samples={} mean={:?} p50={:?} p90={:?} p95={:?} p99={:?} p999={:?} max={:?}",
                            tasks,
                            guard.len(),
                            profile.mean,
                            profile.p50,
                            profile.p90,
                            profile.p95,
                            profile.p99,
                            profile.p999,
                            profile.max,
                        );
                    }
                };
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_saturation_full_pipeline,
    bench_saturation_per_component,
    bench_tail_latency,
);
criterion_main!(benches);
