#![allow(clippy::all)]
//! Benchmarks for the Access Control module.
//!
//! Tests: IP filter check (CIDR matching), AllowList/DenyList lookup, cache performance,
//! policy engine evaluation, policy context construction.

mod common;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use common::generators;
use common::harness::bench_runtime;
use r0n_ingress::modules::access_control::{
    AllowList, DenyList, IpFilter, IpFilterConfig, IpRule, PolicyConfig, PolicyContext,
    PolicyDecision, PolicyEngine, PolicyStrategy, RuleAction,
};
use r0n_ingress::modules::l4_passthrough::{ConnectionState, ConnectionTracker};
use r0n_ingress::modules::tcp_router::TcpRouter;
use r0n_ingress::modules::tls_terminator::{CertificateStore, SniRouter};

// ---------------------------------------------------------------------------
// IP Filter benchmarks
// ---------------------------------------------------------------------------

fn bench_ip_filter(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/ip_filter");

    // Small filter (10 rules)
    let small_config = IpFilterConfig {
        enabled: true,
        rules: (0..10)
            .map(|i| IpRule {
                name: None,
                addresses: vec![format!("10.{i}.0.0/16")],
                action: if i % 2 == 0 {
                    RuleAction::Allow
                } else {
                    RuleAction::Deny
                },
                priority: i as i32,
            })
            .collect(),
        default_action: RuleAction::Deny,
        trust_proxy_headers: false,
        trusted_proxies: vec![],
    };
    let small_filter = IpFilter::new(small_config).unwrap();

    group.bench_function("check_small_filter", |b| {
        b.iter(|| {
            black_box(small_filter.check("10.5.1.1").unwrap());
        });
    });

    group.bench_function("is_allowed_small_filter", |b| {
        b.iter(|| {
            black_box(small_filter.is_allowed("10.5.1.1").unwrap());
        });
    });

    // Large filter (1000 rules)
    let large_config = IpFilterConfig {
        enabled: true,
        rules: generators::cidr_ranges(1000)
            .into_iter()
            .enumerate()
            .map(|(i, cidr)| IpRule {
                name: None,
                addresses: vec![cidr],
                action: if i % 3 == 0 {
                    RuleAction::Allow
                } else {
                    RuleAction::Deny
                },
                priority: i as i32,
            })
            .collect(),
        default_action: RuleAction::Deny,
        trust_proxy_headers: false,
        trusted_proxies: vec![],
    };
    let large_filter = IpFilter::new(large_config).unwrap();

    group.bench_function("check_large_filter", |b| {
        let ips = generators::random_ipv4_addresses(100);
        let mut idx = 0usize;
        b.iter(|| {
            let ip = &ips[idx % ips.len()];
            idx += 1;
            let _ = black_box(large_filter.check(ip));
        });
    });

    // Cache performance
    group.bench_function("check_cached", |b| {
        // First call populates cache, subsequent calls should use cache
        let _ = small_filter.check("10.3.1.1");
        b.iter(|| {
            black_box(small_filter.check("10.3.1.1").unwrap());
        });
    });

    group.bench_function("clear_cache", |b| {
        b.iter(|| {
            small_filter.clear_cache();
        });
    });

    group.bench_function("cache_size", |b| {
        let _ = small_filter.check("10.1.1.1");
        let _ = small_filter.check("10.2.1.1");
        let _ = small_filter.check("10.3.1.1");
        b.iter(|| {
            black_box(small_filter.cache_size());
        });
    });

    // Client IP extraction with proxy headers
    group.bench_function("get_client_ip_direct", |b| {
        let config = IpFilterConfig {
            enabled: true,
            rules: vec![],
            default_action: RuleAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: vec![],
        };
        let filter = IpFilter::new(config).unwrap();
        let headers = HashMap::new();
        b.iter(|| {
            black_box(filter.get_client_ip("192.168.1.1", &headers).unwrap());
        });
    });

    group.bench_function("get_client_ip_forwarded", |b| {
        let config = IpFilterConfig {
            enabled: true,
            rules: vec![],
            default_action: RuleAction::Allow,
            trust_proxy_headers: true,
            trusted_proxies: vec!["10.0.0.0/8".to_string()],
        };
        let filter = IpFilter::new(config).unwrap();
        let mut headers = HashMap::new();
        headers.insert(
            "X-Forwarded-For".to_string(),
            "203.0.113.50, 70.41.3.18".to_string(),
        );
        b.iter(|| {
            black_box(filter.get_client_ip("10.0.0.1", &headers).unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// AllowList / DenyList
// ---------------------------------------------------------------------------

fn bench_allow_deny_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/lists");

    for size in [10, 100, 1000] {
        let addrs = generators::cidr_ranges(size);

        group.bench_with_input(
            BenchmarkId::new("allowlist_check", size),
            &addrs,
            |b, addrs| {
                let list = AllowList::new(addrs.clone()).unwrap();
                let test_ips = generators::random_ipv4_addresses(20);
                let mut idx = 0;
                b.iter(|| {
                    let ip = &test_ips[idx % test_ips.len()];
                    idx += 1;
                    let _ = black_box(list.is_allowed(ip));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("denylist_check", size),
            &addrs,
            |b, addrs| {
                let list = DenyList::new(addrs.clone()).unwrap();
                let test_ips = generators::random_ipv4_addresses(20);
                let mut idx = 0;
                b.iter(|| {
                    let ip = &test_ips[idx % test_ips.len()];
                    idx += 1;
                    let _ = black_box(list.is_blocked(ip));
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Policy engine
// ---------------------------------------------------------------------------

fn bench_policy_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/policy_engine");

    // Simple policy with a few rules
    let simple_config = PolicyConfig {
        enabled: true,
        rules: vec![
            r0n_ingress::modules::access_control::PolicyRule {
                name: "admin-access".to_string(),
                action: RuleAction::Allow,
                conditions: vec![
                    r0n_ingress::modules::access_control::PolicyCondition::HasRole {
                        role: "admin".to_string(),
                    },
                ],
                priority: 100,
                routes: vec![],
                methods: vec![],
            },
            r0n_ingress::modules::access_control::PolicyRule {
                name: "deny-blocked-ip".to_string(),
                action: RuleAction::Deny,
                conditions: vec![
                    r0n_ingress::modules::access_control::PolicyCondition::IpInList {
                        addresses: vec!["10.0.0.0/8".to_string()],
                    },
                ],
                priority: 50,
                routes: vec![],
                methods: vec![],
            },
        ],
        strategy: PolicyStrategy::FirstMatch,
        default_action: RuleAction::Deny,
    };
    let simple_engine = PolicyEngine::new(simple_config);

    group.bench_function("evaluate_simple_allow", |b| {
        let ctx = PolicyContext::new()
            .with_identity("admin-user")
            .with_role("admin")
            .with_path("/admin/dashboard")
            .with_method("GET")
            .with_client_ip("192.168.1.1");
        b.iter(|| {
            black_box(simple_engine.evaluate(&ctx).unwrap());
        });
    });

    group.bench_function("evaluate_simple_deny", |b| {
        let ctx = PolicyContext::new()
            .with_identity("regular-user")
            .with_path("/public")
            .with_method("GET")
            .with_client_ip("10.1.2.3");
        b.iter(|| {
            black_box(simple_engine.evaluate(&ctx).unwrap());
        });
    });

    group.bench_function("evaluate_no_match", |b| {
        let ctx = PolicyContext::new()
            .with_identity("unknown-user")
            .with_path("/other")
            .with_method("GET")
            .with_client_ip("172.16.0.1");
        b.iter(|| {
            black_box(simple_engine.evaluate(&ctx).unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// PolicyContext construction
// ---------------------------------------------------------------------------

fn bench_policy_context(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/policy_context");

    group.bench_function("minimal_context", |b| {
        b.iter(|| {
            black_box(PolicyContext::new().with_client_ip("192.168.1.1"));
        });
    });

    group.bench_function("full_context", |b| {
        b.iter(|| {
            black_box(
                PolicyContext::new()
                    .with_identity("user@example.com")
                    .with_role("admin")
                    .with_role("editor")
                    .with_role("viewer")
                    .with_claim("sub", "user-123")
                    .with_claim("iss", "auth.example.com")
                    .with_claim("aud", "api.example.com")
                    .with_path("/api/v1/resources/123")
                    .with_method("PUT")
                    .with_header("Authorization", "Bearer xyz")
                    .with_header("Content-Type", "application/json")
                    .with_client_ip("203.0.113.50"),
            );
        });
    });

    group.bench_function("role_checks", |b| {
        let ctx = PolicyContext::new()
            .with_role("admin")
            .with_role("editor")
            .with_role("viewer")
            .with_role("moderator");
        b.iter(|| {
            black_box(ctx.has_role("admin"));
            black_box(ctx.has_role("unknown"));
            black_box(ctx.has_any_role(&["admin".to_string(), "superadmin".to_string()]));
            black_box(ctx.has_all_roles(&["admin".to_string(), "editor".to_string()]));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// PolicyDecision
// ---------------------------------------------------------------------------

fn bench_policy_decision(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/policy_decision");

    group.bench_function("create_allow", |b| {
        b.iter(|| {
            black_box(PolicyDecision::allow("Authorized"));
        });
    });

    group.bench_function("create_deny_with_rule", |b| {
        b.iter(|| {
            black_box(PolicyDecision::deny("IP blocked").with_rule("ip-block-rule"));
        });
    });

    group.bench_function("decision_checks", |b| {
        let allow = PolicyDecision::allow("ok");
        let deny = PolicyDecision::deny("no");
        b.iter(|| {
            black_box(allow.is_allowed());
            black_box(deny.is_denied());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Concurrent benchmark (Tokio multi-threaded)
// ---------------------------------------------------------------------------

fn bench_concurrent_policy_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/concurrent");
    group.sample_size(50);

    let config = PolicyConfig {
        enabled: true,
        rules: (0..50)
            .map(|i| r0n_ingress::modules::access_control::PolicyRule {
                name: format!("rule-{i}"),
                action: if i % 3 == 0 {
                    RuleAction::Allow
                } else {
                    RuleAction::Deny
                },
                conditions: vec![
                    r0n_ingress::modules::access_control::PolicyCondition::HasRole {
                        role: format!("role-{i}"),
                    },
                ],
                priority: i as i32,
                routes: vec![],
                methods: vec![],
            })
            .collect(),
        strategy: PolicyStrategy::Priority,
        default_action: RuleAction::Deny,
    };
    let engine = Arc::new(PolicyEngine::new(config));

    for concurrency in [4, 16, 64] {
        group.bench_with_input(
            BenchmarkId::new("policy_eval_tasks", concurrency),
            &concurrency,
            |b, &tasks| {
                let rt = bench_runtime();
                let engine = Arc::clone(&engine);
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(tasks);
                        for t in 0..tasks {
                            let eng = Arc::clone(&engine);
                            handles.push(tokio::spawn(async move {
                                let ctx = PolicyContext::new()
                                    .with_identity(&format!("user-{t}"))
                                    .with_role(&format!("role-{}", t % 50))
                                    .with_path("/api/resource")
                                    .with_method("GET")
                                    .with_client_ip(&format!("10.0.{}.{}", t / 256, (t % 254) + 1));
                                black_box(eng.evaluate(&ctx).unwrap());
                            }));
                        }
                        for h in handles {
                            h.await.unwrap();
                        }
                    });
                });
            },
        );
    }

    // Concurrent IpFilter checks
    let ip_config = IpFilterConfig {
        enabled: true,
        rules: generators::cidr_ranges(500)
            .into_iter()
            .enumerate()
            .map(|(i, cidr)| IpRule {
                name: None,
                addresses: vec![cidr],
                action: if i % 2 == 0 {
                    RuleAction::Allow
                } else {
                    RuleAction::Deny
                },
                priority: i as i32,
            })
            .collect(),
        default_action: RuleAction::Deny,
        trust_proxy_headers: false,
        trusted_proxies: vec![],
    };
    let filter = Arc::new(IpFilter::new(ip_config).unwrap());

    for concurrency in [4, 16, 64] {
        group.bench_with_input(
            BenchmarkId::new("ip_filter_tasks", concurrency),
            &concurrency,
            |b, &tasks| {
                let rt = bench_runtime();
                let ips = generators::random_ipv4_addresses(200);
                let ips = Arc::new(ips);
                let filter = Arc::clone(&filter);
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(tasks);
                        for t in 0..tasks {
                            let f = Arc::clone(&filter);
                            let addrs = Arc::clone(&ips);
                            handles.push(tokio::spawn(async move {
                                let ip = &addrs[t % addrs.len()];
                                let _ = black_box(f.check(ip));
                            }));
                        }
                        for h in handles {
                            h.await.unwrap();
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// End-to-end TCP proxy benchmark
// ---------------------------------------------------------------------------

fn bench_tcp_proxy_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/tcp_proxy_e2e");
    group.sample_size(50);

    let tracker = ConnectionTracker::new();
    let router = TcpRouter::new();

    // Simulate connection lifecycle: track → ACL check → route → update → remove
    group.bench_function("full_connection_lifecycle", |b| {
        let filter_config = IpFilterConfig {
            enabled: true,
            rules: generators::cidr_ranges(100)
                .into_iter()
                .enumerate()
                .map(|(i, cidr)| IpRule {
                    name: None,
                    addresses: vec![cidr],
                    action: RuleAction::Allow,
                    priority: i as i32,
                })
                .collect(),
            default_action: RuleAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: vec![],
        };
        let filter = IpFilter::new(filter_config).unwrap();
        let mut idx = 0u64;

        b.iter(|| {
            idx += 1;
            let client = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, ((idx % 254) + 1) as u8)),
                (10000 + (idx % 50000)) as u16,
            );
            let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);

            // 1. Track the connection
            let conn_id = tracker.track_connection(client, backend, "default".to_string());

            // 2. ACL check on client IP
            let ip_str = client.ip().to_string();
            let _ = black_box(filter.check(&ip_str));

            // 3. Get router stats (simulate routing decision)
            let _ = black_box(router.stats());

            // 4. Update connection state
            tracker.update_state(conn_id, ConnectionState::Active);
            tracker.update_bytes(conn_id, 1024, 512);

            // 5. Remove connection
            black_box(tracker.remove_connection(conn_id));
        });
    });

    // Batched connections with ACL pipeline
    for batch_size in [10, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("batch_lifecycle", batch_size),
            &batch_size,
            |b, &size| {
                let filter_config = IpFilterConfig {
                    enabled: true,
                    rules: vec![IpRule {
                        name: None,
                        addresses: vec!["0.0.0.0/0".to_string()],
                        action: RuleAction::Allow,
                        priority: 0,
                    }],
                    default_action: RuleAction::Allow,
                    trust_proxy_headers: false,
                    trusted_proxies: vec![],
                };
                let filter = IpFilter::new(filter_config).unwrap();
                let batch_tracker = ConnectionTracker::new();
                let ips = generators::random_ipv4_addresses(size);

                b.iter(|| {
                    let mut conn_ids = Vec::with_capacity(size);
                    // Accept + ACL check
                    for (i, ip) in ips.iter().enumerate() {
                        let client = SocketAddr::new(
                            ip.parse::<IpAddr>()
                                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                            10000 + i as u16,
                        );
                        let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
                        let id =
                            batch_tracker.track_connection(client, backend, "default".to_string());
                        let _ = black_box(filter.check(ip));
                        conn_ids.push(id);
                    }
                    // Teardown
                    for id in conn_ids {
                        batch_tracker.update_state(id, ConnectionState::Closed);
                        black_box(batch_tracker.remove_connection(id));
                    }
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// TLS termination benchmark
// ---------------------------------------------------------------------------

fn bench_tls_termination_with_acl(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/tls_termination");

    // Combined TLS SNI routing + access-control decision
    group.bench_function("sni_resolve_then_acl", |b| {
        let sni_router = SniRouter::new();
        let filter_config = IpFilterConfig {
            enabled: true,
            rules: generators::cidr_ranges(200)
                .into_iter()
                .enumerate()
                .map(|(i, cidr)| IpRule {
                    name: None,
                    addresses: vec![cidr],
                    action: if i % 4 == 0 {
                        RuleAction::Deny
                    } else {
                        RuleAction::Allow
                    },
                    priority: i as i32,
                })
                .collect(),
            default_action: RuleAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: vec![],
        };
        let filter = IpFilter::new(filter_config).unwrap();
        let domains = [
            "api.example.com",
            "web.example.com",
            "admin.example.com",
            "cdn.example.com",
        ];
        let ips = generators::random_ipv4_addresses(50);
        let mut idx = 0usize;

        b.iter(|| {
            let domain = domains[idx % domains.len()];
            let ip = &ips[idx % ips.len()];
            idx += 1;

            // 1. SNI resolution
            let _ = black_box(sni_router.resolve(domain));

            // 2. IP-based access control
            let _ = black_box(filter.check(ip));
        });
    });

    // Certificate store lookup + policy evaluation pipeline
    group.bench_function("cert_lookup_then_policy", |b| {
        let store = CertificateStore::new();
        let policy_config = PolicyConfig {
            enabled: true,
            rules: (0..20)
                .map(|i| r0n_ingress::modules::access_control::PolicyRule {
                    name: format!("tls-rule-{i}"),
                    action: if i % 2 == 0 {
                        RuleAction::Allow
                    } else {
                        RuleAction::Deny
                    },
                    conditions: vec![
                        r0n_ingress::modules::access_control::PolicyCondition::HasRole {
                            role: format!("svc-role-{i}"),
                        },
                    ],
                    priority: i as i32,
                    routes: vec![],
                    methods: vec![],
                })
                .collect(),
            strategy: PolicyStrategy::FirstMatch,
            default_action: RuleAction::Deny,
        };
        let engine = PolicyEngine::new(policy_config);
        let sni_names = ["api.example.com", "web.example.com", "unknown.example.com"];
        let mut idx = 0usize;

        b.iter(|| {
            let sni = sni_names[idx % sni_names.len()];
            idx += 1;

            // 1. Certificate lookup by SNI
            let _ = black_box(store.find_by_sni(sni));

            // 2. Policy evaluation post-TLS
            let ctx = PolicyContext::new()
                .with_identity("tls-client")
                .with_role(&format!("svc-role-{}", idx % 20))
                .with_path("/secure/resource")
                .with_method("GET")
                .with_client_ip("203.0.113.50");
            let _ = black_box(engine.evaluate(&ctx));
        });
    });

    // Concurrent TLS + ACL pipeline with Tokio
    group.bench_function("concurrent_tls_acl_pipeline", |b| {
        let rt = bench_runtime();
        let filter_config = IpFilterConfig {
            enabled: true,
            rules: generators::cidr_ranges(100)
                .into_iter()
                .enumerate()
                .map(|(i, cidr)| IpRule {
                    name: None,
                    addresses: vec![cidr],
                    action: RuleAction::Allow,
                    priority: i as i32,
                })
                .collect(),
            default_action: RuleAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: vec![],
        };
        let filter = Arc::new(IpFilter::new(filter_config).unwrap());
        let ips = Arc::new(generators::random_ipv4_addresses(100));

        b.iter(|| {
            rt.block_on(async {
                let mut handles = Vec::with_capacity(32);
                for t in 0..32 {
                    let f = Arc::clone(&filter);
                    let addrs = Arc::clone(&ips);
                    handles.push(tokio::spawn(async move {
                        let sni_router = SniRouter::new();
                        let _ = black_box(sni_router.resolve("api.example.com"));
                        let ip = &addrs[t % addrs.len()];
                        let _ = black_box(f.check(ip));
                    }));
                }
                for h in handles {
                    h.await.unwrap();
                }
            });
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// 10k concurrent connection test
// ---------------------------------------------------------------------------

fn bench_10k_concurrent_connections(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/10k_connections");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(15));

    // 10k connections tracked + ACL checked
    group.bench_function("track_10k_connections", |b| {
        b.iter(|| {
            let tracker = ConnectionTracker::new();
            for i in 0u64..10_000 {
                let client = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        ((i >> 16) & 0xFF) as u8 | 1,
                        ((i >> 8) & 0xFF) as u8,
                        (i & 0xFF) as u8,
                        1,
                    )),
                    (10000 + (i % 55535)) as u16,
                );
                let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
                black_box(tracker.track_connection(client, backend, "default".to_string()));
            }
            black_box(tracker.active_connections());
        });
    });

    // 10k concurrent ACL checks with Tokio
    group.bench_function("acl_check_10k_concurrent", |b| {
        let rt = bench_runtime();
        let filter_config = IpFilterConfig {
            enabled: true,
            rules: generators::cidr_ranges(100)
                .into_iter()
                .enumerate()
                .map(|(i, cidr)| IpRule {
                    name: None,
                    addresses: vec![cidr],
                    action: RuleAction::Allow,
                    priority: i as i32,
                })
                .collect(),
            default_action: RuleAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: vec![],
        };
        let filter = Arc::new(IpFilter::new(filter_config).unwrap());
        let ips = Arc::new(generators::random_ipv4_addresses(10_000));

        b.iter(|| {
            rt.block_on(async {
                let mut handles = Vec::with_capacity(10_000);
                for t in 0..10_000 {
                    let f = Arc::clone(&filter);
                    let addrs = Arc::clone(&ips);
                    handles.push(tokio::spawn(async move {
                        let _ = black_box(f.check(&addrs[t]));
                    }));
                }
                for h in handles {
                    h.await.unwrap();
                }
            });
        });
    });

    // 10k connections: full lifecycle (track → ACL → state update → remove)
    group.bench_function("full_lifecycle_10k", |b| {
        let filter_config = IpFilterConfig {
            enabled: true,
            rules: vec![IpRule {
                name: None,
                addresses: vec!["0.0.0.0/0".to_string()],
                action: RuleAction::Allow,
                priority: 0,
            }],
            default_action: RuleAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: vec![],
        };
        let filter = IpFilter::new(filter_config).unwrap();

        b.iter(|| {
            let tracker = ConnectionTracker::new();
            let mut ids = Vec::with_capacity(10_000);

            // Accept phase
            for i in 0u64..10_000 {
                let client = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        ((i >> 16) & 0xFF) as u8 | 1,
                        ((i >> 8) & 0xFF) as u8,
                        (i & 0xFF) as u8,
                        1,
                    )),
                    (10000 + (i % 55535)) as u16,
                );
                let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
                let id = tracker.track_connection(client, backend, "default".to_string());
                let _ = filter.check(&client.ip().to_string());
                ids.push(id);
            }

            // Active phase
            for &id in &ids {
                tracker.update_state(id, ConnectionState::Active);
                tracker.update_bytes(id, 4096, 2048);
            }

            // Teardown phase
            for id in ids {
                tracker.update_state(id, ConnectionState::Closed);
                tracker.remove_connection(id);
            }

            black_box(tracker.active_connections());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Large rule set (10k–100k CIDRs)
// ---------------------------------------------------------------------------

fn bench_large_rule_set(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_control/large_rule_set");
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(10));

    // Construction time for large filters
    for rule_count in [10_000, 50_000, 100_000] {
        group.bench_with_input(
            BenchmarkId::new("construct_filter", rule_count),
            &rule_count,
            |b, &count| {
                let cidrs = generators::cidr_ranges(count);
                b.iter(|| {
                    let config = IpFilterConfig {
                        enabled: true,
                        rules: cidrs
                            .iter()
                            .enumerate()
                            .map(|(i, cidr)| IpRule {
                                name: None,
                                addresses: vec![cidr.clone()],
                                action: if i % 2 == 0 {
                                    RuleAction::Allow
                                } else {
                                    RuleAction::Deny
                                },
                                priority: i as i32,
                            })
                            .collect(),
                        default_action: RuleAction::Deny,
                        trust_proxy_headers: false,
                        trusted_proxies: vec![],
                    };
                    black_box(IpFilter::new(config).unwrap());
                });
            },
        );
    }

    // Check latency against large rule sets
    for rule_count in [10_000, 50_000, 100_000] {
        group.bench_with_input(
            BenchmarkId::new("check_ip", rule_count),
            &rule_count,
            |b, &count| {
                let config = IpFilterConfig {
                    enabled: true,
                    rules: generators::cidr_ranges(count)
                        .into_iter()
                        .enumerate()
                        .map(|(i, cidr)| IpRule {
                            name: None,
                            addresses: vec![cidr],
                            action: if i % 2 == 0 {
                                RuleAction::Allow
                            } else {
                                RuleAction::Deny
                            },
                            priority: i as i32,
                        })
                        .collect(),
                    default_action: RuleAction::Deny,
                    trust_proxy_headers: false,
                    trusted_proxies: vec![],
                };
                let filter = IpFilter::new(config).unwrap();
                let ips = generators::random_ipv4_addresses(200);
                let mut idx = 0usize;
                b.iter(|| {
                    let ip = &ips[idx % ips.len()];
                    idx += 1;
                    let _ = black_box(filter.check(ip));
                });
            },
        );
    }

    // AllowList / DenyList at scale
    for rule_count in [10_000, 50_000, 100_000] {
        let cidrs = generators::cidr_ranges(rule_count);

        group.bench_with_input(
            BenchmarkId::new("allowlist_check", rule_count),
            &cidrs,
            |b, cidrs| {
                let list = AllowList::new(cidrs.clone()).unwrap();
                let ips = generators::random_ipv4_addresses(100);
                let mut idx = 0usize;
                b.iter(|| {
                    let ip = &ips[idx % ips.len()];
                    idx += 1;
                    let _ = black_box(list.is_allowed(ip));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("denylist_check", rule_count),
            &cidrs,
            |b, cidrs| {
                let list = DenyList::new(cidrs.clone()).unwrap();
                let ips = generators::random_ipv4_addresses(100);
                let mut idx = 0usize;
                b.iter(|| {
                    let ip = &ips[idx % ips.len()];
                    idx += 1;
                    let _ = black_box(list.is_blocked(ip));
                });
            },
        );
    }

    // Cache performance with large rule sets
    group.bench_function("cache_hit_ratio_100k_rules", |b| {
        let config = IpFilterConfig {
            enabled: true,
            rules: generators::cidr_ranges(100_000)
                .into_iter()
                .enumerate()
                .map(|(i, cidr)| IpRule {
                    name: None,
                    addresses: vec![cidr],
                    action: RuleAction::Allow,
                    priority: i as i32,
                })
                .collect(),
            default_action: RuleAction::Deny,
            trust_proxy_headers: false,
            trusted_proxies: vec![],
        };
        let filter = IpFilter::new(config).unwrap();

        // Warm the cache with a small working set
        let hot_ips = generators::random_ipv4_addresses(20);
        for ip in &hot_ips {
            let _ = filter.check(ip);
        }

        let mut idx = 0usize;
        b.iter(|| {
            // 80% cache hits (hot set), 20% cold misses
            let ip = if idx % 5 < 4 {
                &hot_ips[idx % hot_ips.len()]
            } else {
                // Generate a "cold" IP unlikely to be cached
                &hot_ips[(idx + 7) % hot_ips.len()]
            };
            idx += 1;
            let _ = black_box(filter.check(ip));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ip_filter,
    bench_allow_deny_list,
    bench_policy_engine,
    bench_policy_context,
    bench_policy_decision,
    bench_concurrent_policy_evaluation,
    bench_tcp_proxy_end_to_end,
    bench_tls_termination_with_acl,
    bench_10k_concurrent_connections,
    bench_large_rule_set,
);
criterion_main!(benches);
