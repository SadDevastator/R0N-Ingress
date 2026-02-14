#![allow(clippy::all)]
//! Benchmarks for HTTP Handler module.
//!
//! Tests: Request parsing, response building, route matching (exact/wildcard/param/glob),
//! path pattern compilation & matching, middleware chain processing, serialization.

mod common;
use bytes::Bytes;
use common::generators;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use r0n_ingress::modules::http_handler::{
    middleware::{MiddlewareChain, RequestIdMiddleware, TimingMiddleware},
    request::Request,
    response::Response,
    router::{PathPattern, Router},
};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// HTTP request parsing
// ---------------------------------------------------------------------------

fn bench_request_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_handler/parse_request");

    group.bench_function("simple_get", |b| {
        let data = generators::http_get_request("/api/v1/users", "example.com");
        b.iter(|| {
            black_box(Request::parse(&data).unwrap());
        });
    });

    group.bench_function("get_with_query", |b| {
        let data = generators::http_get_request(
            "/api/v1/users?page=1&limit=50&sort=name&order=asc",
            "example.com",
        );
        b.iter(|| {
            black_box(Request::parse(&data).unwrap());
        });
    });

    group.bench_function("post_with_json_body", |b| {
        let body =
            r#"{"name":"John Doe","email":"john@example.com","age":30,"roles":["admin","user"]}"#;
        let data = generators::http_post_request("/api/v1/users", "example.com", body);
        b.iter(|| {
            black_box(Request::parse(&data).unwrap());
        });
    });

    group.bench_function("post_large_body", |b| {
        let body = "x".repeat(8192);
        let data = generators::http_post_request("/api/v1/upload", "example.com", &body);
        b.iter(|| {
            black_box(Request::parse(&data).unwrap());
        });
    });

    // Parse throughput with varied requests
    group.bench_function("batch_varied_requests", |b| {
        let requests = generators::http_request_batch(100);
        b.iter(|| {
            for req in &requests {
                black_box(Request::parse(req).unwrap());
            }
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// HTTP response building & parsing
// ---------------------------------------------------------------------------

fn bench_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_handler/response");

    group.bench_function("build_ok_text", |b| {
        b.iter(|| {
            black_box(Response::ok().text("Hello, World!").build());
        });
    });

    group.bench_function("build_ok_json", |b| {
        b.iter(|| {
            black_box(
                Response::ok()
                    .json(r#"{"status":"ok","data":{"id":1,"name":"test"}}"#)
                    .build(),
            );
        });
    });

    group.bench_function("build_not_found", |b| {
        b.iter(|| {
            black_box(Response::not_found().text("Not Found").build());
        });
    });

    group.bench_function("build_with_headers", |b| {
        b.iter(|| {
            black_box(
                Response::ok()
                    .header("X-Request-ID", "abc-123")
                    .header("X-Response-Time", "42ms")
                    .header("Cache-Control", "no-cache")
                    .header("X-Custom-Header", "benchmark-value")
                    .text("OK")
                    .build(),
            );
        });
    });

    group.bench_function("serialize_response", |b| {
        let resp = Response::ok()
            .header("Content-Type", "application/json")
            .json(r#"{"result":"success"}"#)
            .build();
        b.iter(|| {
            black_box(resp.serialize());
        });
    });

    group.bench_function("parse_response", |b| {
        let data = generators::http_response(200, "Hello, World!");
        b.iter(|| {
            black_box(Response::parse(&data).unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Request serialization
// ---------------------------------------------------------------------------

fn bench_request_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_handler/request_serialize");

    group.bench_function("serialize_get", |b| {
        let data = generators::http_get_request("/api/v1/users", "example.com");
        let (req, _) = Request::parse(&data).unwrap();
        b.iter(|| {
            black_box(req.serialize());
        });
    });

    group.bench_function("serialize_post", |b| {
        let body = r#"{"key":"value"}"#;
        let data = generators::http_post_request("/api/v1/data", "example.com", body);
        let (req, _) = Request::parse(&data).unwrap();
        b.iter(|| {
            black_box(req.serialize());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Request builder
// ---------------------------------------------------------------------------

fn bench_request_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_handler/request_builder");

    group.bench_function("build_simple", |b| {
        b.iter(|| {
            black_box(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/test")
                    .unwrap()
                    .header("Host", "example.com")
                    .build()
                    .unwrap(),
            );
        });
    });

    group.bench_function("build_with_body", |b| {
        b.iter(|| {
            black_box(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/data")
                    .unwrap()
                    .header("Host", "example.com")
                    .header("Content-Type", "application/json")
                    .body(Bytes::from(r#"{"key":"value"}"#))
                    .build()
                    .unwrap(),
            );
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Path pattern matching
// ---------------------------------------------------------------------------

fn bench_path_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_handler/path_pattern");

    group.bench_function("compile_exact", |b| {
        b.iter(|| {
            black_box(PathPattern::compile("/api/v1/users").unwrap());
        });
    });

    group.bench_function("compile_wildcard", |b| {
        b.iter(|| {
            black_box(PathPattern::compile("/api/v1/*/profile").unwrap());
        });
    });

    group.bench_function("compile_param", |b| {
        b.iter(|| {
            black_box(PathPattern::compile("/api/v1/:id/posts/:post_id").unwrap());
        });
    });

    group.bench_function("compile_globstar", |b| {
        b.iter(|| {
            black_box(PathPattern::compile("/static/**").unwrap());
        });
    });

    // Match benchmarks
    let patterns = vec![
        ("/api/v1/users", "exact"),
        ("/api/v1/*/profile", "wildcard"),
        ("/api/v1/:id/posts", "param"),
        ("/static/**", "globstar"),
    ];

    for (pattern, name) in &patterns {
        let compiled = PathPattern::compile(pattern).unwrap();
        group.bench_function(format!("match_{name}"), |b| {
            b.iter(|| {
                black_box(compiled.matches("/api/v1/users"));
                black_box(compiled.matches("/api/v1/123/profile"));
                black_box(compiled.matches("/api/v1/456/posts"));
                black_box(compiled.matches("/static/js/app.js"));
            });
        });
    }

    // Strip prefix
    group.bench_function("strip_prefix", |b| {
        let pattern = PathPattern::compile("/api/v1/**").unwrap();
        b.iter(|| {
            black_box(pattern.strip_prefix("/api/v1/users/123/posts"));
        });
    });

    // Rewrite
    group.bench_function("rewrite", |b| {
        let pattern = PathPattern::compile("/old-api/**").unwrap();
        b.iter(|| {
            black_box(pattern.rewrite("/old-api/users/123", "/new-api/$1"));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Router benchmarks
// ---------------------------------------------------------------------------

fn bench_router(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_handler/router");

    // Build a router with varying route counts
    for route_count in [5, 20, 100] {
        group.bench_with_input(
            BenchmarkId::new("route_match", route_count),
            &route_count,
            |b, &count| {
                let mut router = Router::new();
                for i in 0..count {
                    let config = r0n_ingress::modules::http_handler::config::RouteConfig {
                        name: format!("route-{i}"),
                        path: format!("/api/v{}/resource-{i}", (i % 3) + 1),
                        methods: vec!["GET".to_string()],
                        host: None,
                        headers: HashMap::new(),
                        backend: r0n_ingress::modules::http_handler::config::BackendConfig {
                            address: "10.0.0.1".to_string(),
                            port: 8080,
                            tls: false,
                            verify_tls: true,
                            connect_timeout: None,
                            request_timeout: None,
                        },
                        priority: i as i32,
                        strip_prefix: false,
                        rewrite: None,
                        middleware: vec![],
                    };
                    let route =
                        r0n_ingress::modules::http_handler::router::Route::from_config(config)
                            .unwrap();
                    router.add_route(route);
                }

                let data = generators::http_get_request("/api/v1/resource-0", "example.com");
                let (req, _) = Request::parse(&data).unwrap();

                b.iter(|| {
                    black_box(router.route(&req));
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Middleware chain
// ---------------------------------------------------------------------------

fn bench_middleware(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_handler/middleware");

    group.bench_function("empty_chain", |b| {
        let chain = MiddlewareChain::new();
        let data = generators::http_get_request("/test", "example.com");
        let (req, _) = Request::parse(&data).unwrap();
        b.iter(|| {
            let r = req.clone();
            black_box(chain.process_request(r).unwrap());
        });
    });

    group.bench_function("request_id_middleware", |b| {
        let mut chain = MiddlewareChain::new();
        chain.add(Arc::new(RequestIdMiddleware::new()));
        let data = generators::http_get_request("/test", "example.com");
        let (req, _) = Request::parse(&data).unwrap();
        b.iter(|| {
            let r = req.clone();
            black_box(chain.process_request(r).unwrap());
        });
    });

    group.bench_function("timing_middleware", |b| {
        let mut chain = MiddlewareChain::new();
        chain.add(Arc::new(TimingMiddleware::new()));
        let data = generators::http_get_request("/test", "example.com");
        let (req, _) = Request::parse(&data).unwrap();
        b.iter(|| {
            let r = req.clone();
            black_box(chain.process_request(r).unwrap());
        });
    });

    group.bench_function("full_chain_3_middleware", |b| {
        let mut chain = MiddlewareChain::new();
        chain.add(Arc::new(RequestIdMiddleware::new()));
        chain.add(Arc::new(TimingMiddleware::new()));
        chain.add(Arc::new(
            r0n_ingress::modules::http_handler::middleware::LoggerMiddleware::new(),
        ));
        let data = generators::http_get_request("/test", "example.com");
        let (req, _) = Request::parse(&data).unwrap();
        b.iter(|| {
            let r = req.clone();
            black_box(chain.process_request(r).unwrap());
        });
    });

    group.bench_function("response_chain", |b| {
        let mut chain = MiddlewareChain::new();
        chain.add(Arc::new(TimingMiddleware::new()));
        let data = generators::http_get_request("/test", "example.com");
        let (req, _) = Request::parse(&data).unwrap();
        let resp = Response::ok().text("OK").build();
        b.iter(|| {
            let r = resp.clone();
            black_box(chain.process_response(&req, r).unwrap());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_request_parsing,
    bench_response,
    bench_request_serialization,
    bench_request_builder,
    bench_path_pattern,
    bench_router,
    bench_middleware,
);
criterion_main!(benches);
