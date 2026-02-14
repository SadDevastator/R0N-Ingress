#![allow(clippy::all)]
//! Benchmarks for the ModuleContract lifecycle across all modules.
//!
//! Tests: init, start, stop, pause, resume, heartbeat, metrics, reload latency.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use r0n_ingress::module::{
    Capability, ContractVersion, MetricsPayload, ModuleConfig, ModuleContract, ModuleManifest,
    ModuleStatus,
};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// A minimal stub module to benchmark pure contract overhead
// ---------------------------------------------------------------------------
struct StubModule {
    status: ModuleStatus,
}

impl StubModule {
    fn new() -> Self {
        Self {
            status: ModuleStatus::Stopped,
        }
    }
}

impl ModuleContract for StubModule {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("bench-stub")
            .description("Benchmark stub module")
            .version(0, 1, 0)
            .capability(Capability::Metrics)
            .build()
    }

    fn init(&mut self, _config: ModuleConfig) -> r0n_ingress::module::ModuleResult<()> {
        self.status = ModuleStatus::Initializing;
        Ok(())
    }

    fn start(&mut self) -> r0n_ingress::module::ModuleResult<()> {
        self.status = ModuleStatus::Running;
        Ok(())
    }

    fn stop(&mut self) -> r0n_ingress::module::ModuleResult<()> {
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut m = MetricsPayload::new();
        m.counter("bench_ops", 42);
        m.gauge("bench_latency", 1.23);
        m.histogram("bench_distribution", vec![0.1, 0.5, 1.0, 2.0, 5.0]);
        m
    }

    fn heartbeat(&self) -> bool {
        self.status.is_operational()
    }

    fn pause(&mut self) -> r0n_ingress::module::ModuleResult<()> {
        self.status = ModuleStatus::Paused;
        Ok(())
    }

    fn resume(&mut self) -> r0n_ingress::module::ModuleResult<()> {
        self.status = ModuleStatus::Running;
        Ok(())
    }

    fn reload(&mut self, _config: ModuleConfig) -> r0n_ingress::module::ModuleResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_manifest_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_lifecycle/manifest");

    group.bench_function("simple_manifest", |b| {
        b.iter(|| {
            black_box(
                ModuleManifest::builder("test")
                    .description("A test module")
                    .version(1, 0, 0)
                    .capability(Capability::Metrics)
                    .build(),
            )
        });
    });

    group.bench_function("complex_manifest", |b| {
        b.iter(|| {
            black_box(
                ModuleManifest::builder("complex-test")
                    .description("Complex module with many capabilities")
                    .version(2, 5, 3)
                    .capability(Capability::TcpListener)
                    .capability(Capability::TlsTermination)
                    .capability(Capability::LoadBalancing)
                    .capability(Capability::Metrics)
                    .capability(Capability::HotReload)
                    .capability(Capability::HttpProtocol)
                    .capability(Capability::WebSocketProtocol)
                    .capability(Capability::RateLimiting)
                    .author("R0N Labs")
                    .license("Apache-2.0")
                    .build(),
            )
        });
    });

    group.finish();
}

fn bench_init_start_stop(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_lifecycle/init_start_stop");

    group.bench_function("init", |b| {
        b.iter_with_setup(StubModule::new, |mut module| {
            let config = ModuleConfig::new();
            black_box(module.init(config).unwrap());
        });
    });

    group.bench_function("start", |b| {
        b.iter_with_setup(
            || {
                let mut m = StubModule::new();
                m.init(ModuleConfig::new()).unwrap();
                m
            },
            |mut module| {
                black_box(module.start().unwrap());
            },
        );
    });

    group.bench_function("stop", |b| {
        b.iter_with_setup(
            || {
                let mut m = StubModule::new();
                m.init(ModuleConfig::new()).unwrap();
                m.start().unwrap();
                m
            },
            |mut module| {
                black_box(module.stop().unwrap());
            },
        );
    });

    group.bench_function("full_lifecycle", |b| {
        b.iter(|| {
            let mut m = StubModule::new();
            m.init(ModuleConfig::new()).unwrap();
            m.start().unwrap();
            m.stop().unwrap();
            black_box(&m);
        });
    });

    group.finish();
}

fn bench_pause_resume(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_lifecycle/pause_resume");

    group.bench_function("pause", |b| {
        b.iter_with_setup(
            || {
                let mut m = StubModule::new();
                m.init(ModuleConfig::new()).unwrap();
                m.start().unwrap();
                m
            },
            |mut module| {
                black_box(module.pause().unwrap());
            },
        );
    });

    group.bench_function("resume", |b| {
        b.iter_with_setup(
            || {
                let mut m = StubModule::new();
                m.init(ModuleConfig::new()).unwrap();
                m.start().unwrap();
                m.pause().unwrap();
                m
            },
            |mut module| {
                black_box(module.resume().unwrap());
            },
        );
    });

    group.bench_function("pause_resume_cycle", |b| {
        let mut m = StubModule::new();
        m.init(ModuleConfig::new()).unwrap();
        m.start().unwrap();
        b.iter(|| {
            m.pause().unwrap();
            m.resume().unwrap();
            black_box(&m);
        });
    });

    group.finish();
}

fn bench_heartbeat(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_lifecycle/heartbeat");

    group.bench_function("heartbeat_running", |b| {
        let mut m = StubModule::new();
        m.init(ModuleConfig::new()).unwrap();
        m.start().unwrap();
        b.iter(|| {
            black_box(m.heartbeat());
        });
    });

    group.bench_function("heartbeat_stopped", |b| {
        let m = StubModule::new();
        b.iter(|| {
            black_box(m.heartbeat());
        });
    });

    group.finish();
}

fn bench_metrics(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_lifecycle/metrics");

    group.bench_function("collect_metrics", |b| {
        let mut m = StubModule::new();
        m.init(ModuleConfig::new()).unwrap();
        m.start().unwrap();
        b.iter(|| {
            black_box(m.metrics());
        });
    });

    group.bench_function("metrics_to_prometheus", |b| {
        let mut m = StubModule::new();
        m.init(ModuleConfig::new()).unwrap();
        m.start().unwrap();
        let metrics = m.metrics();
        b.iter(|| {
            black_box(metrics.to_prometheus("bench"));
        });
    });

    group.finish();
}

fn bench_module_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_lifecycle/config");

    group.bench_function("config_create_empty", |b| {
        b.iter(|| {
            black_box(ModuleConfig::new());
        });
    });

    group.bench_function("config_set_get", |b| {
        b.iter(|| {
            let mut config = ModuleConfig::new();
            config.set_string("host", "0.0.0.0");
            config.set_integer("port", 8080);
            config.set_bool("enabled", true);
            black_box(config.get_string("host"));
            black_box(config.get_integer("port"));
            black_box(config.get_bool("enabled"));
        });
    });

    group.bench_function("config_from_raw", |b| {
        let raw = r#"host = "0.0.0.0"
port = 8080
enabled = true
max_connections = 10000"#
            .to_string();
        b.iter(|| {
            black_box(ModuleConfig::from_raw(raw.clone()));
        });
    });

    for count in [5, 20, 100] {
        group.bench_with_input(
            BenchmarkId::new("config_populate", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let mut config = ModuleConfig::new();
                    for i in 0..count {
                        config.set_string(format!("key_{i}"), format!("value_{i}"));
                    }
                    black_box(&config);
                });
            },
        );
    }

    group.finish();
}

fn bench_contract_version(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_lifecycle/contract_version");

    group.bench_function("version_create", |b| {
        b.iter(|| {
            black_box(ContractVersion::new(1, 1, 0));
        });
    });

    group.bench_function("version_compatibility_check", |b| {
        let v1 = ContractVersion::new(1, 0, 0);
        let v2 = ContractVersion::new(1, 1, 0);
        b.iter(|| {
            black_box(v1.is_compatible_with(&v2));
        });
    });

    group.finish();
}

fn bench_status(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_lifecycle/status");

    let statuses = vec![
        ModuleStatus::Initializing,
        ModuleStatus::Running,
        ModuleStatus::Paused,
        ModuleStatus::Stopped,
        ModuleStatus::Error {
            message: "test error".into(),
        },
        ModuleStatus::Degraded {
            reason: "partial failure".into(),
        },
    ];

    group.bench_function("status_checks", |b| {
        b.iter(|| {
            for s in &statuses {
                black_box(s.is_healthy());
                black_box(s.is_operational());
                black_box(s.is_paused());
                black_box(s.is_stopped());
                black_box(s.is_error());
            }
        });
    });

    group.finish();
}

fn bench_reload(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_lifecycle/reload");

    group.bench_function("reload_config", |b| {
        let mut m = StubModule::new();
        m.init(ModuleConfig::new()).unwrap();
        m.start().unwrap();
        b.iter(|| {
            let mut config = ModuleConfig::new();
            config.set_string("host", "0.0.0.0");
            config.set_integer("port", 9090);
            black_box(m.reload(config).unwrap());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_manifest_creation,
    bench_init_start_stop,
    bench_pause_resume,
    bench_heartbeat,
    bench_metrics,
    bench_module_config,
    bench_contract_version,
    bench_status,
    bench_reload,
);
criterion_main!(benches);
