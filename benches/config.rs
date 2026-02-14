#![allow(clippy::all)]
//! Benchmarks for the Configuration system.
//!
//! Tests: TOML parsing, config loading, validation, schema generation,
//! config serialization.

mod common;
use common::generators;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use r0n_ingress::config::{
    BasicValidator, ConfigLoader, PortConflictValidator, ValidationError, ValidationResult,
    Validator,
};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// Config loading / parsing
// ---------------------------------------------------------------------------

fn bench_config_loading(c: &mut Criterion) {
    let mut group = c.benchmark_group("config/loading");

    group.bench_function("load_minimal", |b| {
        let loader = ConfigLoader::new();
        let content = generators::minimal_gateway_config();
        b.iter(|| {
            black_box(loader.load_str(&content).unwrap());
        });
    });

    for module_count in [5, 20, 50] {
        group.bench_with_input(
            BenchmarkId::new("load_complex", module_count),
            &module_count,
            |b, &count| {
                let loader = ConfigLoader::new();
                let content = generators::complex_gateway_config(count);
                b.iter(|| {
                    black_box(loader.load_str(&content).unwrap());
                });
            },
        );
    }

    // With validator
    group.bench_function("load_with_basic_validator", |b| {
        let loader = ConfigLoader::new().with_validator(BasicValidator::new());
        let content = generators::minimal_gateway_config();
        b.iter(|| {
            black_box(loader.load_str(&content).unwrap());
        });
    });

    group.bench_function("load_with_port_validator", |b| {
        let loader = ConfigLoader::new().with_validator(PortConflictValidator::new());
        let content = generators::minimal_gateway_config();
        b.iter(|| {
            black_box(loader.load_str(&content).unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn bench_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("config/validation");

    let loader = ConfigLoader::new();
    let config = loader
        .load_str(&generators::minimal_gateway_config())
        .unwrap();

    group.bench_function("basic_validator", |b| {
        let validator = BasicValidator::new();
        b.iter(|| {
            black_box(validator.validate(&config));
        });
    });

    group.bench_function("port_conflict_validator", |b| {
        let validator = PortConflictValidator::new();
        b.iter(|| {
            black_box(validator.validate(&config));
        });
    });

    // Complex config validation
    let complex_config = loader
        .load_str(&generators::complex_gateway_config(50))
        .unwrap();

    group.bench_function("basic_validator_complex", |b| {
        let validator = BasicValidator::new();
        b.iter(|| {
            black_box(validator.validate(&complex_config));
        });
    });

    group.bench_function("port_conflict_complex", |b| {
        let validator = PortConflictValidator::new();
        b.iter(|| {
            black_box(validator.validate(&complex_config));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ValidationResult operations
// ---------------------------------------------------------------------------

fn bench_validation_result(c: &mut Criterion) {
    let mut group = c.benchmark_group("config/validation_result");

    group.bench_function("create_empty", |b| {
        b.iter(|| {
            black_box(ValidationResult::new());
        });
    });

    group.bench_function("add_errors", |b| {
        b.iter(|| {
            let mut result = ValidationResult::new();
            for i in 0..10 {
                result.add_error(ValidationError::error(
                    format!("field_{i}"),
                    format!("Error message {i}"),
                ));
            }
            for i in 0..5 {
                result.add_error(ValidationError::warning(
                    format!("field_{i}"),
                    format!("Warning message {i}"),
                ));
            }
            black_box(&result);
        });
    });

    group.bench_function("is_valid", |b| {
        let result = ValidationResult::new();
        b.iter(|| {
            black_box(result.is_valid());
        });
    });

    group.bench_function("merge_results", |b| {
        b.iter(|| {
            let mut r1 = ValidationResult::new();
            r1.add_error(ValidationError::error("f1", "e1"));
            let mut r2 = ValidationResult::new();
            r2.add_error(ValidationError::error("f2", "e2"));
            r2.add_error(ValidationError::warning("f3", "w1"));
            r1.merge(r2);
            black_box(&r1);
        });
    });

    group.bench_function("errors_only_filter", |b| {
        let mut result = ValidationResult::new();
        for i in 0..20 {
            if i % 3 == 0 {
                result.add_error(ValidationError::warning(format!("f{i}"), format!("w{i}")));
            } else {
                result.add_error(ValidationError::error(format!("f{i}"), format!("e{i}")));
            }
        }
        b.iter(|| {
            black_box(result.errors_only());
            black_box(result.warnings());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ConfigLoader construction
// ---------------------------------------------------------------------------

fn bench_loader_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("config/loader_construction");

    group.bench_function("new_empty", |b| {
        b.iter(|| {
            black_box(ConfigLoader::new());
        });
    });

    group.bench_function("with_validators", |b| {
        b.iter(|| {
            black_box(
                ConfigLoader::new()
                    .with_validator(BasicValidator::new())
                    .with_validator(PortConflictValidator::new()),
            );
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Config file I/O
// ---------------------------------------------------------------------------

fn bench_config_io(c: &mut Criterion) {
    let mut group = c.benchmark_group("config/io");

    group.bench_function("save_and_load", |b| {
        let loader = ConfigLoader::new();
        let config = loader
            .load_str(&generators::minimal_gateway_config())
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bench-config.toml");

        b.iter(|| {
            loader.save(&config, &path).unwrap();
            let loaded = loader.load(&path).unwrap();
            black_box(loaded);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_config_loading,
    bench_validation,
    bench_validation_result,
    bench_loader_construction,
    bench_config_io,
);
criterion_main!(benches);
