//! Criterion benchmarks for PledgeRecon core operations.
//!
//! Run with: cargo bench -p pledgerecon-core

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use pledgerecon_core::config::ScanConfig;
use pledgerecon_core::dependency::build_dependency_graph;
use pledgerecon_core::sbom::SbomGenerator;
use pledgerecon_core::scanner::Scanner;
use pledgerecon_core::secret::{builtin_patterns, scan_source_code, shannon_entropy};
use std::path::PathBuf;

fn fixture_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn bench_dependency_graph(c: &mut Criterion) {
    let mut group = c.benchmark_group("dependency_graph");

    group.bench_function("rust_project", |b| {
        b.iter(|| {
            let dir = fixture_dir("rust-project");
            black_box(build_dependency_graph(&dir).unwrap());
        });
    });

    group.bench_function("node_project", |b| {
        b.iter(|| {
            let dir = fixture_dir("node-project");
            black_box(build_dependency_graph(&dir).unwrap());
        });
    });

    group.bench_function("python_project", |b| {
        b.iter(|| {
            let dir = fixture_dir("python-project");
            black_box(build_dependency_graph(&dir).unwrap());
        });
    });

    group.bench_function("go_project", |b| {
        b.iter(|| {
            let dir = fixture_dir("go-project");
            black_box(build_dependency_graph(&dir).unwrap());
        });
    });

    group.finish();
}

fn bench_full_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_pipeline");

    group.bench_function("rust_offline", |b| {
        b.iter(|| {
            let dir = fixture_dir("rust-project");
            let config = ScanConfig {
                offline: true,
                reachability: false,
                ..ScanConfig::default()
            };
            let scanner = Scanner::new(config);
            black_box(scanner.scan(&dir).unwrap());
        });
    });

    group.bench_function("node_offline", |b| {
        b.iter(|| {
            let dir = fixture_dir("node-project");
            let config = ScanConfig {
                offline: true,
                reachability: false,
                ..ScanConfig::default()
            };
            let scanner = Scanner::new(config);
            black_box(scanner.scan(&dir).unwrap());
        });
    });

    group.bench_function("rust_with_reachability", |b| {
        b.iter(|| {
            let dir = fixture_dir("rust-project");
            let config = ScanConfig {
                offline: true,
                reachability: true,
                ..ScanConfig::default()
            };
            let scanner = Scanner::new(config);
            black_box(scanner.scan(&dir).unwrap());
        });
    });

    group.finish();
}

fn bench_sbom_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("sbom_generation");

    group.bench_function("cyclonedx_rust", |b| {
        let dir = fixture_dir("rust-project");
        let graph = build_dependency_graph(&dir).unwrap();
        let generator = SbomGenerator::from_graph(&graph, &dir);
        b.iter(|| {
            black_box(generator.generate_cyclonedx(&graph).unwrap());
        });
    });

    group.bench_function("spdx_rust", |b| {
        let dir = fixture_dir("rust-project");
        let graph = build_dependency_graph(&dir).unwrap();
        let generator = SbomGenerator::from_graph(&graph, &dir);
        b.iter(|| {
            black_box(generator.generate_spdx(&graph).unwrap());
        });
    });

    group.finish();
}

fn bench_secret_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_scanning");

    group.bench_function("builtin_patterns_compile", |b| {
        b.iter(|| {
            black_box(builtin_patterns());
        });
    });

    group.bench_function("scan_rust_fixture", |b| {
        let dir = fixture_dir("rust-project");
        let patterns = builtin_patterns();
        b.iter(|| {
            black_box(scan_source_code(&dir, &patterns).unwrap());
        });
    });

    group.finish();
}

fn bench_entropy(c: &mut Criterion) {
    c.bench_function("shannon_entropy", |b| {
        let data = "AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        b.iter(|| {
            black_box(shannon_entropy(data));
        });
    });
}

criterion_group!(
    benches,
    bench_dependency_graph,
    bench_full_scan,
    bench_sbom_generation,
    bench_secret_scanning,
    bench_entropy,
);
criterion_main!(benches);
