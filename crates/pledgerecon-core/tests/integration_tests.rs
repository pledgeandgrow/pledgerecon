//! Integration tests — end-to-end scan tests with fixture projects.
//!
//! These tests verify that PledgeRecon can:
//! - Parse manifests from different ecosystems
//! - Build dependency graphs
//! - Generate SBOMs
//! - Produce scan reports

use pledgerecon_core::dependency::{DependencyKind, build_dependency_graph};
use pledgerecon_core::sbom::{SbomFormat, SbomGenerator};
use std::path::PathBuf;

fn fixture_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join(name)
}

// ─── Rust Fixture ──────────────────────────────────────────

#[test]
fn test_scan_rust_project() {
    let dir = fixture_dir("rust-project");
    let graph = build_dependency_graph(&dir).expect("failed to build rust dep graph");

    assert!(!graph.is_empty(), "should find at least one dependency");
    assert!(
        graph
            .dependencies
            .values()
            .any(|d| d.kind == DependencyKind::Rust),
        "should find Rust dependencies"
    );
}

#[test]
fn test_rust_project_has_serde() {
    let dir = fixture_dir("rust-project");
    let graph = build_dependency_graph(&dir).expect("failed to build rust dep graph");

    assert!(
        graph.dependencies.values().any(|d| d.name == "serde"),
        "should find serde dependency"
    );
}

// ─── Node.js Fixture ───────────────────────────────────────

#[test]
fn test_scan_node_project() {
    let dir = fixture_dir("node-project");
    let graph = build_dependency_graph(&dir).expect("failed to build node dep graph");

    assert!(!graph.is_empty(), "should find at least one dependency");
    assert!(
        graph
            .dependencies
            .values()
            .any(|d| d.kind == DependencyKind::Npm),
        "should find npm dependencies"
    );
}

#[test]
fn test_node_project_has_express() {
    let dir = fixture_dir("node-project");
    let graph = build_dependency_graph(&dir).expect("failed to build node dep graph");

    assert!(
        graph.dependencies.values().any(|d| d.name == "express"),
        "should find express dependency"
    );
}

// ─── Python Fixture ────────────────────────────────────────

#[test]
fn test_scan_python_project() {
    let dir = fixture_dir("python-project");
    let graph = build_dependency_graph(&dir).expect("failed to build python dep graph");

    assert!(!graph.is_empty(), "should find at least one dependency");
    assert!(
        graph
            .dependencies
            .values()
            .any(|d| d.kind == DependencyKind::Python),
        "should find Python dependencies"
    );
}

#[test]
fn test_python_project_has_django() {
    let dir = fixture_dir("python-project");
    let graph = build_dependency_graph(&dir).expect("failed to build python dep graph");

    assert!(
        graph.dependencies.values().any(|d| d.name == "django"),
        "should find django dependency"
    );
}

// ─── Go Fixture ────────────────────────────────────────────

#[test]
fn test_scan_go_project() {
    let dir = fixture_dir("go-project");
    let graph = build_dependency_graph(&dir).expect("failed to build go dep graph");

    assert!(!graph.is_empty(), "should find at least one dependency");
    assert!(
        graph
            .dependencies
            .values()
            .any(|d| d.kind == DependencyKind::Go),
        "should find Go dependencies"
    );
}

// ─── SBOM Generation ───────────────────────────────────────

#[test]
fn test_generate_cyclonedx_sbom() {
    let dir = fixture_dir("rust-project");
    let graph = build_dependency_graph(&dir).expect("failed to build dep graph");
    let generator = SbomGenerator::from_graph(&graph, &dir);

    let sbom = generator
        .generate_cyclonedx(&graph)
        .expect("failed to generate sbom");
    assert!(sbom.contains("CycloneDX"), "sbom should contain CycloneDX");
    assert!(sbom.contains("1.5"), "sbom should specify version 1.5");
}

#[test]
fn test_generate_spdx_sbom() {
    let dir = fixture_dir("rust-project");
    let graph = build_dependency_graph(&dir).expect("failed to build dep graph");
    let generator = SbomGenerator::from_graph(&graph, &dir);

    let sbom = generator
        .generate_spdx(&graph)
        .expect("failed to generate sbom");
    assert!(sbom.contains("SPDX-2.3"), "sbom should contain SPDX-2.3");
}

#[test]
fn test_generate_sbom_to_file() {
    let dir = fixture_dir("node-project");
    let graph = build_dependency_graph(&dir).expect("failed to build dep graph");
    let generator = SbomGenerator::from_graph(&graph, &dir);

    let tmp = std::env::temp_dir().join("pledgerecon_integration_sbom.json");
    generator
        .generate(&graph, SbomFormat::CycloneDx, &tmp)
        .expect("failed to write sbom");
    assert!(tmp.exists(), "sbom file should exist");
    let content = std::fs::read_to_string(&tmp).expect("failed to read sbom");
    assert!(
        content.contains("CycloneDX"),
        "sbom should contain CycloneDX"
    );
}

// ─── Empty Project ─────────────────────────────────────────

#[test]
fn test_scan_empty_project() {
    let dir = fixture_dir("empty-project");
    let graph = build_dependency_graph(&dir).expect("failed to build dep graph");
    assert_eq!(graph.len(), 0, "empty project should have 0 dependencies");
}
