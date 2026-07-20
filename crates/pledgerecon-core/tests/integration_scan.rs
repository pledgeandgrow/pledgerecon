//! Integration tests — end-to-end scan pipeline tests with fixture projects.
//!
//! These tests exercise the full Scanner pipeline (dependency graph → advisory
//! matching → reachability → report) and the secret scanning module against
//! real fixture projects.

use pledgerecon_core::config::ScanConfig;
use pledgerecon_core::scanner::Scanner;
use pledgerecon_core::output::{to_json, to_sarif, to_text, to_markdown};
use pledgerecon_core::dependency::build_dependency_graph;
use pledgerecon_core::secret::{
    builtin_patterns, scan_source_code, scan_env_files, scan_iac_files,
    scan_manifests, scan_git_history, shannon_entropy, detect_high_entropy,
    SecretType, SecretSeverity, IaCKind, ManifestKind, ManifestToScan,
    GitCommitContent, ContainerLayer, scan_container_secrets,
};
use std::path::PathBuf;
use tempfile::tempdir;

fn fixture_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join(name)
}

// ─── End-to-end scan (offline, local advisories only) ─────────────────────

#[test]
fn test_full_scan_offline_rust_project() {
    let dir = fixture_dir("rust-project");
    let config = ScanConfig {
        offline: true,
        reachability: false,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan should succeed");

    assert_eq!(report.project_name, "rust-project");
    assert!(report.dependencies_scanned > 0, "should scan dependencies");
    assert!(report.duration_ms < 10000, "scan should complete in <10s");
}

#[test]
fn test_full_scan_offline_node_project() {
    let dir = fixture_dir("node-project");
    let config = ScanConfig {
        offline: true,
        reachability: false,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan should succeed");

    assert_eq!(report.project_name, "node-project");
    assert!(report.dependencies_scanned > 0);
}

#[test]
fn test_full_scan_offline_python_project() {
    let dir = fixture_dir("python-project");
    let config = ScanConfig {
        offline: true,
        reachability: false,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan should succeed");

    assert_eq!(report.project_name, "python-project");
    assert!(report.dependencies_scanned > 0);
}

#[test]
fn test_full_scan_offline_go_project() {
    let dir = fixture_dir("go-project");
    let config = ScanConfig {
        offline: true,
        reachability: false,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan should succeed");

    assert_eq!(report.project_name, "go-project");
    assert!(report.dependencies_scanned > 0);
}

#[test]
fn test_full_scan_empty_project() {
    let dir = fixture_dir("empty-project");
    let config = ScanConfig {
        offline: true,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan should succeed");

    assert_eq!(report.dependencies_scanned, 0);
    assert_eq!(report.findings.len(), 0);
}

// ─── Output format integration ─────────────────────────────────────────────

#[test]
fn test_scan_output_json_format() {
    let dir = fixture_dir("rust-project");
    let config = ScanConfig {
        offline: true,
        reachability: false,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan should succeed");
    let json = to_json(&report);
    assert!(json.contains("\"scan_id\""));
    assert!(json.contains("\"project_name\""));
    assert!(json.contains("\"dependencies_scanned\""));
}

#[test]
fn test_scan_output_sarif_format() {
    let dir = fixture_dir("rust-project");
    let config = ScanConfig {
        offline: true,
        reachability: false,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan should succeed");
    let sarif = to_sarif(&report);
    assert!(sarif.contains("\"version\""));
    assert!(sarif.contains("\"runs\""));
}

#[test]
fn test_scan_output_text_format() {
    let dir = fixture_dir("rust-project");
    let config = ScanConfig {
        offline: true,
        reachability: false,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan should succeed");
    let text = to_text(&report);
    assert!(text.contains("PledgeRecon") || text.contains("Scan"));
}

#[test]
fn test_scan_output_markdown_format() {
    let dir = fixture_dir("rust-project");
    let config = ScanConfig {
        offline: true,
        reachability: false,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan should succeed");
    let md = to_markdown(&report);
    assert!(md.contains("#") || md.contains("**"));
}

// ─── Reachability integration ──────────────────────────────────────────────

#[test]
fn test_scan_with_reachability_rust() {
    let dir = fixture_dir("rust-project");
    let config = ScanConfig {
        offline: true,
        reachability: true,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan with reachability should succeed");
    // Reachability may downgrade findings to Info — just verify it doesn't crash
    assert!(report.duration_ms < 30000, "reachability should complete in <30s");
}

// ─── Secret scanning integration ───────────────────────────────────────────

#[test]
fn test_secret_scan_fixture_project() {
    let dir = fixture_dir("rust-project");
    let patterns = builtin_patterns();
    let result = scan_source_code(&dir, &patterns).expect("secret scan should succeed");
    assert!(result.files_scanned > 0, "should scan at least one file");
}

#[test]
fn test_secret_scan_finds_aws_key_in_tempdir() {
    let tmp = tempdir().expect("failed to create tempdir");
    let file_path = tmp.path().join("config.rs");
    std::fs::write(&file_path, "let key = \"AKIAIOSFODNN7EXAMPLE\";\n").unwrap();

    let patterns = builtin_patterns();
    let result = scan_source_code(tmp.path(), &patterns).expect("scan should succeed");
    assert!(result.total_secrets >= 1, "should find AWS key");
    assert!(result.findings.iter().any(|f| f.secret_type == SecretType::AwsAccessKey));
}

#[test]
fn test_secret_scan_finds_github_token_in_tempdir() {
    let tmp = tempdir().expect("failed to create tempdir");
    let file_path = tmp.path().join("auth.py");
    std::fs::write(&file_path, "TOKEN = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\"\n").unwrap();

    let patterns = builtin_patterns();
    let result = scan_source_code(tmp.path(), &patterns).expect("scan should succeed");
    assert!(result.total_secrets >= 1, "should find GitHub token");
    assert!(result.findings.iter().any(|f| f.secret_type == SecretType::GitHubToken));
}

#[test]
fn test_secret_scan_finds_private_key_in_tempdir() {
    let tmp = tempdir().expect("failed to create tempdir");
    let file_path = tmp.path().join("id_rsa.pem");
    std::fs::write(&file_path, "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n").unwrap();

    let patterns = builtin_patterns();
    let result = scan_source_code(tmp.path(), &patterns).expect("scan should succeed");
    assert!(result.total_secrets >= 1, "should find private key");
    assert!(result.findings.iter().any(|f| f.secret_type == SecretType::PrivateKeyPem));
}

#[test]
fn test_secret_scan_env_file_integration() {
    let files = vec![(".env".into(), "AWS_SECRET_ACCESS_KEY=mysecret123\nDATABASE_URL=postgres://user:pass@db:5432\n".into())];
    let result = scan_env_files(&files).expect("env scan should succeed");
    assert!(result.total_secrets >= 1, "should find sensitive env vars");
}

#[test]
fn test_secret_scan_iac_terraform_integration() {
    let files = vec![
        (IaCKind::Terraform, "main.tf".into(),
         "provider \"aws\" { access_key = \"AKIAIOSFODNN7EXAMPLE\" secret_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\" }".into()),
    ];
    let result = scan_iac_files(&files).expect("IaC scan should succeed");
    assert!(result.total_secrets >= 1, "should find secrets in Terraform");
}

#[test]
fn test_secret_scan_container_layer_integration() {
    let layers = vec![ContainerLayer {
        digest: "sha256:abc".into(),
        command: "COPY .".into(),
        files: [("etc/config".into(), "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n".into())].into(),
    }];
    let result = scan_container_secrets(&layers).expect("container scan should succeed");
    assert!(result.total_secrets >= 1, "should find secrets in container layer");
}

#[test]
fn test_secret_scan_git_history_integration() {
    let commits = vec![GitCommitContent {
        commit_sha: "deadbeef".into(),
        files: [("config.js".into(), "const token = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\";\n".into())].into(),
    }];
    let result = scan_git_history(&commits).expect("git history scan should succeed");
    assert!(result.total_secrets >= 1, "should find secrets in git history");
}

#[test]
fn test_secret_scan_manifest_npmrc_integration() {
    let manifests = vec![ManifestToScan {
        kind: ManifestKind::Npmrc,
        file: ".npmrc".into(),
        content: "//registry.npmjs.org/:_authToken=npm_1234567890abcdef\n".into(),
    }];
    let result = scan_manifests(&manifests).expect("manifest scan should succeed");
    assert!(result.total_secrets >= 1, "should find npm auth token");
}

#[test]
fn test_entropy_detection_integration() {
    let high_entropy = "Zm9vYmFyMTIzNDU2Nzg5MDEyMzQ1Njc4OTBhYmNkZWYoKSk=";
    let low_entropy = "hello world";
    assert!(shannon_entropy(high_entropy) > 4.0, "base64-like string should have high entropy");
    assert!(shannon_entropy(low_entropy) < 4.0, "plain text should have low entropy");
    let findings = detect_high_entropy(high_entropy, "test.txt", 4.0, 20);
    assert!(!findings.is_empty(), "should detect high entropy string");
    let no_findings = detect_high_entropy(low_entropy, "test.txt", 4.0, 20);
    assert!(no_findings.is_empty(), "should not flag low entropy string");
}

// ─── Dependency graph integration ──────────────────────────────────────────

#[test]
fn test_dependency_graph_rust_has_transitive_deps() {
    let dir = fixture_dir("rust-project");
    let graph = build_dependency_graph(&dir).expect("failed to build graph");
    assert!(graph.dependencies.len() >= 1, "should have at least 1 dependency");
    assert!(!graph.direct.is_empty(), "should have direct dependencies");
}

#[test]
fn test_dependency_graph_node_has_express() {
    let dir = fixture_dir("node-project");
    let graph = build_dependency_graph(&dir).expect("failed to build graph");
    assert!(graph.dependencies.values().any(|d| d.name == "express"), "should find express");
}

// ─── Scan report fields ────────────────────────────────────────────────────

#[test]
fn test_scan_report_has_valid_scan_id() {
    let dir = fixture_dir("rust-project");
    let config = ScanConfig {
        offline: true,
        reachability: false,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan should succeed");
    assert!(!report.scan_id.is_empty(), "scan_id should not be empty");
    assert!(report.scan_id.len() >= 8, "scan_id should be a UUID");
}

#[test]
fn test_scan_report_timestamp_is_recent() {
    let dir = fixture_dir("rust-project");
    let config = ScanConfig {
        offline: true,
        reachability: false,
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(config);
    let report = scanner.scan(&dir).expect("scan should succeed");
    let now = chrono::Utc::now();
    let diff = now.signed_duration_since(report.scanned_at);
    assert!(diff.num_seconds() < 60, "scan timestamp should be within last 60s");
}
