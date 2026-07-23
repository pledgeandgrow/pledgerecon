//! Scale & Distribution — packaging, CI caching, distributed scanning,
//! and branch diffing (Goals 191–200).

use crate::finding::Finding;
use crate::scanner::ScanReport;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DistributionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not found: {0}")]
    NotFound(String),
}

// ─── Goal 191: Homebrew Formula ──────────────────────────────────────────────

/// Generate a Homebrew formula for PledgeRecon.
pub fn homebrew_formula(version: &str, sha256: &str) -> String {
    format!(
        r##"class Pledgerecon < Formula
  desc "Rust-native dependency vulnerability scanner"
  homepage "https://github.com/pledgeandgrow/pledgerecon"
  url "https://github.com/pledgeandgrow/pledgerecon/releases/download/v{version}/pledgerecon-v{version}-x86_64-apple-darwin.tar.gz"
  sha256 "{sha256}"
  license "MIT"

  depends_on "openssl@3"

  def install
    bin.install "pledgerecon"
    man1.install "pledgerecon.1"
  end

  test do
    assert_match "pledgerecon v{version}", shell_output("#{{bin}}/pledgerecon --version")
  end
end
"##,
        version = version,
        sha256 = sha256
    )
}

// ─── Goal 192: Windows MSI Installer ─────────────────────────────────────────

/// MSI installer configuration (WiX).
pub fn wix_config(version: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="PledgeRecon" Language="1033" Version="{version}" Manufacturer="PledgeLabs" UpgradeCode="{{12345678-1234-1234-1234-123456789012}}">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine" />
    <MajorUpgrade DowngradeErrorMessage="A newer version of PledgeRecon is already installed." />
    <MediaTemplate EmbedCab="yes" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLDIR" Name="PledgeRecon">
          <Component Id="MainExecutable" Guid="{{87654321-4321-4321-4321-210987654321}}">
            <File Id="PledgeReconExe" Source="pledgerecon.exe" KeyPath="yes" />
            <Environment Id="PATH" Name="PATH" Value="[INSTALLDIR]" Permanent="no" Part="last" Action="set" System="yes" />
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="Complete" Title="PledgeRecon" Level="1">
      <ComponentRef Id="MainExecutable" />
    </Feature>
  </Product>
</Wix>
"#,
        version = version
    )
}

// ─── Goal 193: Linux .deb and .rpm Packages ──────────────────────────────────

/// Debian package control file.
pub fn debian_control(version: &str) -> String {
    format!(
        r#"Package: pledgerecon
Version: {version}
Section: security
Priority: optional
Architecture: amd64
Depends: libc6 (>= 2.28), libssl3
Maintainer: PledgeLabs <security@pledgelabs.io>
Description: Rust-native dependency vulnerability scanner
 PledgeRecon scans project dependencies for known vulnerabilities
 using OSV, NVD, and GHSA advisory databases with AST-based
 reachability analysis and LLM-powered triage.
Homepage: https://github.com/pledgeandgrow/pledgerecon
License: MIT
"#,
        version = version
    )
}

/// RPM spec file.
pub fn rpm_spec(version: &str) -> String {
    format!(
        r#"Name:           pledgerecon
Version:        {version}
Release:        1%{{?dist}}
Summary:        Rust-native dependency vulnerability scanner
License:        MIT
URL:            https://github.com/pledgeandgrow/pledgerecon
Source0:        %{{name}}-v%{{version}}-x86_64-unknown-linux-gnu.tar.gz
BuildRequires:  openssl-devel
Requires:       openssl-libs

%description
PledgeRecon scans project dependencies for known vulnerabilities using
OSV, NVD, and GHSA advisory databases with AST-based reachability analysis.

%prep
%setup -q

%install
install -D -m 755 pledgerecon %{{buildroot}}/usr/bin/pledgerecon

%files
%license LICENSE
/usr/bin/pledgerecon

%changelog
* Mon Jan 01 2024 PledgeLabs <security@pledgelabs.io> - {version}-1
- Initial package
"#,
        version = version
    )
}

// ─── Goal 194: Nix Flake ─────────────────────────────────────────────────────

/// Generate a Nix flake for PledgeRecon.
pub fn nix_flake(version: &str) -> String {
    format!(
        r##"{{
  description = "PledgeRecon — Rust-native dependency vulnerability scanner";

  inputs = {{
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  }};

  outputs = {{ self, nixpkgs, flake-utils }}:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.{{system}};
      in {{
        packages.default = pkgs.rustPlatform.buildRustPackage {{
          pname = "pledgerecon";
          version = "{version}";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];
        }};
        devShells.default = pkgs.mkShell {{
          buildInputs = with pkgs; [ rustc cargo pkg-config openssl ];
        }};
      }});
}}
"##,
        version = version
    )
}

// ─── Goal 195: Scoop Manifest ────────────────────────────────────────────────

/// Generate a Scoop manifest for Windows.
pub fn scoop_manifest(version: &str, url: &str, hash: &str) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "version": version,
        "description": "Rust-native dependency vulnerability scanner",
        "homepage": "https://github.com/pledgeandgrow/pledgerecon",
        "license": "MIT",
        "architecture": {
            "64bit": {
                "url": url,
                "hash": hash
            }
        },
        "bin": "pledgerecon.exe",
        "checkver": {
            "github": "https://github.com/pledgeandgrow/pledgerecon"
        },
        "autoupdate": {
            "architecture": {
                "64bit": {
                    "url": "https://github.com/pledgeandgrow/pledgerecon/releases/download/v$version/pledgerecon-v$version-x86_64-pc-windows-msvc.zip"
                }
            }
        }
    })).unwrap_or_default()
}

// ─── Goal 196: Pre-built Binaries with Cross-Compilation ─────────────────────

/// Supported cross-compilation targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrossTarget {
    X86_64LinuxMusl,
    Aarch64LinuxMusl,
    X86_64AppleDarwin,
    Aarch64AppleDarwin,
    X86_64WindowsMsvc,
}

impl CrossTarget {
    pub fn target_triple(&self) -> &'static str {
        match self {
            Self::X86_64LinuxMusl => "x86_64-unknown-linux-musl",
            Self::Aarch64LinuxMusl => "aarch64-unknown-linux-musl",
            Self::X86_64AppleDarwin => "x86_64-apple-darwin",
            Self::Aarch64AppleDarwin => "aarch64-apple-darwin",
            Self::X86_64WindowsMsvc => "x86_64-pc-windows-msvc",
        }
    }
    pub fn archive_name(&self, version: &str) -> String {
        format!("pledgerecon-v{}-{}.tar.gz", version, self.target_triple())
    }
}

/// Generate GitHub Actions matrix for cross-compilation.
pub fn cross_compilation_matrix(version: &str) -> String {
    let targets = [
        CrossTarget::X86_64LinuxMusl,
        CrossTarget::Aarch64LinuxMusl,
        CrossTarget::X86_64AppleDarwin,
        CrossTarget::Aarch64AppleDarwin,
        CrossTarget::X86_64WindowsMsvc,
    ];
    let matrix: Vec<String> = targets
        .iter()
        .map(|t| {
            format!(
                "      - target: {}\n        archive: {}",
                t.target_triple(),
                t.archive_name(version)
            )
        })
        .collect();
    format!("matrix:\n{}", matrix.join("\n"))
}

// ─── Goal 197: GitHub Action v2 ──────────────────────────────────────────────

/// Generate the GitHub Action v2 workflow YAML.
pub fn github_action_v2() -> String {
    r#"name: PledgeRecon Security Scan
on:
  push:
    branches: [main, master]
  pull_request:

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  pledgerecon:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install PledgeRecon
        run: |
          curl -sSL https://github.com/pledgeandgrow/pledgerecon/releases/latest/download/pledgerecon-linux-amd64 -o /usr/local/bin/pledgerecon
          chmod +x /usr/local/bin/pledgerecon
      - name: Run scan
        run: pledgerecon scan --sarif --output results.sarif --sbom --sbom-format cyclonedx --sbom-output sbom.json
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
      - name: PR Review
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const sarif = JSON.parse(fs.readFileSync('results.sarif', 'utf8'));
            const results = sarif.runs[0].results || [];
            if (results.length > 0) {
              await github.rest.issues.createComment({
                ...context.repo,
                issue_number: context.issue.number,
                body: `PledgeRecon found ${results.length} security findings. See the SARIF report for details.`
              });
            }
"#.to_string()
}

// ─── Goal 198: Scan Result Caching in CI ─────────────────────────────────────

/// Cache key based on lockfile hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCache {
    pub lockfile_hash: String,
    pub scan_result: String,
    pub timestamp: String,
}

/// Compute a cache key from lockfile contents.
pub fn compute_cache_key(lockfile_path: &Path) -> Result<String, DistributionError> {
    let content = std::fs::read_to_string(lockfile_path)?;
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

/// Check if cached scan result is still valid.
pub fn is_cache_valid(cache: &ScanCache, lockfile_path: &Path) -> bool {
    match compute_cache_key(lockfile_path) {
        Ok(current_hash) => current_hash == cache.lockfile_hash,
        Err(_) => false,
    }
}

/// Save scan result to cache.
pub fn save_scan_cache(
    cache_dir: &Path,
    lockfile_path: &Path,
    scan_result: &ScanReport,
) -> Result<ScanCache, DistributionError> {
    let hash = compute_cache_key(lockfile_path)?;
    let cache = ScanCache {
        lockfile_hash: hash.clone(),
        scan_result: serde_json::to_string(scan_result)?,
        timestamp: Utc::now().to_rfc3339(),
    };
    let cache_file = cache_dir.join(format!("scan-{}.json", &hash[..16]));
    std::fs::create_dir_all(cache_dir)?;
    std::fs::write(cache_file, serde_json::to_string_pretty(&cache)?)?;
    Ok(cache)
}

/// Load scan result from cache.
pub fn load_scan_cache(
    cache_dir: &Path,
    lockfile_path: &Path,
) -> Result<Option<ScanCache>, DistributionError> {
    let hash = compute_cache_key(lockfile_path)?;
    let cache_file = cache_dir.join(format!("scan-{}.json", &hash[..16]));
    if !cache_file.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(cache_file)?;
    let cache: ScanCache = serde_json::from_str(&content)?;
    if is_cache_valid(&cache, lockfile_path) {
        Ok(Some(cache))
    } else {
        Ok(None)
    }
}

// ─── Goal 199: Distributed Scanning ──────────────────────────────────────────

/// A scan partition for distributed scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPartition {
    pub id: String,
    pub project_path: String,
    pub manifest_files: Vec<String>,
    pub estimated_complexity: u64,
}

/// Partition a monorepo into scan chunks for distributed scanning.
pub fn partition_scan(
    root: &Path,
    max_partitions: usize,
) -> Result<Vec<ScanPartition>, DistributionError> {
    let mut manifests: Vec<(PathBuf, u64)> = Vec::new();

    // Walk the directory and collect manifest files
    collect_manifests(root, &mut manifests)?;

    // Sort by complexity (file size as proxy)
    manifests.sort_by_key(|a| std::cmp::Reverse(a.1));

    // Distribute using round-robin with load balancing
    let mut partitions: Vec<ScanPartition> = (0..max_partitions)
        .map(|i| ScanPartition {
            id: format!("partition-{}", i),
            project_path: root.display().to_string(),
            manifest_files: Vec::new(),
            estimated_complexity: 0,
        })
        .collect();

    for (path, complexity) in manifests {
        let idx = partitions
            .iter()
            .enumerate()
            .min_by_key(|(_, p)| p.estimated_complexity)
            .map(|(i, _)| i)
            .unwrap_or(0);
        partitions[idx]
            .manifest_files
            .push(path.display().to_string());
        partitions[idx].estimated_complexity += complexity;
    }

    // Remove empty partitions
    Ok(partitions
        .into_iter()
        .filter(|p| !p.manifest_files.is_empty())
        .collect())
}

fn collect_manifests(
    dir: &Path,
    manifests: &mut Vec<(PathBuf, u64)>,
) -> Result<(), DistributionError> {
    let manifest_names = [
        "Cargo.toml",
        "package.json",
        "go.mod",
        "requirements.txt",
        "Pipfile",
        "pom.xml",
        "build.gradle",
        "Gemfile",
        "composer.json",
        ".csproj",
        "Package.swift",
        "build.sbt",
        "mix.exs",
        "rebar.config",
        "deps.edn",
        "conanfile.txt",
        "MODULE.bazel",
    ];
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && (name.starts_with('.')
                    || name == "node_modules"
                    || name == "target"
                    || name == "vendor")
            {
                continue;
            }
            collect_manifests(&path, manifests)?;
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && (manifest_names.contains(&name) || name.ends_with(".cabal") || name == "DESCRIPTION")
        {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(1);
            manifests.push((path, size));
        }
    }
    Ok(())
}

/// Merge results from distributed scan partitions.
pub fn merge_scan_results(partitions: Vec<ScanReport>) -> ScanReport {
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut total_duration: u128 = 0;
    for p in partitions {
        all_findings.extend(p.findings);
        total_duration += p.duration_ms as u128;
    }
    ScanReport {
        findings: all_findings,
        scan_id: "merged".into(),
        project_name: "merged".into(),
        scanned_at: Utc::now(),
        duration_ms: total_duration as u64,
        dependencies_scanned: 0,
        advisories_checked: 0,
    }
}

// ─── Goal 200: Scan Result Diffing Across Branches ───────────────────────────

/// The diff between two scan results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiff {
    pub new_findings: Vec<Finding>,
    pub resolved_findings: Vec<Finding>,
    pub unchanged_findings: Vec<Finding>,
    pub summary: ScanDiffSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiffSummary {
    pub new_count: usize,
    pub resolved_count: usize,
    pub unchanged_count: usize,
    pub new_by_severity: HashMap<String, usize>,
    pub resolved_by_severity: HashMap<String, usize>,
}

/// Diff scan results between two branches.
pub fn diff_scan_results(base: &ScanReport, head: &ScanReport) -> ScanDiff {
    let base_ids: std::collections::HashSet<String> = base
        .findings
        .iter()
        .map(|f| format!("{}:{}", f.advisory_id, f.package))
        .collect();
    let head_ids: std::collections::HashSet<String> = head
        .findings
        .iter()
        .map(|f| format!("{}:{}", f.advisory_id, f.package))
        .collect();

    let new_findings: Vec<Finding> = head
        .findings
        .iter()
        .filter(|f| !base_ids.contains(&format!("{}:{}", f.advisory_id, f.package)))
        .cloned()
        .collect();

    let resolved_findings: Vec<Finding> = base
        .findings
        .iter()
        .filter(|f| !head_ids.contains(&format!("{}:{}", f.advisory_id, f.package)))
        .cloned()
        .collect();

    let unchanged_findings: Vec<Finding> = head
        .findings
        .iter()
        .filter(|f| base_ids.contains(&format!("{}:{}", f.advisory_id, f.package)))
        .cloned()
        .collect();

    let mut new_by_severity = HashMap::new();
    for f in &new_findings {
        let key = f.severity.to_string();
        *new_by_severity.entry(key).or_insert(0) += 1;
    }
    let mut resolved_by_severity = HashMap::new();
    for f in &resolved_findings {
        let key = f.severity.to_string();
        *resolved_by_severity.entry(key).or_insert(0) += 1;
    }

    let new_count = new_findings.len();
    let resolved_count = resolved_findings.len();
    let unchanged_count = unchanged_findings.len();

    ScanDiff {
        new_findings,
        resolved_findings,
        unchanged_findings,
        summary: ScanDiffSummary {
            new_count,
            resolved_count,
            unchanged_count,
            new_by_severity,
            resolved_by_severity,
        },
    }
}

/// Render a scan diff as a markdown report.
pub fn diff_to_markdown(diff: &ScanDiff) -> String {
    let mut out = String::new();
    out.push_str("# PledgeRecon Scan Diff\n\n");
    out.push_str(&format!(
        "**New findings:** {} | **Resolved:** {} | **Unchanged:** {}\n\n",
        diff.summary.new_count, diff.summary.resolved_count, diff.summary.unchanged_count
    ));
    if !diff.new_findings.is_empty() {
        out.push_str("## New Findings\n\n");
        for f in &diff.new_findings {
            out.push_str(&format!(
                "- **{}** [{}] {} in {}@{}\n",
                f.severity, f.advisory_id, f.summary, f.package, f.version
            ));
        }
        out.push('\n');
    }
    if !diff.resolved_findings.is_empty() {
        out.push_str("## Resolved Findings\n\n");
        for f in &diff.resolved_findings {
            out.push_str(&format!(
                "- ~~**{}** [{}] {} in {}@{}~~\n",
                f.severity, f.advisory_id, f.summary, f.package, f.version
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
    use std::path::PathBuf;

    fn make_finding(id: &str, pkg: &str, sev: VulnerabilitySeverity) -> Finding {
        Finding {
            advisory_id: id.into(),
            summary: "Test".into(),
            description: "Test".into(),
            severity: sev,
            cvss_score: Some(7.0),
            package: pkg.into(),
            version: "1.0.0".into(),
            fix_version: Some("1.0.1".into()),
            fix_available: true,
            reachability: ReachabilityStatus::Reachable,
            vulnerable_functions: vec![],
            call_chain: vec![],
            status: FindingStatus::Pending,
            triage_explanation: None,
            references: vec![],
            cwes: vec![],
            manifest_path: PathBuf::from("Cargo.toml"),
            aliases: vec![],
        }
    }

    fn make_report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            scan_id: "test".into(),
            project_name: "test".into(),
            scanned_at: Utc::now(),
            duration_ms: 100,
            dependencies_scanned: 10,
            advisories_checked: 5,
            findings,
        }
    }

    #[test]
    fn test_homebrew_formula() {
        let formula = homebrew_formula("1.0.0", "abc123");
        assert!(formula.contains("class Pledgerecon"));
        assert!(formula.contains("1.0.0"));
        assert!(formula.contains("abc123"));
    }

    #[test]
    fn test_wix_config() {
        let wix = wix_config("1.0.0");
        assert!(wix.contains("PledgeRecon"));
        assert!(wix.contains("1.0.0"));
        assert!(wix.contains("PATH"));
    }

    #[test]
    fn test_debian_control() {
        let ctrl = debian_control("1.0.0");
        assert!(ctrl.contains("Package: pledgerecon"));
        assert!(ctrl.contains("1.0.0"));
        assert!(ctrl.contains("amd64"));
    }

    #[test]
    fn test_rpm_spec() {
        let spec = rpm_spec("1.0.0");
        assert!(spec.contains("Name:           pledgerecon"));
        assert!(spec.contains("1.0.0"));
    }

    #[test]
    fn test_nix_flake() {
        let flake = nix_flake("1.0.0");
        assert!(flake.contains("description"));
        assert!(flake.contains("pledgerecon"));
        assert!(flake.contains("1.0.0"));
    }

    #[test]
    fn test_scoop_manifest() {
        let manifest = scoop_manifest("1.0.0", "https://example.com/pledgerecon.zip", "sha256hash");
        let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(parsed["version"], "1.0.0");
        assert_eq!(parsed["bin"], "pledgerecon.exe");
    }

    #[test]
    fn test_cross_targets() {
        assert_eq!(
            CrossTarget::X86_64LinuxMusl.target_triple(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            CrossTarget::Aarch64AppleDarwin.target_triple(),
            "aarch64-apple-darwin"
        );
        let archive = CrossTarget::X86_64LinuxMusl.archive_name("1.0.0");
        assert!(archive.contains("1.0.0"));
        assert!(archive.contains("x86_64-unknown-linux-musl"));
    }

    #[test]
    fn test_cross_matrix() {
        let matrix = cross_compilation_matrix("1.0.0");
        assert!(matrix.contains("x86_64-unknown-linux-musl"));
        assert!(matrix.contains("aarch64-apple-darwin"));
    }

    #[test]
    fn test_github_action_v2() {
        let action = github_action_v2();
        assert!(action.contains("PledgeRecon Security Scan"));
        assert!(action.contains("sarif"));
        assert!(action.contains("sbom"));
        assert!(action.contains("upload-sarif"));
    }

    #[test]
    fn test_cache_key() {
        let dir = std::env::temp_dir();
        let lockfile = dir.join("pledgerecon_test_lockfile.txt");
        std::fs::write(&lockfile, "test content").unwrap();
        let key = compute_cache_key(&lockfile).unwrap();
        assert!(!key.is_empty());
        let key2 = compute_cache_key(&lockfile).unwrap();
        assert_eq!(key, key2);
        std::fs::write(&lockfile, "different content").unwrap();
        let key3 = compute_cache_key(&lockfile).unwrap();
        assert_ne!(key, key3);
        let _ = std::fs::remove_file(&lockfile);
    }

    #[test]
    fn test_scan_cache_save_load() {
        let dir = std::env::temp_dir();
        let cache_dir = dir.join("pledgerecon_cache_test");
        let lockfile = dir.join("pledgerecon_test_lockfile2.txt");
        std::fs::write(&lockfile, "lockfile content").unwrap();
        let report = make_report(vec![make_finding(
            "CVE-2024-1",
            "npm:test",
            VulnerabilitySeverity::High,
        )]);
        let cache = save_scan_cache(&cache_dir, &lockfile, &report).unwrap();
        assert!(!cache.lockfile_hash.is_empty());
        let loaded = load_scan_cache(&cache_dir, &lockfile).unwrap();
        assert!(loaded.is_some());
        // Change lockfile -> cache invalid
        std::fs::write(&lockfile, "changed content").unwrap();
        let loaded2 = load_scan_cache(&cache_dir, &lockfile).unwrap();
        assert!(loaded2.is_none());
        let _ = std::fs::remove_dir_all(&cache_dir);
        let _ = std::fs::remove_file(&lockfile);
    }

    #[test]
    fn test_partition_scan() {
        let dir = std::env::temp_dir().join("pledgerecon_partition_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"a\"").unwrap();
        std::fs::write(dir.join("package.json"), "{}").unwrap();
        let partitions = partition_scan(&dir, 2).unwrap();
        assert!(!partitions.is_empty());
        let total_manifests: usize = partitions.iter().map(|p| p.manifest_files.len()).sum();
        assert_eq!(total_manifests, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_merge_scan_results() {
        let r1 = make_report(vec![make_finding(
            "CVE-1",
            "npm:a",
            VulnerabilitySeverity::High,
        )]);
        let r2 = make_report(vec![make_finding(
            "CVE-2",
            "npm:b",
            VulnerabilitySeverity::Medium,
        )]);
        let merged = merge_scan_results(vec![r1, r2]);
        assert_eq!(merged.findings.len(), 2);
    }

    #[test]
    fn test_diff_scan_results() {
        let base = make_report(vec![
            make_finding("CVE-1", "npm:a", VulnerabilitySeverity::High),
            make_finding("CVE-2", "npm:b", VulnerabilitySeverity::Medium),
        ]);
        let head = make_report(vec![
            make_finding("CVE-1", "npm:a", VulnerabilitySeverity::High),
            make_finding("CVE-3", "npm:c", VulnerabilitySeverity::Critical),
        ]);
        let diff = diff_scan_results(&base, &head);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.unchanged_findings.len(), 1);
        assert_eq!(diff.new_findings[0].advisory_id, "CVE-3");
        assert_eq!(diff.resolved_findings[0].advisory_id, "CVE-2");
    }

    #[test]
    fn test_diff_to_markdown() {
        let base = make_report(vec![make_finding(
            "CVE-1",
            "npm:a",
            VulnerabilitySeverity::High,
        )]);
        let head = make_report(vec![
            make_finding("CVE-1", "npm:a", VulnerabilitySeverity::High),
            make_finding("CVE-2", "npm:b", VulnerabilitySeverity::Critical),
        ]);
        let diff = diff_scan_results(&base, &head);
        let md = diff_to_markdown(&diff);
        assert!(md.contains("New Findings"));
        assert!(md.contains("CVE-2"));
    }
}
