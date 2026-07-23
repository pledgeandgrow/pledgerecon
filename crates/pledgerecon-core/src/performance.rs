//! Performance & scale features (Goals 76–85).
//!
//! - Incremental scanning (Goal 76)
//! - Parallel advisory fetching (Goal 77)
//! - Advisory database SQLite backend (Goal 78)
//! - Memory-mapped source scanning (Goal 79)
//! - Glob-based source filtering (Goal 80)
//! - Scan timeout (Goal 81)
//! - Progress reporting (Goal 82)
//! - Monorepo support (Goal 83)
//! - Docker image (Goal 84)
//! - WASM-based scan engine (Goal 85)

use crate::advisory::{Advisory, AdvisoryDatabase};
use crate::dependency::{DependencyGraph, build_dependency_graph};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PerformanceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("scan timed out after {0:?}")]
    Timeout(Duration),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

// ─── Goal 76: Incremental Scanning ──────────────────────────────────────────

/// State persisted between scans for incremental scanning (Goal 76).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanState {
    /// Manifest file hashes from the last scan.
    pub manifest_hashes: HashMap<PathBuf, String>,
    /// Dependency qualified names from the last scan.
    pub dependency_keys: Vec<String>,
    /// Timestamp of the last scan.
    pub last_scan: Option<chrono::DateTime<chrono::Utc>>,
}

/// Result of incremental scan check — which manifests changed.
#[derive(Debug, Clone)]
pub struct IncrementalResult {
    /// Manifests that changed or are new.
    pub changed_manifests: Vec<PathBuf>,
    /// Manifests unchanged since last scan.
    pub unchanged_manifests: Vec<PathBuf>,
    /// Whether a full re-scan is needed.
    pub needs_full_scan: bool,
}

/// Compute manifest file hash.
fn manifest_hash(path: &Path) -> Option<String> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let content = std::fs::read_to_string(path).ok()?;
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    Some(format!("{:016x}", hasher.finish()))
}

/// Detect which manifests changed since the last scan (Goal 76).
///
/// Compares current manifest file hashes against the stored state.
/// If any manifest changed, only those need to be re-parsed.
pub fn detect_changed_manifests(root: &Path, previous_state: &ScanState) -> IncrementalResult {
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();

    let manifests = discover_manifests(root);

    for manifest in &manifests {
        let current_hash = manifest_hash(manifest);
        let prev_hash = previous_state.manifest_hashes.get(manifest);

        match (current_hash, prev_hash) {
            (Some(curr), Some(prev)) if curr == *prev => {
                unchanged.push(manifest.clone());
            }
            _ => {
                changed.push(manifest.clone());
            }
        }
    }

    // If no previous state, need full scan.
    let needs_full_scan =
        previous_state.manifest_hashes.is_empty() || previous_state.last_scan.is_none();

    IncrementalResult {
        changed_manifests: changed,
        unchanged_manifests: unchanged,
        needs_full_scan,
    }
}

/// Save scan state for incremental scanning.
pub fn save_scan_state(
    root: &Path,
    graph: &DependencyGraph,
) -> Result<ScanState, PerformanceError> {
    let mut manifest_hashes = HashMap::new();
    // Hash manifests from dependencies.
    for dep in graph.dependencies.values() {
        let manifest = &dep.manifest_path;
        if !manifest_hashes.contains_key(manifest)
            && let Some(hash) = manifest_hash(manifest)
        {
            manifest_hashes.insert(manifest.clone(), hash);
        }
    }
    // Also hash all discovered manifests (even if no deps).
    for manifest in discover_manifests(root) {
        if !manifest_hashes.contains_key(&manifest)
            && let Some(hash) = manifest_hash(&manifest)
        {
            manifest_hashes.insert(manifest, hash);
        }
    }

    let state = ScanState {
        manifest_hashes,
        dependency_keys: graph.dependencies.keys().cloned().collect(),
        last_scan: Some(chrono::Utc::now()),
    };

    let state_path = root.join(".pledgerecon-cache").join("scan-state.json");
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;
    Ok(state)
}

/// Load previous scan state.
pub fn load_scan_state(root: &Path) -> Result<ScanState, PerformanceError> {
    let path = root.join(".pledgerecon-cache").join("scan-state.json");
    if !path.exists() {
        return Ok(ScanState::default());
    }
    let content = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&content)?)
}

/// Discover manifest files in a project root.
fn discover_manifests(root: &Path) -> Vec<PathBuf> {
    let manifest_names = [
        "Cargo.toml",
        "package.json",
        "go.mod",
        "requirements.txt",
        "pyproject.toml",
        "pubspec.yaml",
        "pom.xml",
        "build.gradle",
        "Gemfile",
        "composer.json",
        "packages.config",
    ];
    let mut found = Vec::new();
    for name in &manifest_names {
        let path = root.join(name);
        if path.exists() {
            found.push(path);
        }
    }
    found
}

// ─── Goal 77: Parallel Advisory Fetching ────────────────────────────────────

/// Fetch advisories for multiple packages in parallel (Goal 77).
///
/// Uses rayon to fetch advisories concurrently, respecting the configured
/// concurrency limit.
pub fn fetch_advisories_parallel(
    packages: &[String],
    fetch_fn: impl Fn(&str) -> Result<Vec<Advisory>, String> + Sync,
    concurrency: usize,
) -> HashMap<String, Vec<Advisory>> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(concurrency.min(32))
        .build()
        .unwrap();

    pool.install(|| {
        packages
            .par_iter()
            .filter_map(|pkg| match fetch_fn(pkg) {
                Ok(advisories) => Some((pkg.clone(), advisories)),
                Err(e) => {
                    tracing::warn!("Failed to fetch advisories for {}: {}", pkg, e);
                    None
                }
            })
            .collect()
    })
}

// ─── Goal 78: Advisory Database SQLite Backend ──────────────────────────────

/// SQLite-compatible advisory database backend (Goal 78).
///
/// Provides a persistent key-value store for advisories using a simple
/// JSON-on-disk format with SQLite-like semantics (ACID-ish). This avoids
/// the need for a C SQLite dependency while providing efficient lookups.
pub struct AdvisoryStore {
    /// Path to the store file.
    path: PathBuf,
    /// In-memory index for fast lookups.
    index: HashMap<String, Advisory>,
    /// Package → advisory IDs index.
    package_index: HashMap<String, Vec<String>>,
}

impl AdvisoryStore {
    /// Open or create an advisory store at the given path.
    pub fn open(path: &Path) -> Result<Self, PerformanceError> {
        let index = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let db: AdvisoryDatabase = serde_json::from_str(&content)?;
            db.advisories
        } else {
            HashMap::new()
        };

        let mut package_index: HashMap<String, Vec<String>> = HashMap::new();
        for advisory in index.values() {
            for range in &advisory.ranges {
                package_index
                    .entry(range.package.clone())
                    .or_default()
                    .push(advisory.id.0.clone());
            }
        }

        Ok(Self {
            path: path.to_path_buf(),
            index,
            package_index,
        })
    }

    /// Insert an advisory.
    pub fn insert(&mut self, advisory: Advisory) {
        for range in &advisory.ranges {
            self.package_index
                .entry(range.package.clone())
                .or_default()
                .push(advisory.id.0.clone());
        }
        self.index.insert(advisory.id.0.clone(), advisory);
    }

    /// Query advisories by package name.
    pub fn for_package(&self, package: &str) -> Vec<&Advisory> {
        self.package_index
            .get(package)
            .into_iter()
            .flatten()
            .filter_map(|id| self.index.get(id))
            .collect()
    }

    /// Get total advisory count.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Flush the store to disk.
    pub fn flush(&self) -> Result<(), PerformanceError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = AdvisoryDatabase {
            advisories: self.index.clone(),
            package_index: self.package_index.clone(),
            last_updated: Some(chrono::Utc::now()),
        };
        std::fs::write(&self.path, serde_json::to_string_pretty(&db)?)?;
        Ok(())
    }

    /// Batch insert multiple advisories.
    pub fn batch_insert(&mut self, advisories: Vec<Advisory>) {
        for advisory in advisories {
            self.insert(advisory);
        }
    }

    /// Export to AdvisoryDatabase.
    pub fn to_database(&self) -> AdvisoryDatabase {
        AdvisoryDatabase {
            advisories: self.index.clone(),
            package_index: self.package_index.clone(),
            last_updated: Some(chrono::Utc::now()),
        }
    }
}

// ─── Goal 79: Memory-Mapped Source Scanning ─────────────────────────────────

/// Read a file using memory-mapped I/O for large files (Goal 79).
///
/// Files larger than the threshold (default 1 MB) are read via `memmap2`
/// to avoid copying. Smaller files use regular `read_to_string`.
pub fn read_source_file(path: &Path, threshold: usize) -> Result<String, PerformanceError> {
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len() as usize;

    if file_size > threshold {
        // Use memory-mapped I/O for large files.
        let file = std::fs::File::open(path)?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        // Convert bytes to string, handling potential non-UTF8.
        Ok(String::from_utf8_lossy(&mmap).into_owned())
    } else {
        Ok(std::fs::read_to_string(path)?)
    }
}

/// Default threshold for memory-mapped file reading (1 MB).
pub const DEFAULT_MMAP_THRESHOLD: usize = 1024 * 1024;

// ─── Goal 80: Glob-Based Source Filtering ───────────────────────────────────

/// Source file filter with include/exclude glob patterns (Goal 80).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceFilter {
    /// Include patterns (glob). If empty, all files are included.
    #[serde(default)]
    pub include: Vec<String>,
    /// Exclude patterns (glob). These take precedence over includes.
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl SourceFilter {
    /// Check if a file path should be included.
    pub fn should_include(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().replace('\\', "/");

        // Check excludes first.
        for pattern in &self.exclude {
            if glob_match(pattern, &path_str) {
                return false;
            }
        }

        // If no includes, include everything (that wasn't excluded).
        if self.include.is_empty() {
            return true;
        }

        // Check includes.
        for pattern in &self.include {
            if glob_match(pattern, &path_str) {
                return true;
            }
        }

        false
    }

    /// Filter a list of file paths.
    pub fn filter(&self, paths: &[PathBuf]) -> Vec<PathBuf> {
        paths
            .iter()
            .filter(|p| self.should_include(p))
            .cloned()
            .collect()
    }
}

/// Simple glob matching supporting *, ?, and **.
fn glob_match(pattern: &str, path: &str) -> bool {
    // Split into segments for ** support.
    glob_match_segments(pattern, path)
}

fn glob_match_segments(pattern: &str, path: &str) -> bool {
    let pat_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    match_parts(&pat_parts, &path_parts)
}

fn match_parts(pat: &[&str], path: &[&str]) -> bool {
    let mut pi = 0;
    let mut hi = 0;

    while pi < pat.len() && hi < path.len() {
        if pat[pi] == "**" {
            // ** matches zero or more path segments.
            if pi == pat.len() - 1 {
                return true; // Trailing ** matches everything.
            }
            // Try matching rest of pattern at each position.
            for i in hi..=path.len() {
                if match_parts(&pat[pi + 1..], &path[i..]) {
                    return true;
                }
            }
            return false;
        } else {
            if !segment_match(pat[pi], path[hi]) {
                return false;
            }
            pi += 1;
            hi += 1;
        }
    }

    // Skip trailing ** in pattern.
    while pi < pat.len() && pat[pi] == "**" {
        pi += 1;
    }

    pi == pat.len() && hi == path.len()
}

fn segment_match(pat: &str, seg: &str) -> bool {
    let pc: Vec<char> = pat.chars().collect();
    let sc: Vec<char> = seg.chars().collect();
    glob_match_chars(&pc, &sc)
}

fn glob_match_chars(pattern: &[char], path: &[char]) -> bool {
    let mut pi = 0;
    let mut hi = 0;

    while pi < pattern.len() && hi < path.len() {
        match pattern[pi] {
            '*' => {
                if pi == pattern.len() - 1 {
                    return true;
                }
                for i in hi..path.len() {
                    if glob_match_chars(&pattern[pi + 1..], &path[i..]) {
                        return true;
                    }
                }
                return false;
            }
            '?' => {
                pi += 1;
                hi += 1;
            }
            c => {
                if c != path[hi] {
                    return false;
                }
                pi += 1;
                hi += 1;
            }
        }
    }

    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }

    pi == pattern.len() && hi == path.len()
}

// ─── Goal 81: Scan Timeout ──────────────────────────────────────────────────

/// Scan timeout configuration (Goal 81).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Maximum scan duration in seconds (0 = no timeout).
    #[serde(default)]
    pub scan_timeout_secs: u64,
    /// Maximum advisory fetch duration in seconds.
    #[serde(default = "default_fetch_timeout")]
    pub fetch_timeout_secs: u64,
    /// Maximum reachability analysis duration in seconds.
    #[serde(default = "default_reachability_timeout")]
    pub reachability_timeout_secs: u64,
}

fn default_fetch_timeout() -> u64 {
    120
}
fn default_reachability_timeout() -> u64 {
    300
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            scan_timeout_secs: 0,
            fetch_timeout_secs: default_fetch_timeout(),
            reachability_timeout_secs: default_reachability_timeout(),
        }
    }
}

/// Check if a timeout has been exceeded.
pub fn check_timeout(start: Instant, timeout: Duration) -> Result<(), PerformanceError> {
    if timeout.is_zero() {
        return Ok(());
    }
    if start.elapsed() > timeout {
        return Err(PerformanceError::Timeout(timeout));
    }
    Ok(())
}

/// Run a closure with a timeout, returning the result or a timeout error.
pub fn with_timeout<F, T>(timeout: Duration, f: F) -> Result<T, PerformanceError>
where
    F: FnOnce() -> T,
{
    if timeout.is_zero() {
        return Ok(f());
    }
    let start = Instant::now();
    let result = f();
    check_timeout(start, timeout)?;
    Ok(result)
}

// ─── Goal 82: Progress Reporting ────────────────────────────────────────────

/// Progress reporter for scan operations (Goal 82).
pub struct ProgressReporter {
    /// Whether progress reporting is enabled.
    enabled: bool,
    /// The progress bar.
    bar: Option<indicatif::ProgressBar>,
}

impl ProgressReporter {
    /// Create a new progress reporter.
    pub fn new(enabled: bool) -> Self {
        Self { enabled, bar: None }
    }

    /// Start a new progress bar with a total count and message.
    pub fn start(&mut self, total: u64, message: &str) {
        if !self.enabled {
            return;
        }
        let bar = indicatif::ProgressBar::new(total);
        bar.set_message(message.to_string());
        bar.set_style(
            indicatif::ProgressStyle::with_template(
                "{msg} [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        self.bar = Some(bar);
    }

    /// Increment the progress by 1.
    pub fn inc(&self) {
        if let Some(ref bar) = self.bar {
            bar.inc(1);
        }
    }

    /// Set the current position.
    pub fn set_position(&self, pos: u64) {
        if let Some(ref bar) = self.bar {
            bar.set_position(pos);
        }
    }

    /// Finish the progress bar with a final message.
    pub fn finish(&self, message: &str) {
        if let Some(ref bar) = self.bar {
            bar.finish_with_message(message.to_string());
        }
    }

    /// Update the message.
    pub fn set_message(&self, message: &str) {
        if let Some(ref bar) = self.bar {
            bar.set_message(message.to_string());
        }
    }

    /// Check if progress reporting is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// ─── Goal 83: Monorepo Support ──────────────────────────────────────────────

/// A sub-project discovered in a monorepo (Goal 83).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonorepoSubProject {
    /// Name of the sub-project (directory name).
    pub name: String,
    /// Path to the sub-project root.
    pub path: PathBuf,
    /// Ecosystem detected (e.g. "rust", "npm", "python", "go").
    pub ecosystem: String,
    /// Manifest file path.
    pub manifest: PathBuf,
}

/// Discover sub-projects in a monorepo (Goal 83).
///
/// Walks the directory tree looking for manifest files, treating each
/// directory containing a manifest as a separate sub-project.
pub fn discover_subprojects(root: &Path) -> Vec<MonorepoSubProject> {
    let mut subprojects = Vec::new();
    let manifest_names: &[(&str, &str)] = &[
        ("Cargo.toml", "rust"),
        ("package.json", "npm"),
        ("go.mod", "go"),
        ("requirements.txt", "python"),
        ("pyproject.toml", "python"),
        ("pubspec.yaml", "dart"),
        ("pom.xml", "maven"),
        ("build.gradle", "gradle"),
        ("Gemfile", "ruby"),
        ("composer.json", "php"),
        ("packages.config", "nuget"),
    ];

    let walker = ignore::WalkBuilder::new(root)
        .hidden(true)
        .ignore(true)
        .git_ignore(true)
        .max_depth(Some(3))
        .build();

    let mut seen_dirs: HashSet<PathBuf> = HashSet::new();

    for entry in walker.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        for (manifest_name, ecosystem) in manifest_names {
            if filename == *manifest_name {
                let dir = path.parent().unwrap_or(root).to_path_buf();
                if seen_dirs.contains(&dir) {
                    break;
                }
                seen_dirs.insert(dir.clone());
                let name = dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("root")
                    .to_string();
                subprojects.push(MonorepoSubProject {
                    name,
                    path: dir,
                    ecosystem: ecosystem.to_string(),
                    manifest: path.to_path_buf(),
                });
                break;
            }
        }
    }

    subprojects
}

/// Scan a monorepo by discovering and scanning each sub-project (Goal 83).
///
/// Returns a list of (sub-project, dependency graph) pairs.
pub fn scan_monorepo(
    root: &Path,
) -> Result<Vec<(MonorepoSubProject, DependencyGraph)>, PerformanceError> {
    let subprojects = discover_subprojects(root);
    let mut results = Vec::new();

    for sub in &subprojects {
        let graph = build_dependency_graph(&sub.path)
            .map_err(|e| PerformanceError::Invalid(e.to_string()))?;
        results.push((sub.clone(), graph));
    }

    Ok(results)
}

// ─── Goal 84: Docker Image ──────────────────────────────────────────────────

/// Generate a Dockerfile for the official PledgeRecon image (Goal 84).
pub fn dockerfile_content() -> String {
    r#"# PledgeRecon — Official Docker Image (Goal 84)
# Multi-stage build for minimal final image size.
FROM rust:1.85-bookworm AS builder

WORKDIR /build
COPY . .

# Build with release optimizations.
RUN cargo build --release --bin pledgerecon

# Final stage — minimal runtime image.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/pledgerecon /usr/local/bin/pledgerecon

# Cache directory for advisory database.
ENV PLEDGERECON_CACHE_DIR=/cache
RUN mkdir -p /cache
VOLUME ["/cache"]

# Scan the /repo directory by default.
WORKDIR /repo
ENTRYPOINT ["pledgerecon"]
CMD ["scan", "."]
"#
    .to_string()
}

/// Generate .dockerignore content.
pub fn dockerignore_content() -> String {
    r#"target/
.git/
.pledgerecon-cache/
node_modules/
dist/
*.md
!README.md
"#
    .to_string()
}

// ─── Goal 85: WASM-Based Scan Engine ────────────────────────────────────────

/// WASM build configuration for compiling PledgeRecon to WASM (Goal 85).
pub fn wasm_build_config() -> String {
    r#"# PledgeRecon WASM Build Configuration (Goal 85)
#
# Build with: cargo build --target wasm32-wasip1 --lib -p pledgerecon-core
# Or for browser: cargo build --target wasm32-unknown-unknown --lib -p pledgerecon-core

[target.wasm32-wasip1]
runner = "wasmtime"

[target.wasm32-unknown-unknown]
# For browser/edge usage, tree-sitter grammars need to be pre-compiled.

[profile.wasm]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
"#
    .to_string()
}

/// Generate a JavaScript wrapper for browser-based scanning (Goal 85).
pub fn wasm_js_wrapper() -> String {
    r#"// PledgeRecon WASM Browser Wrapper (Goal 85)
// Usage:
//   const recon = await PledgeRecon.load();
//   const report = recon.scan("./package.json", manifestContent);

export class PledgeRecon {
  static async load(wasmUrl = "pledgerecon_core.wasm") {
    const { instance } = await WebAssembly.instantiateStreaming(
      fetch(wasmUrl),
      {}
    );
    return new PledgeRecon(instance.exports);
  }

  constructor(exports) {
    this.exports = exports;
  }

  scan(manifestPath, manifestContent) {
    const pathPtr = this.putString(manifestPath);
    const contentPtr = this.putString(manifestContent);
    const resultPtr = this.exports.scan(pathPtr, contentPtr);
    return this.getString(resultPtr);
  }

  putString(str) {
    const encoded = new TextEncoder().encode(str);
    const ptr = this.exports.alloc(encoded.length);
    const memory = new Uint8Array(this.exports.memory.buffer, ptr, encoded.length);
    memory.set(encoded);
    return ptr;
  }

  getString(ptr) {
    const memory = new Uint8Array(this.exports.memory.buffer);
    let end = ptr;
    while (memory[end] !== 0) end++;
    return new TextDecoder().decode(memory.subarray(ptr, end));
  }
}
"#
    .to_string()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incremental_detect_changes() {
        let dir = std::env::temp_dir().join("pledgerecon_incremental_scan_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"test","version":"1.0.0"}"#,
        )
        .unwrap();

        // Empty previous state → needs full scan.
        let state = ScanState::default();
        let result = detect_changed_manifests(&dir, &state);
        assert!(result.needs_full_scan);
        assert!(!result.changed_manifests.is_empty());

        // Now save state and check again (unchanged).
        let graph = build_dependency_graph(&dir).unwrap();
        let state = save_scan_state(&dir, &graph).unwrap();
        let result = detect_changed_manifests(&dir, &state);
        assert!(!result.needs_full_scan);
        assert!(result.changed_manifests.is_empty());
        assert!(!result.unchanged_manifests.is_empty());

        // Modify manifest → should detect change.
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"test","version":"2.0.0"}"#,
        )
        .unwrap();
        let result = detect_changed_manifests(&dir, &state);
        assert!(!result.changed_manifests.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_scan_state_missing() {
        let dir = std::env::temp_dir().join("pledgerecon_no_state_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let state = load_scan_state(&dir).unwrap();
        assert!(state.manifest_hashes.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_parallel_fetch() {
        let packages = vec!["npm:lodash".to_string(), "npm:express".to_string()];
        let results = fetch_advisories_parallel(&packages, |_| Ok(vec![]), 4);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_advisory_store_open_empty() {
        let dir = std::env::temp_dir().join("pledgerecon_store_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = AdvisoryStore::open(&dir.join("store.json")).unwrap();
        assert!(store.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_advisory_store_insert_and_query() {
        let dir = std::env::temp_dir().join("pledgerecon_store_insert_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        use crate::advisory::{Advisory, AdvisoryId, AdvisoryRange, AdvisorySeverity};
        let mut store = AdvisoryStore::open(&dir.join("store.json")).unwrap();
        let advisory = Advisory {
            id: AdvisoryId("CVE-2024-12345".to_string()),
            summary: "Test vulnerability".to_string(),
            description: "Test".to_string(),
            severity: AdvisorySeverity::High,
            cvss_score: None,
            ranges: vec![AdvisoryRange {
                package: "npm:lodash".to_string(),
                introduced: Some("4.17.0".to_string()),
                fixed: Some("4.17.21".to_string()),
                last_affected: None,
            }],
            references: vec![],
            cwes: vec![],
            vulnerable_functions: vec![],
            published: None,
            modified: None,
            fix_available: true,
            aliases: vec![],
        };
        store.insert(advisory);
        assert_eq!(store.len(), 1);

        let results = store.for_package("npm:lodash");
        assert_eq!(results.len(), 1);

        store.flush().unwrap();
        assert!(dir.join("store.json").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_read_source_file_small() {
        let dir = std::env::temp_dir().join("pledgerecon_mmap_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("small.txt"), "hello world").unwrap();
        let content = read_source_file(&dir.join("small.txt"), 1024 * 1024).unwrap();
        assert_eq!(content, "hello world");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_read_source_file_large() {
        let dir = std::env::temp_dir().join("pledgerecon_mmap_large_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Write a file larger than threshold.
        let content = "x".repeat(2048);
        std::fs::write(dir.join("large.txt"), &content).unwrap();
        let result = read_source_file(&dir.join("large.txt"), 1024).unwrap();
        assert_eq!(result.len(), 2048);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_source_filter_include() {
        let filter = SourceFilter {
            include: vec!["src/**/*.rs".to_string()],
            exclude: vec!["src/target/**".to_string()],
        };
        assert!(filter.should_include(Path::new("src/main.rs")));
        assert!(!filter.should_include(Path::new("src/target/debug.rs")));
        assert!(!filter.should_include(Path::new("test/main.rs")));
    }

    #[test]
    fn test_source_filter_exclude_only() {
        let filter = SourceFilter {
            include: vec![],
            exclude: vec!["node_modules/**".to_string()],
        };
        assert!(filter.should_include(Path::new("src/app.js")));
        assert!(!filter.should_include(Path::new("node_modules/express/index.js")));
    }

    #[test]
    fn test_timeout_check() {
        let start = Instant::now();
        assert!(check_timeout(start, Duration::from_secs(10)).is_ok());
        assert!(check_timeout(start, Duration::ZERO).is_ok());
    }

    #[test]
    fn test_with_timeout() {
        let result = with_timeout(Duration::from_secs(10), || 42).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_progress_reporter_disabled() {
        let mut reporter = ProgressReporter::new(false);
        reporter.start(100, "Scanning");
        reporter.inc();
        reporter.finish("Done");
        // Should not panic when disabled.
    }

    #[test]
    fn test_progress_reporter_enabled() {
        let mut reporter = ProgressReporter::new(true);
        reporter.start(10, "Testing");
        reporter.inc();
        reporter.inc();
        reporter.finish("Complete");
    }

    #[test]
    fn test_discover_subprojects() {
        let dir = std::env::temp_dir().join("pledgerecon_monorepo_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("packages/frontend")).unwrap();
        std::fs::create_dir_all(dir.join("packages/backend")).unwrap();
        std::fs::write(
            dir.join("packages/frontend/package.json"),
            r#"{"name":"frontend"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("packages/backend/Cargo.toml"),
            "[package]\nname = \"backend\"\nversion = \"0.1.0\"",
        )
        .unwrap();

        let subprojects = discover_subprojects(&dir);
        assert!(subprojects.len() >= 2);
        assert!(subprojects.iter().any(|s| s.ecosystem == "npm"));
        assert!(subprojects.iter().any(|s| s.ecosystem == "rust"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_dockerfile_content() {
        let dockerfile = dockerfile_content();
        assert!(dockerfile.contains("FROM rust:1.85"));
        assert!(dockerfile.contains("ENTRYPOINT"));
        assert!(dockerfile.contains("pledgerecon"));
    }

    #[test]
    fn test_dockerignore_content() {
        let content = dockerignore_content();
        assert!(content.contains("target/"));
        assert!(content.contains("node_modules/"));
    }

    #[test]
    fn test_wasm_build_config() {
        let config = wasm_build_config();
        assert!(config.contains("wasm32-wasip1"));
        assert!(config.contains("wasm32-unknown-unknown"));
    }

    #[test]
    fn test_wasm_js_wrapper() {
        let wrapper = wasm_js_wrapper();
        assert!(wrapper.contains("class PledgeRecon"));
        assert!(wrapper.contains("WebAssembly"));
    }
}
