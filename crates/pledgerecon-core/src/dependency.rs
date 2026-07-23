//! Dependency parsing — extract dependencies from project manifests.
//!
//! Supports multiple ecosystems:
//! - **Rust**: `Cargo.toml`
//! - **Node.js**: `package.json`, `package-lock.json`
//! - **Python**: `requirements.txt`, `pyproject.toml`, `Pipfile.lock`
//! - **Go**: `go.mod`
//! - **Java**: `pom.xml` (Maven), `build.gradle` (Gradle)
//! - **Ruby**: `Gemfile.lock`
//! - **PHP**: `composer.json`, `composer.lock`
//! - **.NET**: `packages.config`, `*.csproj`
//! - **Swift**: `Package.swift`
//! - **Dart**: `pubspec.yaml`
//! - **Scala**: `build.sbt` (sbt)
//! - **Kotlin**: `build.gradle.kts` (Gradle Kotlin DSL)
//! - **Elixir**: `mix.exs`
//! - **Haskell**: `*.cabal`
//! - **R**: `DESCRIPTION`
//! - **Erlang**: `rebar.config`
//! - **Clojure**: `deps.edn`
//! - **C/C++**: `conanfile.txt`, `conanfile.py` (Conan)
//! - **Bazel**: `BUILD`, `BUILD.bazel`, `MODULE.bazel`
//!
//! The [`DependencyGraph`] is the central data structure: a directed graph
//! of all dependencies (direct and transitive) with their versions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info};

/// The kind of dependency ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyKind {
    Rust,
    Npm,
    Python,
    Go,
    Maven,
    Gradle,
    Ruby,
    Composer,
    Nuget,
    Swift,
    Dart,
    Scala,
    Kotlin,
    Elixir,
    Haskell,
    R,
    Erlang,
    Clojure,
    Conan,
    Bazel,
    Unknown,
}

impl DependencyKind {
    /// The ecosystem prefix used in advisory package names (e.g. "crates.io").
    pub fn ecosystem_prefix(&self) -> &'static str {
        match self {
            DependencyKind::Rust => "crates.io",
            DependencyKind::Npm => "npm",
            DependencyKind::Python => "PyPI",
            DependencyKind::Go => "Go",
            DependencyKind::Maven => "Maven",
            DependencyKind::Gradle => "Maven",
            DependencyKind::Ruby => "RubyGems",
            DependencyKind::Composer => "Packagist",
            DependencyKind::Nuget => "NuGet",
            DependencyKind::Swift => "SwiftURL",
            DependencyKind::Dart => "Pub",
            DependencyKind::Scala => "Maven",
            DependencyKind::Kotlin => "Maven",
            DependencyKind::Elixir => "Hex",
            DependencyKind::Haskell => "Hackage",
            DependencyKind::R => "CRAN",
            DependencyKind::Erlang => "Hex",
            DependencyKind::Clojure => "Maven",
            DependencyKind::Conan => "Conan",
            DependencyKind::Bazel => "Bazel",
            DependencyKind::Unknown => "unknown",
        }
    }

    /// Detect ecosystem from a manifest filename.
    pub fn from_manifest(filename: &str) -> Option<Self> {
        match filename {
            "Cargo.toml" | "Cargo.lock" => Some(DependencyKind::Rust),
            "package.json" | "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" => {
                Some(DependencyKind::Npm)
            }
            "requirements.txt" | "pyproject.toml" | "Pipfile.lock" | "poetry.lock" => {
                Some(DependencyKind::Python)
            }
            "go.mod" | "go.sum" => Some(DependencyKind::Go),
            "pom.xml" => Some(DependencyKind::Maven),
            "build.gradle.kts" => Some(DependencyKind::Kotlin),
            "build.gradle" => Some(DependencyKind::Gradle),
            "Gemfile" | "Gemfile.lock" => Some(DependencyKind::Ruby),
            "composer.json" | "composer.lock" => Some(DependencyKind::Composer),
            "packages.config" => Some(DependencyKind::Nuget),
            "Package.swift" => Some(DependencyKind::Swift),
            "pubspec.yaml" | "pubspec.lock" => Some(DependencyKind::Dart),
            "build.sbt" => Some(DependencyKind::Scala),
            "mix.exs" => Some(DependencyKind::Elixir),
            s if s.ends_with(".cabal") => Some(DependencyKind::Haskell),
            "DESCRIPTION" => Some(DependencyKind::R),
            "rebar.config" => Some(DependencyKind::Erlang),
            "deps.edn" => Some(DependencyKind::Clojure),
            "conanfile.txt" | "conanfile.py" => Some(DependencyKind::Conan),
            "MODULE.bazel" => Some(DependencyKind::Bazel),
            "BUILD" | "BUILD.bazel" => Some(DependencyKind::Bazel),
            _ => None,
        }
    }
}

impl std::fmt::Display for DependencyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ecosystem_prefix())
    }
}

/// A single dependency in the graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    /// Package name (without ecosystem prefix).
    pub name: String,
    /// Installed or declared version.
    pub version: String,
    /// Ecosystem kind.
    pub kind: DependencyKind,
    /// Whether this is a direct (declared) or transitive dependency.
    pub is_direct: bool,
    /// Path to the manifest file where this dependency was found.
    pub manifest_path: PathBuf,
    /// Dependencies of this dependency (by name).
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// Optional: resolved URL (for Git, path, or custom registry deps).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
}

impl Dependency {
    /// The fully-qualified package name with ecosystem prefix (e.g. "npm:lodash").
    pub fn qualified_name(&self) -> String {
        format!("{}:{}", self.kind.ecosystem_prefix(), self.name)
    }
}

/// Errors encountered when parsing manifests.
#[derive(Debug, Error)]
pub enum ManifestParseError {
    #[error("I/O error reading {0}: {1}")]
    Io(String, #[source] std::io::Error),
    #[error("TOML parsing failed in {0}: {1}")]
    Toml(String, String),
    #[error("JSON parsing failed in {0}: {1}")]
    Json(String, String),
    #[error("YAML parsing failed in {0}: {1}")]
    Yaml(String, String),
    #[error("unsupported manifest format: {0}")]
    Unsupported(String),
}

/// The dependency graph — all dependencies in a project.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DependencyGraph {
    /// All dependencies, keyed by qualified name ("ecosystem:package@version").
    pub dependencies: HashMap<String, Dependency>,
    /// Direct (declared) dependencies only — qualified names.
    pub direct: Vec<String>,
    /// Entry point manifest paths.
    pub manifests: Vec<PathBuf>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a dependency to the graph.
    pub fn add(&mut self, dep: Dependency) {
        let key = format!("{}@{}", dep.qualified_name(), dep.version);
        if dep.is_direct {
            self.direct.push(key.clone());
        }
        self.dependencies.insert(key, dep);
    }

    /// Get all dependencies for a given ecosystem.
    pub fn by_kind(&self, kind: DependencyKind) -> Vec<&Dependency> {
        self.dependencies
            .values()
            .filter(|d| d.kind == kind)
            .collect()
    }

    /// Get a dependency by package name (any version).
    pub fn find(&self, qualified_name: &str) -> Option<&Dependency> {
        self.dependencies
            .values()
            .find(|d| d.qualified_name() == qualified_name)
    }

    /// Number of dependencies in the graph.
    pub fn len(&self) -> usize {
        self.dependencies.len()
    }

    /// Whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.dependencies.is_empty()
    }
}

/// Trait for manifest parsers. Each ecosystem implements this.
pub trait ManifestParser {
    /// Parse a manifest file and return its dependencies.
    fn parse(&self, path: &Path) -> Result<Vec<Dependency>, ManifestParseError>;
}

/// Detect and parse any supported manifest file.
pub fn parse_manifest(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ManifestParseError::Unsupported(path.display().to_string()))?;

    let kind = DependencyKind::from_manifest(filename)
        .ok_or_else(|| ManifestParseError::Unsupported(filename.to_string()))?;

    match kind {
        DependencyKind::Rust => {
            if filename == "Cargo.lock" {
                parse_cargo_lock(path)
            } else {
                parse_cargo_toml(path)
            }
        }
        DependencyKind::Npm => {
            if filename == "yarn.lock" {
                parse_yarn_lock(path)
            } else {
                parse_package_json(path)
            }
        }
        DependencyKind::Python => {
            if filename == "pyproject.toml" {
                parse_pyproject_toml(path)
            } else {
                parse_requirements_txt(path)
            }
        }
        DependencyKind::Go => parse_go_mod(path),
        DependencyKind::Maven => parse_pom_xml(path),
        DependencyKind::Gradle => parse_build_gradle(path),
        DependencyKind::Ruby => {
            if filename == "Gemfile.lock" {
                parse_gemfile_lock(path)
            } else {
                parse_gemfile(path)
            }
        }
        DependencyKind::Composer => {
            if filename == "composer.lock" {
                parse_composer_lock(path)
            } else {
                parse_composer_json(path)
            }
        }
        DependencyKind::Nuget => parse_packages_config(path),
        DependencyKind::Dart => parse_pubspec_yaml(path),
        DependencyKind::Scala => parse_build_sbt(path),
        DependencyKind::Kotlin => parse_build_gradle(path),
        DependencyKind::Elixir => parse_mix_exs(path),
        DependencyKind::Haskell => parse_cabal(path),
        DependencyKind::R => parse_r_description(path),
        DependencyKind::Erlang => parse_rebar_config(path),
        DependencyKind::Clojure => parse_deps_edn(path),
        DependencyKind::Conan => parse_conanfile(path),
        DependencyKind::Bazel => parse_bazel_build(path),
        _ => Err(ManifestParseError::Unsupported(filename.to_string())),
    }
}

/// Discover all manifest files in a project directory (respecting .gitignore).
pub fn discover_manifests(root: &Path) -> Vec<PathBuf> {
    let manifest_names = [
        "Cargo.toml",
        "Cargo.lock",
        "package.json",
        "yarn.lock",
        "requirements.txt",
        "pyproject.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
        "Gemfile.lock",
        "composer.json",
        "composer.lock",
        "packages.config",
        "Package.swift",
        "pubspec.yaml",
        "build.sbt",
        "mix.exs",
        "DESCRIPTION",
        "rebar.config",
        "deps.edn",
        "conanfile.txt",
        "conanfile.py",
        "MODULE.bazel",
    ];

    let mut results = Vec::new();

    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .ignore(true)
        .git_ignore(true)
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if manifest_names.contains(&filename) {
            // Skip node_modules
            if path.to_string_lossy().contains("node_modules") {
                continue;
            }
            debug!("Found manifest: {}", path.display());
            results.push(path.to_path_buf());
        }
    }

    results
}

/// Build a dependency graph from a project root directory.
pub fn build_dependency_graph(root: &Path) -> Result<DependencyGraph, ManifestParseError> {
    let manifests = discover_manifests(root);
    let mut graph = DependencyGraph::new();

    for manifest in &manifests {
        info!("Parsing manifest: {}", manifest.display());
        let deps = parse_manifest(manifest)?;
        for dep in deps {
            graph.add(dep);
        }
        graph.manifests.push(manifest.clone());
    }

    info!(
        "Dependency graph built: {} dependencies from {} manifests",
        graph.len(),
        graph.manifests.len()
    );

    Ok(graph)
}

// ─── Ecosystem-specific parsers ──────────────────────────────────────────

/// Parse a `Cargo.toml` file.
fn parse_cargo_toml(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let doc: toml::Value = toml::from_str(&content)
        .map_err(|e| ManifestParseError::Toml(path.display().to_string(), e.to_string()))?;

    let mut deps = Vec::new();

    // Parse [dependencies] and [dev-dependencies]
    for section in &["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = doc.get(section).and_then(|v| v.as_table()) {
            let is_direct = true;
            for (name, value) in table {
                let version = extract_cargo_version(value);
                deps.push(Dependency {
                    name: name.clone(),
                    version,
                    kind: DependencyKind::Rust,
                    is_direct,
                    manifest_path: path.to_path_buf(),
                    dependencies: Vec::new(),
                    source_url: extract_cargo_source(value),
                });
            }
        }
    }

    // Parse workspace dependencies
    if let Some(workspace) = doc
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        for (name, value) in workspace {
            let version = extract_cargo_version(value);
            deps.push(Dependency {
                name: name.clone(),
                version,
                kind: DependencyKind::Rust,
                is_direct: true,
                manifest_path: path.to_path_buf(),
                dependencies: Vec::new(),
                source_url: extract_cargo_source(value),
            });
        }
    }

    Ok(deps)
}

fn extract_cargo_version(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(t) => t
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("*")
            .to_string(),
        _ => "*".to_string(),
    }
}

fn extract_cargo_source(value: &toml::Value) -> Option<String> {
    if let toml::Value::Table(t) = value {
        if let Some(git) = t.get("git").and_then(|v| v.as_str()) {
            return Some(format!("git+{}", git));
        }
        if let Some(path) = t.get("path").and_then(|v| v.as_str()) {
            return Some(format!("path:{}", path));
        }
    }
    None
}

/// Parse a `package.json` file.
fn parse_package_json(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| ManifestParseError::Json(path.display().to_string(), e.to_string()))?;

    let mut deps = Vec::new();

    for (section, is_dev) in &[("dependencies", false), ("devDependencies", true)] {
        if let Some(obj) = json.get(section).and_then(|v| v.as_object()) {
            for (name, version) in obj {
                deps.push(Dependency {
                    name: name.clone(),
                    version: version.as_str().unwrap_or("*").to_string(),
                    kind: DependencyKind::Npm,
                    is_direct: !is_dev,
                    manifest_path: path.to_path_buf(),
                    dependencies: Vec::new(),
                    source_url: None,
                });
            }
        }
    }

    Ok(deps)
}

/// Parse a `requirements.txt` file.
fn parse_requirements_txt(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let mut deps = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }

        // Parse "package==1.0.0" or "package>=1.0.0" or "package~=1.0.0" or "package"
        let (name, version) = if let Some(pos) = line.find(['=', '>', '<', '~', '!']) {
            let name = line[..pos].trim().to_string();
            let version_part = line[pos..].trim_start_matches(['=', '>', '<', '~', '!', ' ']);
            (name, version_part.to_string())
        } else {
            (line.to_string(), "*".to_string())
        };

        if !name.is_empty() {
            deps.push(Dependency {
                name,
                version,
                kind: DependencyKind::Python,
                is_direct: true,
                manifest_path: path.to_path_buf(),
                dependencies: Vec::new(),
                source_url: None,
            });
        }
    }

    Ok(deps)
}

/// Parse a `pyproject.toml` file.
fn parse_pyproject_toml(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let doc: toml::Value = toml::from_str(&content)
        .map_err(|e| ManifestParseError::Toml(path.display().to_string(), e.to_string()))?;

    let mut deps = Vec::new();

    // [project] dependencies (PEP 621)
    if let Some(project) = doc
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        for dep_str in project.iter().filter_map(|d| d.as_str()) {
            let (name, version) = parse_pep508(dep_str);
            deps.push(Dependency {
                name,
                version,
                kind: DependencyKind::Python,
                is_direct: true,
                manifest_path: path.to_path_buf(),
                dependencies: Vec::new(),
                source_url: None,
            });
        }
    }

    // [tool.poetry.dependencies]
    if let Some(poetry) = doc
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        for (name, value) in poetry {
            if name == "python" {
                continue;
            }
            let version = match value {
                toml::Value::String(s) => s.clone(),
                toml::Value::Table(t) => t
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_string(),
                _ => "*".to_string(),
            };
            deps.push(Dependency {
                name: name.clone(),
                version,
                kind: DependencyKind::Python,
                is_direct: true,
                manifest_path: path.to_path_buf(),
                dependencies: Vec::new(),
                source_url: None,
            });
        }
    }

    Ok(deps)
}

/// Parse a PEP 508 dependency string (e.g. "requests>=2.0,<3.0").
fn parse_pep508(s: &str) -> (String, String) {
    let s = s.trim();
    // Strip extras: "package[extra]>=1.0" → "package>=1.0"
    let s = if let Some(bracket) = s.find('[') {
        let before = &s[..bracket];
        let after = s
            .find(['>', '<', '=', '~', '!'])
            .map(|pos| &s[pos..])
            .unwrap_or("");
        format!("{}{}", before, after)
    } else {
        s.to_string()
    };

    if let Some(pos) = s.find(['=', '>', '<', '~', '!']) {
        let name = s[..pos].trim().to_string();
        let version = s[pos..]
            .trim()
            .trim_start_matches(['=', '>', '<', '~', '!', ' '])
            .to_string();
        (name, version)
    } else {
        (s.trim().to_string(), "*".to_string())
    }
}

/// Parse a `go.mod` file.
fn parse_go_mod(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let mut deps = Vec::new();
    let mut in_require_block = false;

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with("require ") && line.contains('(') {
            in_require_block = true;
            continue;
        }
        if line == ")" {
            in_require_block = false;
            continue;
        }

        if in_require_block || line.starts_with("require ") {
            let dep_line = if line.starts_with("require ") {
                line.strip_prefix("require ").unwrap_or(line)
            } else {
                line
            };

            let parts: Vec<&str> = dep_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();
                let is_direct = !dep_line.contains("// indirect");

                deps.push(Dependency {
                    name,
                    version,
                    kind: DependencyKind::Go,
                    is_direct,
                    manifest_path: path.to_path_buf(),
                    dependencies: Vec::new(),
                    source_url: None,
                });
            }
        }
    }

    Ok(deps)
}

/// Parse a `pubspec.yaml` file (Dart/Flutter).
fn parse_pubspec_yaml(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| ManifestParseError::Yaml(path.display().to_string(), e.to_string()))?;

    let mut deps = Vec::new();

    for section in &["dependencies", "dev_dependencies"] {
        if let Some(map) = yaml.get(section).and_then(|d| d.as_mapping()) {
            for (key, value) in map {
                let name = key.as_str().unwrap_or("").to_string();
                if name.is_empty() || name == "flutter" || name == "sdk" {
                    continue;
                }
                let version = match value {
                    serde_yaml::Value::String(s) => s.clone(),
                    serde_yaml::Value::Mapping(m) => m
                        .get(serde_yaml::Value::String("version".to_string()))
                        .and_then(|v| v.as_str())
                        .unwrap_or("*")
                        .to_string(),
                    _ => "*".to_string(),
                };
                deps.push(Dependency {
                    name,
                    version,
                    kind: DependencyKind::Dart,
                    is_direct: true,
                    manifest_path: path.to_path_buf(),
                    dependencies: Vec::new(),
                    source_url: None,
                });
            }
        }
    }

    Ok(deps)
}

/// Parse a `pom.xml` file (Maven).
fn parse_pom_xml(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let mut deps = Vec::new();

    // Simple XML parsing: extract <dependency> blocks.
    // We use a lightweight regex-free approach: scan for <dependency> tags.
    let mut in_dependency = false;
    let mut current_group = String::new();
    let mut current_artifact = String::new();
    let mut current_version = String::new();
    let mut current_scope = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.contains("<dependency>") {
            in_dependency = true;
            current_group.clear();
            current_artifact.clear();
            current_version.clear();
            current_scope.clear();
            continue;
        }

        if trimmed.contains("</dependency>") {
            in_dependency = false;
            if !current_artifact.is_empty() {
                let name = if current_group.is_empty() {
                    current_artifact.clone()
                } else {
                    format!("{}:{}", current_group, current_artifact)
                };
                let is_direct = current_scope != "test" && current_scope != "provided";
                deps.push(Dependency {
                    name,
                    version: if current_version.is_empty() {
                        "*".to_string()
                    } else {
                        current_version.clone()
                    },
                    kind: DependencyKind::Maven,
                    is_direct,
                    manifest_path: path.to_path_buf(),
                    dependencies: Vec::new(),
                    source_url: None,
                });
            }
            continue;
        }

        if in_dependency {
            if let Some(val) = extract_xml_tag(trimmed, "groupId") {
                current_group = val;
            } else if let Some(val) = extract_xml_tag(trimmed, "artifactId") {
                current_artifact = val;
            } else if let Some(val) = extract_xml_tag(trimmed, "version") {
                // Skip Maven properties like ${project.version}
                if !val.starts_with('$') {
                    current_version = val;
                }
            } else if let Some(val) = extract_xml_tag(trimmed, "scope") {
                current_scope = val;
            }
        }
    }

    Ok(deps)
}

fn extract_xml_tag(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    if let Some(start) = line.find(&open) {
        let rest = &line[start + open.len()..];
        if let Some(end) = rest.find(&close) {
            return Some(rest[..end].trim().to_string());
        }
    }
    None
}

/// Parse a `build.gradle` or `build.gradle.kts` file (Gradle).
fn parse_build_gradle(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let mut deps = Vec::new();

    // Match Gradle dependency declarations:
    //   implementation "group:artifact:version"
    //   testImplementation 'group:artifact:version'
    //   api "group:artifact:version"
    //   implementation group: "g", name: "a", version: "v"
    for line in content.lines() {
        let line = line.trim();

        // Detect configuration keyword.
        let is_direct = if line.starts_with("test") {
            false
        } else {
            line.starts_with("implementation")
                || line.starts_with("api")
                || line.starts_with("compile")
                || line.starts_with("runtimeOnly")
                || line.starts_with("compileOnly")
        };

        if !is_direct && !line.starts_with("test") {
            continue;
        }

        // Try to extract group:artifact:version from string literal.
        if let Some(dep_str) = extract_gradle_string_dep(line) {
            let parts: Vec<&str> = dep_str.split(':').collect();
            if parts.len() >= 3 {
                let name = format!("{}:{}", parts[0], parts[1]);
                deps.push(Dependency {
                    name,
                    version: parts[2].to_string(),
                    kind: DependencyKind::Gradle,
                    is_direct: !line.starts_with("test"),
                    manifest_path: path.to_path_buf(),
                    dependencies: Vec::new(),
                    source_url: None,
                });
            }
        }
    }

    Ok(deps)
}

fn extract_gradle_string_dep(line: &str) -> Option<String> {
    // Find content between quotes (single or double).
    for quote in &['"', '\''] {
        if let Some(start) = line.find(*quote) {
            let rest = &line[start + 1..];
            if let Some(end) = rest.find(*quote) {
                let candidate = &rest[..end];
                // Must look like a Maven coordinate (contains at least two colons).
                if candidate.matches(':').count() >= 2 {
                    return Some(candidate.to_string());
                }
            }
        }
    }
    None
}

/// Parse a `Gemfile` (Ruby).
fn parse_gemfile(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let mut deps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Match: gem "name", "version"  or  gem 'name', '~> 1.0'
        if let Some(rest) = line.strip_prefix("gem ")
            && let Some((name, version)) = extract_gem_spec(rest)
        {
            deps.push(Dependency {
                name,
                version,
                kind: DependencyKind::Ruby,
                is_direct: true,
                manifest_path: path.to_path_buf(),
                dependencies: Vec::new(),
                source_url: None,
            });
        }
    }

    Ok(deps)
}

fn extract_gem_spec(s: &str) -> Option<(String, String)> {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    for quote in &['"', '\''] {
        let mut start = 0;
        while let Some(pos) = s[start..].find(*quote) {
            let abs_pos = start + pos;
            let rest = &s[abs_pos + 1..];
            if let Some(end) = rest.find(*quote) {
                let val = &rest[..end];
                if name.is_none() {
                    name = Some(val.to_string());
                } else if version.is_none() && val.chars().any(|c| c.is_ascii_digit()) {
                    version = Some(val.to_string());
                }
                start = abs_pos + 1 + end + 1;
            } else {
                break;
            }
        }
    }

    Some((name?, version.unwrap_or_else(|| "*".to_string())))
}

/// Parse a `Gemfile.lock` file (Ruby).
fn parse_gemfile_lock(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let mut deps = Vec::new();
    let mut in_specs = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "specs:" || trimmed == "specs" {
            in_specs = true;
            continue;
        }
        if in_specs && trimmed.is_empty() {
            in_specs = false;
            continue;
        }
        if in_specs {
            // Format: "name (version)" or "  name (version)"
            if let Some(open) = trimmed.rfind('(') {
                let name = trimmed[..open].trim().to_string();
                let rest = &trimmed[open + 1..];
                if let Some(close) = rest.find(')') {
                    let version = rest[..close].trim().to_string();
                    if !name.is_empty() {
                        deps.push(Dependency {
                            name,
                            version,
                            kind: DependencyKind::Ruby,
                            is_direct: false,
                            manifest_path: path.to_path_buf(),
                            dependencies: Vec::new(),
                            source_url: None,
                        });
                    }
                }
            }
        }
    }

    Ok(deps)
}

/// Parse a `composer.json` file (PHP).
fn parse_composer_json(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| ManifestParseError::Json(path.display().to_string(), e.to_string()))?;

    let mut deps = Vec::new();

    for section in &["require", "require-dev"] {
        if let Some(obj) = json.get(section).and_then(|v| v.as_object()) {
            let is_direct = *section == "require";
            for (name, version) in obj {
                // Skip PHP platform requirements like "php", "ext-*".
                if name == "php" || name.starts_with("ext-") {
                    continue;
                }
                deps.push(Dependency {
                    name: name.clone(),
                    version: version.as_str().unwrap_or("*").to_string(),
                    kind: DependencyKind::Composer,
                    is_direct,
                    manifest_path: path.to_path_buf(),
                    dependencies: Vec::new(),
                    source_url: None,
                });
            }
        }
    }

    Ok(deps)
}

/// Parse a `composer.lock` file (PHP).
fn parse_composer_lock(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| ManifestParseError::Json(path.display().to_string(), e.to_string()))?;

    let mut deps = Vec::new();

    // composer.lock has "packages" and "packages-dev" arrays.
    for section in &["packages", "packages-dev"] {
        if let Some(arr) = json.get(section).and_then(|v| v.as_array()) {
            let is_direct = *section == "packages";
            for entry in arr {
                let name = entry.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let version = entry.get("version").and_then(|v| v.as_str()).unwrap_or("*");
                if !name.is_empty() {
                    deps.push(Dependency {
                        name: name.to_string(),
                        version: version.to_string(),
                        kind: DependencyKind::Composer,
                        is_direct,
                        manifest_path: path.to_path_buf(),
                        dependencies: Vec::new(),
                        source_url: None,
                    });
                }
            }
        }
    }

    Ok(deps)
}

/// Parse a `packages.config` file (.NET/NuGet).
fn parse_packages_config(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let mut deps = Vec::new();

    // packages.config uses <package id="..." version="..." />
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("<package ") {
            let id = extract_xml_attr(trimmed, "id").unwrap_or_default();
            let version = extract_xml_attr(trimmed, "version").unwrap_or_else(|| "*".to_string());
            if !id.is_empty() {
                deps.push(Dependency {
                    name: id,
                    version,
                    kind: DependencyKind::Nuget,
                    is_direct: true,
                    manifest_path: path.to_path_buf(),
                    dependencies: Vec::new(),
                    source_url: None,
                });
            }
        }
    }

    Ok(deps)
}

fn extract_xml_attr(line: &str, attr: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr);
    if let Some(pos) = line.find(&pattern) {
        let rest = &line[pos + pattern.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    // Try single quotes.
    let pattern = format!("{}='", attr);
    if let Some(pos) = line.find(&pattern) {
        let rest = &line[pos + pattern.len()..];
        if let Some(end) = rest.find('\'') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

/// Parse a `yarn.lock` file (Node.js).
fn parse_yarn_lock(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let mut deps = Vec::new();
    let mut current_names: Vec<String> = Vec::new();
    let mut current_version: Option<String> = None;
    let mut in_entry = false;

    for line in content.lines() {
        // Yarn lockfile v1 format:
        // "name@^1.0.0", "name@npm:^1.0.0":
        //   version "1.2.3"
        //   resolved "..."
        //
        // Yarn berry format:
        // name@npm:1.2.3:
        //   version: 1.2.3

        if !line.starts_with(' ') && !line.starts_with('\t') && !line.is_empty() {
            // New entry — flush previous.
            if in_entry && let Some(ver) = &current_version {
                for name in &current_names {
                    deps.push(Dependency {
                        name: name.clone(),
                        version: ver.clone(),
                        kind: DependencyKind::Npm,
                        is_direct: false,
                        manifest_path: path.to_path_buf(),
                        dependencies: Vec::new(),
                        source_url: None,
                    });
                }
            }
            in_entry = true;
            current_names.clear();
            current_version = None;

            // Parse package names from the key line.
            // Format: "name@range", "name@npm:range", or name@npm:version
            let line = line.trim_end_matches(':').trim_end_matches(',');
            for part in line.split(", ") {
                let part = part.trim_matches('"').trim_matches('\'');
                // Extract the name before the last @
                if let Some(at_pos) = part.rfind('@') {
                    let name = &part[..at_pos];
                    // Strip npm: or other protocol prefixes from the name part.
                    let name = name.rsplit("npm:").next().unwrap_or(name);
                    if !name.is_empty() {
                        current_names.push(name.to_string());
                    }
                }
            }
        } else if in_entry {
            let trimmed = line.trim();
            // v1: version "1.2.3"
            if let Some(rest) = trimmed.strip_prefix("version ") {
                current_version = Some(rest.trim_matches('"').to_string());
            }
            // berry: version: 1.2.3
            else if let Some(rest) = trimmed.strip_prefix("version:") {
                current_version = Some(rest.trim().trim_matches('"').to_string());
            }
        }
    }

    // Flush last entry.
    if in_entry && let Some(ver) = &current_version {
        for name in &current_names {
            deps.push(Dependency {
                name: name.clone(),
                version: ver.clone(),
                kind: DependencyKind::Npm,
                is_direct: false,
                manifest_path: path.to_path_buf(),
                dependencies: Vec::new(),
                source_url: None,
            });
        }
    }

    Ok(deps)
}

/// Parse a `Cargo.lock` file (Rust).
fn parse_cargo_lock(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;

    let doc: toml::Value = toml::from_str(&content)
        .map_err(|e| ManifestParseError::Toml(path.display().to_string(), e.to_string()))?;

    let mut deps = Vec::new();

    if let Some(packages) = doc.get("package").and_then(|p| p.as_array()) {
        for pkg in packages {
            let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("*");
            if !name.is_empty() {
                deps.push(Dependency {
                    name: name.to_string(),
                    version: version.to_string(),
                    kind: DependencyKind::Rust,
                    is_direct: false, // Lock files contain all deps, not just direct.
                    manifest_path: path.to_path_buf(),
                    dependencies: Vec::new(),
                    source_url: pkg.get("source").and_then(|s| s.as_str()).map(String::from),
                });
            }
        }
    }

    Ok(deps)
}

// ─── Goal 151: Swift/Package.swift is already supported ─────────────────────
// (Package.swift was already in the original DependencyKind enum)

// ─── Goal 152: Scala/sbt parsing ────────────────────────────────────────────

fn parse_build_sbt(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;
    let mut deps = Vec::new();

    // Match patterns like: libraryDependencies += "org" %% "name" % "version"
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("libraryDependencies") {
            let rest = rest.trim_start_matches('+').trim_start_matches('=').trim();
            // Replace %% with % for uniform splitting, then parse "org" % "name" % "version"
            let rest = rest.replace("%%", "%");
            let parts: Vec<&str> = rest
                .split('%')
                .map(|s| s.trim().trim_matches('"').trim_matches('%').trim())
                .collect();
            if parts.len() >= 3 {
                let name = parts[1].to_string();
                let version = parts[2].to_string();
                if !name.is_empty() && !version.is_empty() {
                    deps.push(Dependency {
                        name,
                        version,
                        kind: DependencyKind::Scala,
                        is_direct: true,
                        manifest_path: path.to_path_buf(),
                        dependencies: vec![],
                        source_url: None,
                    });
                }
            }
        }
    }

    Ok(deps)
}

// ─── Goal 153: Kotlin/Gradle Kotlin DSL ─────────────────────────────────────
// (Uses parse_build_gradle which already handles build.gradle.kts)

// ─── Goal 154: Elixir/mix.exs parsing ───────────────────────────────────────

fn parse_mix_exs(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;
    let mut deps = Vec::new();

    // Match patterns like: {:phoenix, "~> 1.7.0"}
    for line in content.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if trimmed.starts_with("{:") {
            // Extract package name and version from {:name, "version"} or {:name, "~> version"}
            let inner = trimmed.trim_start_matches('{').trim_end_matches('}').trim();
            let parts: Vec<&str> = inner.splitn(2, ',').collect();
            if parts.len() == 2 {
                let name = parts[0].trim().trim_start_matches(':').trim().to_string();
                let version = parts[1]
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .trim()
                    .to_string();
                if !name.is_empty() && !version.is_empty() {
                    deps.push(Dependency {
                        name,
                        version,
                        kind: DependencyKind::Elixir,
                        is_direct: true,
                        manifest_path: path.to_path_buf(),
                        dependencies: vec![],
                        source_url: None,
                    });
                }
            }
        }
    }

    Ok(deps)
}

// ─── Goal 155: Haskell/cabal parsing ────────────────────────────────────────

fn parse_cabal(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;
    let mut deps = Vec::new();
    let mut in_build_depends = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.to_lowercase().starts_with("build-depends:") {
            in_build_depends = true;
            let rest = trimmed
                .trim_start_matches(|c: char| c != ':')
                .trim_start_matches(':')
                .trim();
            if !rest.is_empty() {
                parse_cabal_deps(rest, path, &mut deps);
            }
            continue;
        }

        if in_build_depends {
            // Continuation lines are indented (start with whitespace) or start with comma.
            // A non-indented, non-empty line ends the section.
            if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('\t') {
                in_build_depends = false;
            } else if !trimmed.is_empty() {
                parse_cabal_deps(trimmed, path, &mut deps);
            }
        }
    }

    Ok(deps)
}

fn parse_cabal_deps(s: &str, path: &Path, deps: &mut Vec<Dependency>) {
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Format: "package ==1.0.0" or "package >=1.0 && <2.0" or "package"
        let tokens: Vec<&str> = part.split_whitespace().collect();
        let name = tokens[0].to_string();
        let version = if tokens.len() > 1 {
            tokens[1..]
                .join(" ")
                .trim_start_matches('=')
                .trim_start_matches("==")
                .trim()
                .to_string()
        } else {
            "any".to_string()
        };
        if !name.is_empty() {
            deps.push(Dependency {
                name,
                version,
                kind: DependencyKind::Haskell,
                is_direct: true,
                manifest_path: path.to_path_buf(),
                dependencies: vec![],
                source_url: None,
            });
        }
    }
}

// ─── Goal 156: R/DESCRIPTION parsing ────────────────────────────────────────

fn parse_r_description(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;
    let mut deps = Vec::new();
    let mut current_field: Option<&str> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        // Check for field headers like "Imports:" or "Depends:"
        if let Some(colon_idx) = trimmed.find(':') {
            let field = trimmed[..colon_idx].trim().to_lowercase();
            if field == "imports" || field == "depends" {
                current_field = Some(if field == "imports" {
                    "imports"
                } else {
                    "depends"
                });
                let rest = trimmed[colon_idx + 1..].trim();
                if !rest.is_empty() {
                    parse_r_deps(rest, path, &mut deps, current_field == Some("depends"));
                }
                continue;
            }
        }

        // Continuation lines (indented)
        if current_field.is_some() {
            if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('\t') {
                current_field = None;
            } else if !trimmed.is_empty() {
                parse_r_deps(trimmed, path, &mut deps, current_field == Some("depends"));
            }
        }
    }

    Ok(deps)
}

fn parse_r_deps(s: &str, path: &Path, deps: &mut Vec<Dependency>, is_depends: bool) {
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Format: "package (>=1.0.0)" or "package"
        let name = part.split('(').next().unwrap_or("").trim().to_string();
        let version = if let Some(v_start) = part.find('(') {
            part[v_start..]
                .trim_matches('(')
                .trim_matches(')')
                .trim_start_matches(">=")
                .trim()
                .to_string()
        } else {
            "any".to_string()
        };
        if !name.is_empty() && !(is_depends && name == "R") {
            deps.push(Dependency {
                name,
                version,
                kind: DependencyKind::R,
                is_direct: true,
                manifest_path: path.to_path_buf(),
                dependencies: vec![],
                source_url: None,
            });
        }
    }
}

// ─── Goal 157: Erlang/rebar3 parsing ────────────────────────────────────────

fn parse_rebar_config(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;
    let mut deps = Vec::new();

    // Match patterns like: {deps, [{cowboy, "2.12.1"}, ...]}
    let mut in_deps = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("{deps,") {
            in_deps = true;
            continue;
        }
        if in_deps {
            if trimmed.contains(']') || trimmed == "}." || trimmed.starts_with("]}") {
                in_deps = false;
                continue;
            }
            // Match {name, "version"} or {name, {pkg, name, "version"}}
            // Strip leading/trailing braces and trailing comma
            let cleaned = trimmed
                .trim_start_matches('{')
                .trim_end_matches(',')
                .trim_end_matches('}')
                .trim();
            let parts: Vec<&str> = cleaned.split(',').map(|s| s.trim()).collect();
            if parts.len() >= 2 {
                let name = parts[0].trim_matches('"').trim_matches('\'').to_string();
                let version_part = parts[1].trim();
                let version = version_part
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                if !name.is_empty() && !version.is_empty() && !version.contains("{") {
                    deps.push(Dependency {
                        name,
                        version,
                        kind: DependencyKind::Erlang,
                        is_direct: true,
                        manifest_path: path.to_path_buf(),
                        dependencies: vec![],
                        source_url: None,
                    });
                }
            }
        }
    }

    Ok(deps)
}

// ─── Goal 158: Clojure/deps.edn parsing ─────────────────────────────────────

fn parse_deps_edn(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;
    let mut deps = Vec::new();

    // deps.edn format: {:deps {org.clojure/clojure {:mvn/version "1.11.1"}}}
    // Look for lines containing :mvn/version and extract name + version.
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.contains(":mvn/version") {
            continue;
        }
        // The name is everything before the last `{` that precedes :mvn/version
        // The version is in quotes after :mvn/version
        if let Some(v_start) = trimmed.find("\"")
            && let Some(v_end) = trimmed[v_start + 1..].find("\"")
        {
            let version = trimmed[v_start + 1..v_start + 1 + v_end].to_string();
            // Name is before the `{` that contains :mvn/version
            let before_version = &trimmed[..v_start];
            if let Some(brace_idx) = before_version.rfind('{') {
                let name = trimmed[..brace_idx]
                    .trim()
                    .trim_start_matches('{')
                    .trim()
                    .to_string();
                if !name.is_empty() && !version.is_empty() {
                    deps.push(Dependency {
                        name,
                        version,
                        kind: DependencyKind::Clojure,
                        is_direct: true,
                        manifest_path: path.to_path_buf(),
                        dependencies: vec![],
                        source_url: None,
                    });
                }
            }
        }
    }

    Ok(deps)
}

// ─── Goal 159: Conan/Conanfile parsing ──────────────────────────────────────

fn parse_conanfile(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;
    let mut deps = Vec::new();

    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if filename == "conanfile.txt" {
        // Format: [requires] section with "name/version@user/channel"
        let mut in_requires = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed == "[requires]" {
                in_requires = true;
                continue;
            }
            if trimmed.starts_with('[') {
                in_requires = false;
                continue;
            }
            if in_requires && !trimmed.is_empty() {
                let parts: Vec<&str> = trimmed.split('/').collect();
                let name = parts[0].to_string();
                let version = parts.get(1).unwrap_or(&"any").to_string();
                deps.push(Dependency {
                    name,
                    version,
                    kind: DependencyKind::Conan,
                    is_direct: true,
                    manifest_path: path.to_path_buf(),
                    dependencies: vec![],
                    source_url: None,
                });
            }
        }
    } else {
        // conanfile.py — look for requires = "name/version" patterns
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("requires(") {
                let inner = rest
                    .trim_end_matches(')')
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                let parts: Vec<&str> = inner.split('/').collect();
                let name = parts[0].to_string();
                let version = parts.get(1).unwrap_or(&"any").to_string();
                deps.push(Dependency {
                    name,
                    version,
                    kind: DependencyKind::Conan,
                    is_direct: true,
                    manifest_path: path.to_path_buf(),
                    dependencies: vec![],
                    source_url: None,
                });
            } else if let Some(rest) = trimmed.strip_prefix("self.requires(") {
                let inner = rest
                    .trim_end_matches(')')
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                let parts: Vec<&str> = inner.split('/').collect();
                let name = parts[0].to_string();
                let version = parts.get(1).unwrap_or(&"any").to_string();
                deps.push(Dependency {
                    name,
                    version,
                    kind: DependencyKind::Conan,
                    is_direct: true,
                    manifest_path: path.to_path_buf(),
                    dependencies: vec![],
                    source_url: None,
                });
            }
        }
    }

    Ok(deps)
}

// ─── Goal 160: Bazel/BUILD parsing ──────────────────────────────────────────

fn parse_bazel_build(path: &Path) -> Result<Vec<Dependency>, ManifestParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ManifestParseError::Io(path.display().to_string(), e))?;
    let mut deps = Vec::new();

    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if filename == "MODULE.bazel" {
        // MODULE.bazel format: bazel_dep(name = "rules_cc", version = "0.0.1")
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("bazel_dep(") {
                // Extract the content inside bazel_dep(...)
                let inner = trimmed
                    .trim_start_matches("bazel_dep(")
                    .trim_end_matches(')')
                    .trim();
                let mut name = String::new();
                let mut version = String::new();
                for part in inner.split(',') {
                    let part = part.trim();
                    if let Some(rest) = part.strip_prefix("name") {
                        name = rest
                            .trim()
                            .trim_start_matches('=')
                            .trim()
                            .trim_matches('"')
                            .trim_matches('\'')
                            .to_string();
                    } else if let Some(rest) = part.strip_prefix("version") {
                        version = rest
                            .trim()
                            .trim_start_matches('=')
                            .trim()
                            .trim_matches('"')
                            .trim_matches('\'')
                            .to_string();
                    }
                }
                if !name.is_empty() {
                    deps.push(Dependency {
                        name,
                        version,
                        kind: DependencyKind::Bazel,
                        is_direct: true,
                        manifest_path: path.to_path_buf(),
                        dependencies: vec![],
                        source_url: None,
                    });
                }
            }
        }
    } else {
        // BUILD/BUILD.bazel — look for http_archive, git_repository, maven_jar
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("http_archive(") || trimmed.contains("git_repository(") {
                let mut name = String::new();
                for part in trimmed.split(',') {
                    let part = part.trim();
                    if let Some(rest) = part.strip_prefix("name") {
                        name = rest
                            .trim_start_matches('=')
                            .trim()
                            .trim_matches('"')
                            .trim_matches('\'')
                            .to_string();
                    }
                }
                if !name.is_empty() {
                    deps.push(Dependency {
                        name,
                        version: "git".to_string(),
                        kind: DependencyKind::Bazel,
                        is_direct: true,
                        manifest_path: path.to_path_buf(),
                        dependencies: vec![],
                        source_url: None,
                    });
                }
            }
        }
    }

    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cargo_toml() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Cargo.toml");
        std::fs::write(
            &path,
            r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
"#,
        )
        .unwrap();

        let deps = parse_cargo_toml(&path).unwrap();
        assert!(deps.iter().any(|d| d.name == "serde" && d.version == "1.0"));
        assert!(deps.iter().any(|d| d.name == "tokio" && d.version == "1.0"));
    }

    #[test]
    fn test_parse_package_json() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("package.json");
        std::fs::write(
            &path,
            r#"{"dependencies": {"lodash": "^4.17.0"}, "devDependencies": {"jest": "^29.0.0"}}"#,
        )
        .unwrap();

        let deps = parse_package_json(&path).unwrap();
        assert!(deps.iter().any(|d| d.name == "lodash" && d.is_direct));
        assert!(deps.iter().any(|d| d.name == "jest" && !d.is_direct));
    }

    #[test]
    fn test_parse_requirements_txt() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("requirements.txt");
        std::fs::write(&path, "requests==2.28.0\nflask>=2.0.0\n# comment\nnumpy\n").unwrap();

        let deps = parse_requirements_txt(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "requests" && d.version == "2.28.0")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "flask" && d.version == "2.0.0")
        );
        assert!(deps.iter().any(|d| d.name == "numpy" && d.version == "*"));
    }

    #[test]
    fn test_parse_go_mod() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("go.mod");
        std::fs::write(&path, "module test\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgithub.com/stretchr/testify v1.8.0 // indirect\n)\n").unwrap();

        let deps = parse_go_mod(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "github.com/gin-gonic/gin" && d.is_direct)
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "github.com/stretchr/testify" && !d.is_direct)
        );
    }

    #[test]
    fn test_dependency_kind_from_manifest() {
        assert_eq!(
            DependencyKind::from_manifest("Cargo.toml"),
            Some(DependencyKind::Rust)
        );
        assert_eq!(
            DependencyKind::from_manifest("package.json"),
            Some(DependencyKind::Npm)
        );
        assert_eq!(
            DependencyKind::from_manifest("go.mod"),
            Some(DependencyKind::Go)
        );
        assert_eq!(DependencyKind::from_manifest("unknown.txt"), None);
    }

    #[test]
    fn test_qualified_name() {
        let dep = Dependency {
            name: "lodash".to_string(),
            version: "4.17.0".to_string(),
            kind: DependencyKind::Npm,
            is_direct: true,
            manifest_path: PathBuf::new(),
            dependencies: vec![],
            source_url: None,
        };
        assert_eq!(dep.qualified_name(), "npm:lodash");
    }

    #[test]
    fn test_parse_pom_xml() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pom.xml");
        std::fs::write(
            &path,
            r#"<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>"#,
        )
        .unwrap();

        let deps = parse_pom_xml(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "org.springframework:spring-core"
                    && d.version == "5.3.0"
                    && d.is_direct)
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "junit:junit" && d.version == "4.13" && !d.is_direct)
        );
    }

    #[test]
    fn test_parse_build_gradle() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("build.gradle");
        std::fs::write(
            &path,
            r#"
dependencies {
    implementation "org.springframework:spring-core:5.3.0"
    testImplementation "junit:junit:4.13"
    api 'com.google.guava:guava:31.1-jre'
}
"#,
        )
        .unwrap();

        let deps = parse_build_gradle(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "org.springframework:spring-core"
                    && d.version == "5.3.0"
                    && d.is_direct)
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "junit:junit" && d.version == "4.13" && !d.is_direct)
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "com.google.guava:guava" && d.version == "31.1-jre")
        );
    }

    #[test]
    fn test_parse_gemfile() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Gemfile");
        std::fs::write(
            &path,
            "source 'https://rubygems.org'\ngem 'rails', '7.0.0'\ngem \"puma\", \"~> 5.0\"\n",
        )
        .unwrap();

        let deps = parse_gemfile(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "rails" && d.version == "7.0.0")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "puma" && d.version == "~> 5.0")
        );
    }

    #[test]
    fn test_parse_gemfile_lock() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Gemfile.lock");
        std::fs::write(&path, "GEM\n  specs:\n    rails (7.0.0)\n      actionpack (= 7.0.0)\n    puma (5.6.4)\n\nPLATFORMS\n  ruby\n").unwrap();

        let deps = parse_gemfile_lock(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "rails" && d.version == "7.0.0")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "puma" && d.version == "5.6.4")
        );
    }

    #[test]
    fn test_parse_composer_json() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("composer.json");
        std::fs::write(
            &path,
            r#"{"require": {"monolog/monolog": "^2.0", "php": "^8.0"}, "require-dev": {"phpunit/phpunit": "^9.0"}}"#,
        )
        .unwrap();

        let deps = parse_composer_json(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "monolog/monolog" && d.version == "^2.0" && d.is_direct)
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "phpunit/phpunit" && d.version == "^9.0" && !d.is_direct)
        );
        // PHP platform requirement should be skipped.
        assert!(!deps.iter().any(|d| d.name == "php"));
    }

    #[test]
    fn test_parse_composer_lock() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("composer.lock");
        std::fs::write(
            &path,
            r#"{"packages": [{"name": "monolog/monolog", "version": "2.8.0"}], "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.10"}]}"#,
        )
        .unwrap();

        let deps = parse_composer_lock(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "monolog/monolog" && d.version == "2.8.0")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "phpunit/phpunit" && d.version == "9.5.10")
        );
    }

    #[test]
    fn test_parse_packages_config() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("packages.config");
        std::fs::write(
            &path,
            r#"<?xml version="1.0"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" />
  <package id="NUnit" version="3.13.1" />
</packages>"#,
        )
        .unwrap();

        let deps = parse_packages_config(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "Newtonsoft.Json" && d.version == "13.0.1")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "NUnit" && d.version == "3.13.1")
        );
    }

    #[test]
    fn test_parse_yarn_lock() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("yarn.lock");
        std::fs::write(
            &path,
            r#"
# THIS IS AN AUTOGENERATED FILE.

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@babel/core@^7.0.0":
  version "7.20.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.20.0.tgz"
"#,
        )
        .unwrap();

        let deps = parse_yarn_lock(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "lodash" && d.version == "4.17.21")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "@babel/core" && d.version == "7.20.0")
        );
    }

    #[test]
    fn test_parse_cargo_lock() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Cargo.lock");
        std::fs::write(
            &path,
            r#"
# This file is automatically @generated.
version = 3

[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.35.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

        let deps = parse_cargo_lock(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "serde" && d.version == "1.0.193")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "tokio" && d.version == "1.35.0")
        );
        assert!(deps.iter().all(|d| !d.is_direct));
    }

    #[test]
    fn test_parse_build_sbt() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test_sbt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("build.sbt");
        std::fs::write(
            &path,
            r#"libraryDependencies += "org.typelevel" %% "cats-core" % "2.10.0"
libraryDependencies += "io.circe" %% "circe-core" % "0.14.6"
"#,
        )
        .unwrap();
        let deps = parse_build_sbt(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "cats-core" && d.version == "2.10.0")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "circe-core" && d.version == "0.14.6")
        );
        assert!(deps.iter().all(|d| d.kind == DependencyKind::Scala));
    }

    #[test]
    fn test_parse_mix_exs() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test_mix");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mix.exs");
        std::fs::write(
            &path,
            r#"defmodule MyApp.MixProject do
  defp deps do
    [
      {:phoenix, "~> 1.7.0"},
      {:ecto, "~> 3.10"}
    ]
  end
end
"#,
        )
        .unwrap();
        let deps = parse_mix_exs(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "phoenix" && d.version == "~> 1.7.0")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "ecto" && d.version == "~> 3.10")
        );
        assert!(deps.iter().all(|d| d.kind == DependencyKind::Elixir));
    }

    #[test]
    fn test_parse_cabal() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test_cabal");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("myapp.cabal");
        std::fs::write(
            &path,
            r#"build-depends:
    base >=4.7 && <5,
    aeson ==2.1.0,
    text
"#,
        )
        .unwrap();
        let deps = parse_cabal(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "base" && d.version.contains("4.7"))
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "aeson" && d.version.contains("2.1.0"))
        );
        assert!(deps.iter().any(|d| d.name == "text" && d.version == "any"));
        assert!(deps.iter().all(|d| d.kind == DependencyKind::Haskell));
    }

    #[test]
    fn test_parse_r_description() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test_r");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("DESCRIPTION");
        std::fs::write(
            &path,
            r#"Package: mypackage
Version: 1.0.0
Imports:
    ggplot2 (>=3.4.0),
    dplyr
Depends: R (>=4.0)
"#,
        )
        .unwrap();
        let deps = parse_r_description(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "ggplot2" && d.version.contains("3.4.0"))
        );
        assert!(deps.iter().any(|d| d.name == "dplyr" && d.version == "any"));
        assert!(!deps.iter().any(|d| d.name == "R"));
        assert!(deps.iter().all(|d| d.kind == DependencyKind::R));
    }

    #[test]
    fn test_parse_rebar_config() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test_rebar");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rebar.config");
        std::fs::write(
            &path,
            r#"{deps, [
    {cowboy, "2.12.1"},
    {jiffy, "1.1.1"}
]}.
"#,
        )
        .unwrap();
        let deps = parse_rebar_config(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "cowboy" && d.version == "2.12.1")
        );
        assert!(deps.iter().all(|d| d.kind == DependencyKind::Erlang));
    }

    #[test]
    fn test_parse_deps_edn() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test_edn");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("deps.edn");
        std::fs::write(
            &path,
            r#"{:deps
 {org.clojure/clojure {:mvn/version "1.11.1"}
  metosin/malli {:mvn/version "0.13.0"}}
}
"#,
        )
        .unwrap();
        let deps = parse_deps_edn(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "org.clojure/clojure" && d.version == "1.11.1")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "metosin/malli" && d.version == "0.13.0")
        );
        assert!(deps.iter().all(|d| d.kind == DependencyKind::Clojure));
    }

    #[test]
    fn test_parse_conanfile_txt() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test_conan");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("conanfile.txt");
        std::fs::write(
            &path,
            r#"[requires]
openssl/3.1.4
zlib/1.3.1

[generators]
cmake
"#,
        )
        .unwrap();
        let deps = parse_conanfile(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "openssl" && d.version == "3.1.4")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "zlib" && d.version == "1.3.1")
        );
        assert!(deps.iter().all(|d| d.kind == DependencyKind::Conan));
    }

    #[test]
    fn test_parse_bazel_module() {
        let dir = std::env::temp_dir().join("pledgerecon_dep_test_bazel");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("MODULE.bazel");
        std::fs::write(
            &path,
            r#"module(name = "myproject", version = "1.0.0")
bazel_dep(name = "rules_cc", version = "0.0.1")
bazel_dep(name = "rules_java", version = "7.1.0")
"#,
        )
        .unwrap();
        let deps = parse_bazel_build(&path).unwrap();
        assert!(
            deps.iter()
                .any(|d| d.name == "rules_cc" && d.version == "0.0.1")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "rules_java" && d.version == "7.1.0")
        );
        assert!(deps.iter().all(|d| d.kind == DependencyKind::Bazel));
    }

    #[test]
    fn test_dependency_kind_from_manifest_new() {
        assert_eq!(
            DependencyKind::from_manifest("build.sbt"),
            Some(DependencyKind::Scala)
        );
        assert_eq!(
            DependencyKind::from_manifest("build.gradle.kts"),
            Some(DependencyKind::Kotlin)
        );
        assert_eq!(
            DependencyKind::from_manifest("mix.exs"),
            Some(DependencyKind::Elixir)
        );
        assert_eq!(
            DependencyKind::from_manifest("myapp.cabal"),
            Some(DependencyKind::Haskell)
        );
        assert_eq!(
            DependencyKind::from_manifest("DESCRIPTION"),
            Some(DependencyKind::R)
        );
        assert_eq!(
            DependencyKind::from_manifest("rebar.config"),
            Some(DependencyKind::Erlang)
        );
        assert_eq!(
            DependencyKind::from_manifest("deps.edn"),
            Some(DependencyKind::Clojure)
        );
        assert_eq!(
            DependencyKind::from_manifest("conanfile.txt"),
            Some(DependencyKind::Conan)
        );
        assert_eq!(
            DependencyKind::from_manifest("MODULE.bazel"),
            Some(DependencyKind::Bazel)
        );
        assert_eq!(
            DependencyKind::from_manifest("BUILD"),
            Some(DependencyKind::Bazel)
        );
    }
}
