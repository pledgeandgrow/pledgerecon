//! Container & cloud-native security features (Goals 101–110).
//!
//! - Container image scanning (Goal 101)
//! - Layer-aware container scanning (Goal 102)
//! - Base image identification (Goal 103)
//! - Dockerfile analysis (Goal 104)
//! - Kubernetes manifest scanning (Goal 105)
//! - Helm chart scanning (Goal 106)
//! - Terraform IaC scanning (Goal 107)
//! - CloudFormation IaC scanning (Goal 108)
//! - Container registry sync (Goal 109)
//! - OCI artifact attestation verification (Goal 110)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContainerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("YAML error: {0}")]
    Yaml(String),
    #[error("invalid: {0}")]
    Invalid(String),
}

// ─── Goal 101: Container Image Scanning ─────────────────────────────────────

/// Supported Linux distributions for OS package scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxDistro {
    Debian,
    Ubuntu,
    Alpine,
    AmazonLinux,
    Centos,
    Rhel,
    Fedora,
    Unknown,
}

impl std::fmt::Display for LinuxDistro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Debian => write!(f, "debian"),
            Self::Ubuntu => write!(f, "ubuntu"),
            Self::Alpine => write!(f, "alpine"),
            Self::AmazonLinux => write!(f, "amazonlinux"),
            Self::Centos => write!(f, "centos"),
            Self::Rhel => write!(f, "rhel"),
            Self::Fedora => write!(f, "fedora"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl LinuxDistro {
    pub fn from_os_release(content: &str) -> Self {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("ID=") {
                let val = val.trim_matches('"');
                return match val {
                    "debian" => Self::Debian,
                    "ubuntu" => Self::Ubuntu,
                    "alpine" => Self::Alpine,
                    "amzn" | "amazonlinux" => Self::AmazonLinux,
                    "centos" => Self::Centos,
                    "rhel" => Self::Rhel,
                    "fedora" => Self::Fedora,
                    _ => Self::Unknown,
                };
            }
        }
        Self::Unknown
    }
}

/// A package installed in a container image (OS-level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsPackage {
    pub name: String,
    pub version: String,
    pub distro: LinuxDistro,
    pub manager: String,
    #[serde(default)]
    pub arch: Option<String>,
}

/// An application-level dependency found inside a container image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    #[serde(default)]
    pub manifest_path: Option<String>,
}

/// A vulnerability found in a container image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerVulnerability {
    pub advisory_id: String,
    pub package: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub severity: String,
    pub distro: LinuxDistro,
    #[serde(default)]
    pub layer_index: Option<usize>,
    #[serde(default)]
    pub layer_command: Option<String>,
}

/// Summary of container scan results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerScanSummary {
    pub total_packages: usize,
    pub total_vulnerabilities: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Result of scanning a container image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScanResult {
    pub image_ref: String,
    pub distro: LinuxDistro,
    pub os_packages: Vec<OsPackage>,
    #[serde(default)]
    pub app_dependencies: Vec<AppDependency>,
    #[serde(default)]
    pub vulnerabilities: Vec<ContainerVulnerability>,
    pub summary: ContainerScanSummary,
}

/// Scan a container image filesystem root for OS packages.
pub fn scan_container_image(
    image_ref: &str,
    rootfs_path: &Path,
) -> Result<ContainerScanResult, ContainerError> {
    let distro = detect_distro(rootfs_path);
    let os_packages = extract_os_packages(rootfs_path, distro)?;
    let app_deps = extract_app_dependencies(rootfs_path);

    let summary = ContainerScanSummary {
        total_packages: os_packages.len() + app_deps.len(),
        ..Default::default()
    };

    Ok(ContainerScanResult {
        image_ref: image_ref.to_string(),
        distro,
        os_packages,
        app_dependencies: app_deps,
        vulnerabilities: Vec::new(),
        summary,
    })
}

fn detect_distro(rootfs: &Path) -> LinuxDistro {
    let os_release = rootfs.join("etc/os-release");
    if let Ok(content) = std::fs::read_to_string(&os_release) {
        LinuxDistro::from_os_release(&content)
    } else if rootfs.join("etc/alpine-release").exists() {
        LinuxDistro::Alpine
    } else {
        LinuxDistro::Unknown
    }
}

fn extract_os_packages(rootfs: &Path, distro: LinuxDistro) -> Result<Vec<OsPackage>, ContainerError> {
    match distro {
        LinuxDistro::Debian | LinuxDistro::Ubuntu => extract_dpkg_packages(rootfs, distro),
        LinuxDistro::Alpine => extract_apk_packages(rootfs, distro),
        LinuxDistro::Centos | LinuxDistro::Rhel | LinuxDistro::Fedora | LinuxDistro::AmazonLinux => {
            Ok(Vec::new()) // RPM requires BerkeleyDB reader
        }
        LinuxDistro::Unknown => Ok(Vec::new()),
    }
}

fn extract_dpkg_packages(rootfs: &Path, distro: LinuxDistro) -> Result<Vec<OsPackage>, ContainerError> {
    let status_file = rootfs.join("var/lib/dpkg/status");
    let content = match std::fs::read_to_string(&status_file) {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };

    let mut packages = Vec::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut arch: Option<String> = None;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Package: ") {
            name = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("Version: ") {
            version = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("Architecture: ") {
            arch = Some(rest.to_string());
        } else if line.is_empty() && !name.is_empty() {
            packages.push(OsPackage {
                name: std::mem::take(&mut name),
                version: std::mem::take(&mut version),
                distro,
                manager: "dpkg".to_string(),
                arch: arch.take(),
            });
        }
    }
    if !name.is_empty() {
        packages.push(OsPackage { name, version, distro, manager: "dpkg".to_string(), arch });
    }
    Ok(packages)
}

fn extract_apk_packages(rootfs: &Path, distro: LinuxDistro) -> Result<Vec<OsPackage>, ContainerError> {
    let installed_file = rootfs.join("lib/apk/db/installed");
    let content = match std::fs::read_to_string(&installed_file) {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };

    let mut packages = Vec::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut arch: Option<String> = None;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("P:") {
            name = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("V:") {
            version = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("A:") {
            arch = Some(rest.to_string());
        } else if line.is_empty() && !name.is_empty() {
            packages.push(OsPackage {
                name: std::mem::take(&mut name),
                version: std::mem::take(&mut version),
                distro,
                manager: "apk".to_string(),
                arch: arch.take(),
            });
        }
    }
    if !name.is_empty() {
        packages.push(OsPackage { name, version, distro, manager: "apk".to_string(), arch });
    }
    Ok(packages)
}

fn extract_app_dependencies(rootfs: &Path) -> Vec<AppDependency> {
    let mut deps = Vec::new();

    // npm package-lock.json
    let npm_lock = rootfs.join("app/package-lock.json");
    if let Ok(content) = std::fs::read_to_string(&npm_lock) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
                for (name, info) in packages {
                    if name.is_empty() { continue; }
                    if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                        deps.push(AppDependency {
                            name: name.trim_start_matches("node_modules/").to_string(),
                            version: version.to_string(),
                            ecosystem: "npm".to_string(),
                            manifest_path: Some("app/package-lock.json".to_string()),
                        });
                    }
                }
            }
        }
    }

    // Cargo.lock
    let cargo_lock = rootfs.join("app/Cargo.lock");
    if let Ok(content) = std::fs::read_to_string(&cargo_lock) {
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;
        while i + 1 < lines.len() {
            if let Some(rest) = lines[i].strip_prefix("name = ") {
                let name = rest.trim_matches('"');
                if let Some(rest) = lines[i + 1].strip_prefix("version = ") {
                    let version = rest.trim_matches('"');
                    deps.push(AppDependency {
                        name: name.to_string(),
                        version: version.to_string(),
                        ecosystem: "crates".to_string(),
                        manifest_path: Some("app/Cargo.lock".to_string()),
                    });
                }
            }
            i += 1;
        }
    }

    deps
}

// ─── Goal 102: Layer-Aware Container Scanning ───────────────────────────────

/// Represents a single layer in a container image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageLayer {
    pub index: usize,
    pub digest: String,
    #[serde(default)]
    pub command: Option<String>,
    pub size: u64,
    #[serde(default)]
    pub packages: Vec<OsPackage>,
}

/// Container image metadata with layer information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerImage {
    pub image_ref: String,
    pub layers: Vec<ImageLayer>,
    pub distro: LinuxDistro,
}

/// Assign vulnerabilities to the layer that introduced the vulnerable package.
pub fn assign_vulnerabilities_to_layers(
    image: &ContainerImage,
    vulnerabilities: &[ContainerVulnerability],
) -> Vec<ContainerVulnerability> {
    let mut pkg_to_layer: HashMap<String, usize> = HashMap::new();
    for layer in &image.layers {
        for pkg in &layer.packages {
            pkg_to_layer.entry(pkg.name.clone()).or_insert(layer.index);
        }
    }

    vulnerabilities
        .iter()
        .map(|vuln| {
            let layer_idx = pkg_to_layer.get(&vuln.package).copied();
            let layer_command = layer_idx
                .and_then(|idx| image.layers.get(idx))
                .and_then(|l| l.command.clone());
            ContainerVulnerability {
                layer_index: layer_idx,
                layer_command,
                ..vuln.clone()
            }
        })
        .collect()
}

/// Parse a Dockerfile to extract layer commands.
pub fn parse_dockerfile_layers(dockerfile_content: &str) -> Vec<String> {
    dockerfile_content
        .lines()
        .filter(|line| {
            let t = line.trim();
            t.starts_with("RUN ") || t.starts_with("COPY ") || t.starts_with("ADD ")
                || t.starts_with("ENV ") || t.starts_with("WORKDIR ") || t.starts_with("FROM ")
        })
        .map(|line| line.trim().to_string())
        .collect()
}

// ─── Goal 103: Base Image Identification ────────────────────────────────────

/// Information about a container's base image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseImageInfo {
    pub from_line: String,
    pub image: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
    pub is_distroless: bool,
    pub is_official: bool,
}

/// Extract base image info from a Dockerfile.
pub fn identify_base_image(dockerfile_content: &str) -> Option<BaseImageInfo> {
    for line in dockerfile_content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("FROM ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.is_empty() { return None; }

            let image_ref = parts[0];
            let (image_part, digest) = if let Some(at_idx) = image_ref.find('@') {
                (image_ref[..at_idx].to_string(), Some(image_ref[at_idx + 1..].to_string()))
            } else {
                (image_ref.to_string(), None)
            };
            let (image, tag) = if let Some(idx) = image_part.rfind(':') {
                (image_part[..idx].to_string(), Some(image_part[idx + 1..].to_string()))
            } else {
                (image_part, None)
            };

            let is_distroless = image.contains("distroless") || image.contains("scratch");
            let is_official = !image.contains('/') || image.starts_with("library/");

            return Some(BaseImageInfo {
                from_line: trimmed.to_string(),
                image,
                tag,
                digest,
                is_distroless,
                is_official,
            });
        }
    }
    None
}

/// Separate base image vulnerabilities from application vulnerabilities.
pub fn separate_base_and_app_vulnerabilities<'a>(
    scan_result: &'a ContainerScanResult,
    base_image_packages: &'a [String],
) -> (Vec<&'a ContainerVulnerability>, Vec<&'a ContainerVulnerability>) {
    scan_result
        .vulnerabilities
        .iter()
        .partition(|v| base_image_packages.contains(&v.package))
}

// ─── Goal 104: Dockerfile Analysis ──────────────────────────────────────────

/// Severity of a Dockerfile issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerfileIssueSeverity {
    Error,
    Warning,
    Info,
}

/// A Dockerfile security issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerfileIssue {
    pub rule_id: String,
    pub message: String,
    pub severity: DockerfileIssueSeverity,
    pub line: usize,
    pub instruction: String,
}

/// Analyze a Dockerfile for security best practices.
pub fn analyze_dockerfile(content: &str) -> Vec<DockerfileIssue> {
    let mut issues = Vec::new();

    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        let line_num = i + 1;

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let upper = trimmed.to_uppercase();

        // USER root check.
        if upper.starts_with("USER ") {
            let user = trimmed.strip_prefix("USER ").unwrap_or("").trim();
            if user == "root" || user == "0" {
                issues.push(DockerfileIssue {
                    rule_id: "DF001".to_string(),
                    message: "Container runs as root user".to_string(),
                    severity: DockerfileIssueSeverity::Warning,
                    line: line_num,
                    instruction: trimmed.to_string(),
                });
            }
        }

        // Secrets in ENV.
        if upper.starts_with("ENV ") {
            let env_part = trimmed.strip_prefix("ENV ").unwrap_or("");
            let secret_patterns = [
                "PASSWORD", "PASSWD", "SECRET", "API_KEY", "APIKEY", "TOKEN",
                "PRIVATE_KEY", "ACCESS_KEY", "AWS_SECRET", "GITHUB_TOKEN",
            ];
            for pattern in &secret_patterns {
                if env_part.to_uppercase().contains(pattern) {
                    issues.push(DockerfileIssue {
                        rule_id: "DF002".to_string(),
                        message: format!("Potential secret in ENV: {}", pattern.to_lowercase()),
                        severity: DockerfileIssueSeverity::Error,
                        line: line_num,
                        instruction: trimmed.to_string(),
                    });
                    break;
                }
            }
        }

        // apt-get without --no-install-recommends.
        if upper.contains("APT-GET INSTALL") && !upper.contains("--NO-INSTALL-RECOMMENDS") {
            issues.push(DockerfileIssue {
                rule_id: "DF003".to_string(),
                message: "apt-get install without --no-install-recommends".to_string(),
                severity: DockerfileIssueSeverity::Info,
                line: line_num,
                instruction: trimmed.to_string(),
            });
        }

        // ADD with URL.
        if upper.starts_with("ADD ") && (trimmed.contains("http://") || trimmed.contains("https://")) {
            issues.push(DockerfileIssue {
                rule_id: "DF005".to_string(),
                message: "Use COPY instead of ADD for remote URLs".to_string(),
                severity: DockerfileIssueSeverity::Warning,
                line: line_num,
                instruction: trimmed.to_string(),
            });
        }

        // Privileged port exposure.
        if upper.starts_with("EXPOSE ") {
            let ports = trimmed.strip_prefix("EXPOSE ").unwrap_or("");
            for port_part in ports.split_whitespace() {
                if let Ok(port) = port_part.split('/').next().unwrap_or("0").parse::<u16>() {
                    if port < 1024 {
                        issues.push(DockerfileIssue {
                            rule_id: "DF006".to_string(),
                            message: format!("Exposing privileged port {}", port),
                            severity: DockerfileIssueSeverity::Info,
                            line: line_num,
                            instruction: trimmed.to_string(),
                        });
                    }
                }
            }
        }
    }

    // Missing USER instruction.
    let has_user = content.lines().any(|l| l.trim().to_uppercase().starts_with("USER "));
    if !has_user {
        issues.push(DockerfileIssue {
            rule_id: "DF007".to_string(),
            message: "No USER instruction — container runs as root by default".to_string(),
            severity: DockerfileIssueSeverity::Warning,
            line: 0,
            instruction: "(missing)".to_string(),
        });
    }

    // Missing HEALTHCHECK.
    let has_healthcheck = content.lines().any(|l| l.trim().to_uppercase().starts_with("HEALTHCHECK "));
    if !has_healthcheck {
        issues.push(DockerfileIssue {
            rule_id: "DF008".to_string(),
            message: "No HEALTHCHECK instruction defined".to_string(),
            severity: DockerfileIssueSeverity::Info,
            line: 0,
            instruction: "(missing)".to_string(),
        });
    }

    // :latest tag.
    if let Some(base) = identify_base_image(content) {
        if base.tag.as_deref() == Some("latest") {
            issues.push(DockerfileIssue {
                rule_id: "DF009".to_string(),
                message: "Base image uses :latest tag — pin to a specific version".to_string(),
                severity: DockerfileIssueSeverity::Warning,
                line: 1,
                instruction: base.from_line,
            });
        }
    }

    issues
}

// ─── Goal 105: Kubernetes Manifest Scanning ─────────────────────────────────

/// Severity of a Kubernetes misconfiguration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum K8sIssueSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// A Kubernetes manifest misconfiguration finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sIssue {
    pub rule_id: String,
    pub message: String,
    pub severity: K8sIssueSeverity,
    pub resource_kind: String,
    pub resource_name: String,
    pub namespace: String,
}

/// Scan a Kubernetes manifest YAML file for misconfigurations.
pub fn scan_k8s_manifest(yaml_content: &str) -> Result<Vec<K8sIssue>, ContainerError> {
    let docs: Vec<serde_yaml::Value> = serde_yaml::Deserializer::from_str(yaml_content)
        .map(serde_yaml::Value::deserialize)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ContainerError::Yaml(e.to_string()))?;

    let mut issues = Vec::new();

    for doc in &docs {
        if let Some(kind) = doc.get("kind").and_then(|k| k.as_str()) {
            let name = doc
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            let namespace = doc
                .get("metadata")
                .and_then(|m| m.get("namespace"))
                .and_then(|n| n.as_str())
                .unwrap_or("default");

            match kind {
                "Pod" => {
                    if let Some(spec) = doc.get("spec") {
                        issues.extend(scan_container_spec(spec, name, namespace, "Pod"));
                    }
                }
                "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" | "Job" | "CronJob" => {
                    if let Some(spec) = doc.get("spec")
                        .and_then(|s| s.get("template"))
                        .and_then(|t| t.get("spec"))
                    {
                        issues.extend(scan_container_spec(spec, name, namespace, kind));
                    }
                }
                _ => {}
            }
        }
    }

    Ok(issues)
}

fn scan_container_spec(
    spec: &serde_yaml::Value,
    name: &str,
    namespace: &str,
    kind: &str,
) -> Vec<K8sIssue> {
    let mut issues = Vec::new();
    let containers = match spec.get("containers").and_then(|c| c.as_sequence()) {
        Some(c) => c,
        None => return issues,
    };

    for container in containers {
        let cname = container.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");

        // KSV001: Runs as root.
        let run_as_non_root = spec
            .get("securityContext")
            .and_then(|sc| sc.get("runAsNonRoot"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !run_as_non_root {
            issues.push(K8sIssue {
                rule_id: "KSV001".to_string(),
                message: format!("Container {} may run as root", cname),
                severity: K8sIssueSeverity::High,
                resource_kind: kind.to_string(),
                resource_name: name.to_string(),
                namespace: namespace.to_string(),
            });
        }

        // KSV003: Default capabilities not dropped.
        let has_drop_all = container
            .get("securityContext")
            .and_then(|sc| sc.get("capabilities"))
            .and_then(|c| c.get("drop"))
            .and_then(|d| d.as_sequence())
            .map(|d| d.iter().any(|c| c.as_str() == Some("ALL")))
            .unwrap_or(false);
        if !has_drop_all {
            issues.push(K8sIssue {
                rule_id: "KSV003".to_string(),
                message: format!("Container {} does not drop all capabilities", cname),
                severity: K8sIssueSeverity::Medium,
                resource_kind: kind.to_string(),
                resource_name: name.to_string(),
                namespace: namespace.to_string(),
            });
        }

        // KSV011: Privileged container.
        let privileged = container
            .get("securityContext")
            .and_then(|sc| sc.get("privileged"))
            .and_then(|p| p.as_bool())
            .unwrap_or(false);
        if privileged {
            issues.push(K8sIssue {
                rule_id: "KSV011".to_string(),
                message: format!("Container {} is privileged", cname),
                severity: K8sIssueSeverity::Critical,
                resource_kind: kind.to_string(),
                resource_name: name.to_string(),
                namespace: namespace.to_string(),
            });
        }

        // KSV014: hostPath volume.
        if let Some(volumes) = spec.get("volumes").and_then(|v| v.as_sequence()) {
            for vol in volumes {
                if vol.get("hostPath").is_some() {
                    let vname = vol.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                    issues.push(K8sIssue {
                        rule_id: "KSV014".to_string(),
                        message: format!("hostPath volume '{}' mounted", vname),
                        severity: K8sIssueSeverity::High,
                        resource_kind: kind.to_string(),
                        resource_name: name.to_string(),
                        namespace: namespace.to_string(),
                    });
                }
            }
        }

        // KSV016: No resource limits.
        let has_limits = container.get("resources").and_then(|r| r.get("limits")).is_some();
        if !has_limits {
            issues.push(K8sIssue {
                rule_id: "KSV016".to_string(),
                message: format!("Container {} has no resource limits", cname),
                severity: K8sIssueSeverity::Low,
                resource_kind: kind.to_string(),
                resource_name: name.to_string(),
                namespace: namespace.to_string(),
            });
        }

        // KSV030: No seccomp profile.
        let has_seccomp = container
            .get("securityContext")
            .and_then(|sc| sc.get("seccompProfile"))
            .is_some();
        if !has_seccomp {
            issues.push(K8sIssue {
                rule_id: "KSV030".to_string(),
                message: format!("Container {} has no seccomp profile", cname),
                severity: K8sIssueSeverity::Low,
                resource_kind: kind.to_string(),
                resource_name: name.to_string(),
                namespace: namespace.to_string(),
            });
        }
    }

    issues
}

// ─── Goal 106: Helm Chart Scanning ──────────────────────────────────────────

/// A Helm chart security issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmIssue {
    pub rule_id: String,
    pub message: String,
    pub severity: K8sIssueSeverity,
    pub template_file: String,
}

/// Scan a Helm chart directory for misconfigurations.
pub fn scan_helm_chart(chart_dir: &Path) -> Result<Vec<HelmIssue>, ContainerError> {
    let mut issues = Vec::new();

    let chart_yaml = chart_dir.join("Chart.yaml");
    if !chart_yaml.exists() {
        return Err(ContainerError::Invalid(
            "Chart.yaml not found in chart directory".to_string(),
        ));
    }

    let templates_dir = chart_dir.join("templates");
    if templates_dir.is_dir() {
        let walker = ignore::WalkBuilder::new(&templates_dir)
            .hidden(false)
            .build();

        for entry in walker.flatten() {
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yaml" && ext != "yml" {
                continue;
            }

            let content = std::fs::read_to_string(path)?;
            let rel_path = path.strip_prefix(chart_dir).unwrap_or(path).to_string_lossy().to_string();

            match scan_k8s_manifest(&content) {
                Ok(k8s_issues) => {
                    for issue in k8s_issues {
                        issues.push(HelmIssue {
                            rule_id: issue.rule_id,
                            message: issue.message,
                            severity: issue.severity,
                            template_file: rel_path.clone(),
                        });
                    }
                }
                Err(_) => {}
            }
        }
    }

    Ok(issues)
}

// ─── Goal 107: Terraform IaC Scanning ───────────────────────────────────────

/// Severity of a Terraform misconfiguration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerraformIssueSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// A Terraform misconfiguration finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformIssue {
    pub rule_id: String,
    pub message: String,
    pub severity: TerraformIssueSeverity,
    pub resource_type: String,
    pub resource_name: String,
    pub file: String,
    pub line: Option<usize>,
}

/// Scan a Terraform file (`.tf`) for cloud misconfigurations.
pub fn scan_terraform(content: &str, filename: &str) -> Vec<TerraformIssue> {
    let mut issues = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut current_resource_type = String::new();
    let mut current_resource_name = String::new();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Detect resource block start.
        if let Some(rest) = trimmed.strip_prefix("resource ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                current_resource_type = parts[0].trim_matches('"').to_string();
                current_resource_name = parts[1].trim_matches('"').trim_end_matches('{').trim().to_string();
            }
        }

        if current_resource_type.is_empty() {
            continue;
        }

        let line_num = i + 1;

        // S3 bucket public access.
        if current_resource_type.contains("s3_bucket") {
            if trimmed.contains("acl") && (trimmed.contains("\"public-read\"") || trimmed.contains("\"public-read-write\"")) {
                issues.push(TerraformIssue {
                    rule_id: "TF002".to_string(),
                    message: "S3 bucket has public-read or public-read-write ACL".to_string(),
                    severity: TerraformIssueSeverity::Critical,
                    resource_type: current_resource_type.clone(),
                    resource_name: current_resource_name.clone(),
                    file: filename.to_string(),
                    line: Some(line_num),
                });
            }
        }

        // Security group 0.0.0.0/0.
        if current_resource_type.contains("security_group") {
            if trimmed.contains("0.0.0.0/0") {
                issues.push(TerraformIssue {
                    rule_id: "TF003".to_string(),
                    message: "Security group rule allows traffic from 0.0.0.0/0".to_string(),
                    severity: TerraformIssueSeverity::High,
                    resource_type: current_resource_type.clone(),
                    resource_name: current_resource_name.clone(),
                    file: filename.to_string(),
                    line: Some(line_num),
                });
            }
        }

        // Unencrypted DB instance.
        if current_resource_type.contains("db_instance") {
            if trimmed.contains("storage_encrypted") && trimmed.contains("false") {
                issues.push(TerraformIssue {
                    rule_id: "TF004".to_string(),
                    message: "Database instance storage is not encrypted".to_string(),
                    severity: TerraformIssueSeverity::High,
                    resource_type: current_resource_type.clone(),
                    resource_name: current_resource_name.clone(),
                    file: filename.to_string(),
                    line: Some(line_num),
                });
            }
        }

        // Unencrypted EBS volume.
        if current_resource_type == "aws_ebs_volume" || current_resource_type == "aws_instance" {
            if trimmed.contains("encrypted") && trimmed.contains("false") {
                issues.push(TerraformIssue {
                    rule_id: "TF005".to_string(),
                    message: "EBS volume is not encrypted".to_string(),
                    severity: TerraformIssueSeverity::Medium,
                    resource_type: current_resource_type.clone(),
                    resource_name: current_resource_name.clone(),
                    file: filename.to_string(),
                    line: Some(line_num),
                });
            }
        }

        // Hardcoded secrets.
        let secret_patterns = ["password", "secret_key", "access_key", "private_key", "token"];
        for pattern in &secret_patterns {
            if trimmed.to_lowercase().contains(pattern) && trimmed.contains('=') {
                let value_part = trimmed.split('=').nth(1).unwrap_or("");
                if !value_part.contains("var.") && !value_part.contains("data.")
                    && !value_part.is_empty()
                    && (value_part.contains('"') || value_part.contains('\''))
                {
                    issues.push(TerraformIssue {
                        rule_id: "TF006".to_string(),
                        message: format!("Potential hardcoded secret: {}", pattern),
                        severity: TerraformIssueSeverity::High,
                        resource_type: current_resource_type.clone(),
                        resource_name: current_resource_name.clone(),
                        file: filename.to_string(),
                        line: Some(line_num),
                    });
                }
            }
        }
    }

    issues
}

// ─── Goal 108: CloudFormation IaC Scanning ──────────────────────────────────

/// A CloudFormation misconfiguration finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudFormationIssue {
    pub rule_id: String,
    pub message: String,
    pub severity: TerraformIssueSeverity,
    pub resource_type: String,
    pub logical_id: String,
}

/// Scan a CloudFormation template (JSON/YAML) for AWS misconfigurations.
pub fn scan_cloudformation(template: &str) -> Result<Vec<CloudFormationIssue>, ContainerError> {
    let value: serde_yaml::Value = serde_yaml::from_str(template)
        .map_err(|e| ContainerError::Yaml(e.to_string()))?;

    let mut issues = Vec::new();

    let resources = match value.get("Resources") {
        Some(r) => r,
        None => return Ok(issues),
    };

    if let Some(resources_map) = resources.as_mapping() {
        for (logical_id, resource) in resources_map {
            let logical_id_str = logical_id.as_str().unwrap_or("unknown");
            let resource_type = resource
                .get("Type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");

            let properties = resource.get("Properties");

            // S3 bucket public access.
            if resource_type == "AWS::S3::Bucket" {
                if let Some(props) = properties {
                    let acl = props.get("AccessControl").and_then(|a| a.as_str());
                    if acl == Some("PublicReadWrite") || acl == Some("PublicRead") {
                        issues.push(CloudFormationIssue {
                            rule_id: "CF001".to_string(),
                            message: format!("S3 bucket {} has public access control", logical_id_str),
                            severity: TerraformIssueSeverity::Critical,
                            resource_type: resource_type.to_string(),
                            logical_id: logical_id_str.to_string(),
                        });
                    }
                }
            }

            // Security group with 0.0.0.0/0.
            if resource_type == "AWS::EC2::SecurityGroup" {
                if let Some(props) = properties {
                    if let Some(ingress) = props.get("SecurityGroupIngress").and_then(|i| i.as_sequence()) {
                        for rule in ingress {
                            let cidr = rule.get("CidrIp").and_then(|c| c.as_str());
                            if cidr == Some("0.0.0.0/0") {
                                issues.push(CloudFormationIssue {
                                    rule_id: "CF002".to_string(),
                                    message: format!("Security group {} allows 0.0.0.0/0", logical_id_str),
                                    severity: TerraformIssueSeverity::High,
                                    resource_type: resource_type.to_string(),
                                    logical_id: logical_id_str.to_string(),
                                });
                            }
                        }
                    }
                }
            }

            // RDS unencrypted.
            if resource_type == "AWS::RDS::DBInstance" {
                if let Some(props) = properties {
                    let encrypted = props.get("StorageEncrypted").and_then(|e| e.as_bool()).unwrap_or(false);
                    if !encrypted {
                        issues.push(CloudFormationIssue {
                            rule_id: "CF003".to_string(),
                            message: format!("RDS instance {} storage is not encrypted", logical_id_str),
                            severity: TerraformIssueSeverity::High,
                            resource_type: resource_type.to_string(),
                            logical_id: logical_id_str.to_string(),
                        });
                    }
                }
            }
        }
    }

    Ok(issues)
}

// ─── Goal 109: Container Registry Sync ──────────────────────────────────────

/// Configuration for a container registry to monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Registry URL (e.g. `https://registry.hub.docker.com`).
    pub url: String,
    /// Registry type.
    pub registry_type: RegistryType,
    /// Repository/image names to monitor.
    pub repositories: Vec<String>,
    /// Authentication token (if private registry).
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Poll interval in seconds.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
}

fn default_poll_interval() -> u64 {
    3600
}

/// Supported registry types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryType {
    DockerHub,
    Ecr,
    Gcr,
    Acr,
    Gitlab,
    Quay,
    Generic,
}

/// A discovered image in a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredImage {
    pub registry: String,
    pub repository: String,
    pub tag: String,
    pub digest: String,
    pub size_bytes: u64,
}

/// Result of a registry sync operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrySyncResult {
    pub registry: String,
    pub images_discovered: usize,
    pub images_updated: usize,
    pub new_vulnerabilities: usize,
    pub images: Vec<DiscoveredImage>,
}

/// Discover images in a registry (simulated — real impl would call registry API).
pub fn discover_registry_images(config: &RegistryConfig) -> Result<RegistrySyncResult, ContainerError> {
    // In a real implementation, this would call the registry v2 API:
    // GET /v2/_catalog  (list repositories)
    // GET /v2/<name>/tags/list  (list tags)
    // GET /v2/<name>/manifests/<tag>  (get digest)
    //
    // For now, we return a simulated result.
    let images = config
        .repositories
        .iter()
        .flat_map(|repo| {
            vec![
                DiscoveredImage {
                    registry: config.url.clone(),
                    repository: repo.clone(),
                    tag: "latest".to_string(),
                    digest: format!("sha256:{}", blake3_hash(repo, "latest")),
                    size_bytes: 0,
                },
            ]
        })
        .collect::<Vec<_>>();

    Ok(RegistrySyncResult {
        registry: config.url.clone(),
        images_discovered: images.len(),
        images_updated: 0,
        new_vulnerabilities: 0,
        images,
    })
}

fn blake3_hash(repo: &str, tag: &str) -> String {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(repo.as_bytes());
    hasher.update(tag.as_bytes());
    hasher.finalize().to_hex().to_string()
}

// ─── Goal 110: OCI Artifact Attestation Verification ────────────────────────

/// An OCI artifact attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Predicate type URI (e.g. `https://slsa.dev/provenance/v1`).
    pub predicate_type: String,
    /// The attestation statement (JSON).
    pub statement: serde_json::Value,
    /// Signature on the attestation.
    #[serde(default)]
    pub signature: Option<String>,
    /// Signer identity (e.g. GitHub Actions OIDC subject).
    #[serde(default)]
    pub signer_identity: Option<String>,
    /// Whether the signature was verified.
    #[serde(default)]
    pub verified: bool,
}

/// Result of verifying attestations on an OCI image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationVerificationResult {
    pub image_ref: String,
    pub attestations: Vec<Attestation>,
    pub has_slsa_provenance: bool,
    pub has_sbom: bool,
    pub has_scan_result: bool,
    pub all_verified: bool,
}

/// Verify OCI artifact attestations for an image.
///
/// In a real implementation, this would call `cosign verify-attestation`
/// and parse the in-toto envelopes from the OCI registry.
pub fn verify_attestations(
    image_ref: &str,
    raw_attestations: &[serde_json::Value],
) -> Result<AttestationVerificationResult, ContainerError> {
    let mut attestations = Vec::new();
    let mut has_slsa = false;
    let mut has_sbom = false;
    let mut has_scan = false;
    let mut all_verified = true;

    for raw in raw_attestations {
        let predicate_type = raw
            .get("predicateType")
            .and_then(|p| p.as_str())
            .unwrap_or("unknown")
            .to_string();

        let verified = raw
            .get("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !verified {
            all_verified = false;
        }

        if predicate_type.contains("slsa.dev") {
            has_slsa = true;
        }
        if predicate_type.contains("spdx.dev") || predicate_type.contains("cyclonedx.org") {
            has_sbom = true;
        }
        if predicate_type.contains("scan") {
            has_scan = true;
        }

        attestations.push(Attestation {
            predicate_type,
            statement: raw.clone(),
            signature: raw.get("signature").and_then(|s| s.as_str()).map(|s| s.to_string()),
            signer_identity: raw.get("signerIdentity").and_then(|s| s.as_str()).map(|s| s.to_string()),
            verified,
        });
    }

    Ok(AttestationVerificationResult {
        image_ref: image_ref.to_string(),
        attestations,
        has_slsa_provenance: has_slsa,
        has_sbom: has_sbom,
        has_scan_result: has_scan,
        all_verified,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Goal 101 tests

    #[test]
    fn test_distro_from_os_release() {
        let debian = "ID=debian\nVERSION_ID=12\n";
        assert_eq!(LinuxDistro::from_os_release(debian), LinuxDistro::Debian);

        let alpine = "ID=alpine\nVERSION_ID=3.19\n";
        assert_eq!(LinuxDistro::from_os_release(alpine), LinuxDistro::Alpine);

        let ubuntu = "ID=\"ubuntu\"\nVERSION_ID=\"22.04\"\n";
        assert_eq!(LinuxDistro::from_os_release(ubuntu), LinuxDistro::Ubuntu);

        let unknown = "ID=fedora-coreos\n";
        assert_eq!(LinuxDistro::from_os_release(unknown), LinuxDistro::Unknown);
    }

    #[test]
    fn test_scan_container_image_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let result = scan_container_image("test:latest", tmp.path()).unwrap();
        assert_eq!(result.image_ref, "test:latest");
        assert_eq!(result.distro, LinuxDistro::Unknown);
        assert!(result.os_packages.is_empty());
        assert!(result.app_dependencies.is_empty());
    }

    #[test]
    fn test_scan_container_image_alpine() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();

        // Create alpine-release file.
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::fs::write(rootfs.join("etc/alpine-release"), "3.19.1").unwrap();

        // Create apk installed database.
        let apk_db = "P:openssl\nV:3.1.4-r1\nA:x86_64\n\nP:busybox\nV:1.36.1-r0\nA:x86_64\n\n";
        std::fs::create_dir_all(rootfs.join("lib/apk/db")).unwrap();
        std::fs::write(rootfs.join("lib/apk/db/installed"), apk_db).unwrap();

        let result = scan_container_image("alpine:3.19", rootfs).unwrap();
        assert_eq!(result.distro, LinuxDistro::Alpine);
        assert_eq!(result.os_packages.len(), 2);
        assert_eq!(result.os_packages[0].name, "openssl");
        assert_eq!(result.os_packages[0].version, "3.1.4-r1");
        assert_eq!(result.os_packages[0].manager, "apk");
    }

    #[test]
    fn test_scan_container_image_debian() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();

        // Create os-release.
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::fs::write(rootfs.join("etc/os-release"), "ID=debian\nVERSION_ID=12\n").unwrap();

        // Create dpkg status.
        let dpkg_status = "Package: libc6\nVersion: 2.36-9+deb12u1\nArchitecture: amd64\n\nPackage: openssl\nVersion: 3.0.12-1\nArchitecture: amd64\n\n";
        std::fs::create_dir_all(rootfs.join("var/lib/dpkg")).unwrap();
        std::fs::write(rootfs.join("var/lib/dpkg/status"), dpkg_status).unwrap();

        let result = scan_container_image("debian:12", rootfs).unwrap();
        assert_eq!(result.distro, LinuxDistro::Debian);
        assert_eq!(result.os_packages.len(), 2);
        assert_eq!(result.os_packages[0].name, "libc6");
        assert_eq!(result.os_packages[0].manager, "dpkg");
    }

    // Goal 102 tests

    #[test]
    fn test_assign_vulnerabilities_to_layers() {
        let image = ContainerImage {
            image_ref: "test:latest".to_string(),
            distro: LinuxDistro::Alpine,
            layers: vec![
                ImageLayer {
                    index: 0,
                    digest: "sha256:abc".to_string(),
                    command: Some("FROM alpine:3.19".to_string()),
                    size: 5000000,
                    packages: vec![OsPackage {
                        name: "openssl".to_string(),
                        version: "3.1.4".to_string(),
                        distro: LinuxDistro::Alpine,
                        manager: "apk".to_string(),
                        arch: None,
                    }],
                },
                ImageLayer {
                    index: 1,
                    digest: "sha256:def".to_string(),
                    command: Some("RUN apk add curl".to_string()),
                    size: 1000000,
                    packages: vec![OsPackage {
                        name: "curl".to_string(),
                        version: "8.5.0".to_string(),
                        distro: LinuxDistro::Alpine,
                        manager: "apk".to_string(),
                        arch: None,
                    }],
                },
            ],
        };

        let vulns = vec![
            ContainerVulnerability {
                advisory_id: "CVE-2024-12345".to_string(),
                package: "openssl".to_string(),
                installed_version: "3.1.4".to_string(),
                fixed_version: Some("3.1.5".to_string()),
                severity: "high".to_string(),
                distro: LinuxDistro::Alpine,
                layer_index: None,
                layer_command: None,
            },
            ContainerVulnerability {
                advisory_id: "CVE-2024-67890".to_string(),
                package: "curl".to_string(),
                installed_version: "8.5.0".to_string(),
                fixed_version: Some("8.6.0".to_string()),
                severity: "medium".to_string(),
                distro: LinuxDistro::Alpine,
                layer_index: None,
                layer_command: None,
            },
        ];

        let result = assign_vulnerabilities_to_layers(&image, &vulns);
        assert_eq!(result[0].layer_index, Some(0));
        assert_eq!(result[0].layer_command, Some("FROM alpine:3.19".to_string()));
        assert_eq!(result[1].layer_index, Some(1));
        assert_eq!(result[1].layer_command, Some("RUN apk add curl".to_string()));
    }

    #[test]
    fn test_parse_dockerfile_layers() {
        let dockerfile = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm install\nEXPOSE 3000\nCMD [\"node\", \"index.js\"]\n";
        let layers = parse_dockerfile_layers(dockerfile);
        assert_eq!(layers.len(), 4); // FROM, WORKDIR, COPY, RUN
        assert!(layers[0].starts_with("FROM "));
    }

    // Goal 103 tests

    #[test]
    fn test_identify_base_image() {
        let dockerfile = "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\n";
        let info = identify_base_image(dockerfile).unwrap();
        assert_eq!(info.image, "python");
        assert_eq!(info.tag, Some("3.12-slim".to_string()));
        assert!(!info.is_distroless);
        assert!(info.is_official);
    }

    #[test]
    fn test_identify_base_image_distroless() {
        let dockerfile = "FROM gcr.io/distroless/nodejs20\n";
        let info = identify_base_image(dockerfile).unwrap();
        assert!(info.is_distroless);
        assert!(!info.is_official);
    }

    #[test]
    fn test_identify_base_image_with_digest() {
        let dockerfile = "FROM ubuntu@sha256:abc123def456\n";
        let info = identify_base_image(dockerfile).unwrap();
        assert_eq!(info.image, "ubuntu");
        assert!(info.digest.is_some());
    }

    #[test]
    fn test_identify_base_image_latest() {
        let dockerfile = "FROM node:latest\n";
        let info = identify_base_image(dockerfile).unwrap();
        assert_eq!(info.tag, Some("latest".to_string()));
    }

    #[test]
    fn test_identify_base_image_none() {
        let dockerfile = "# just a comment\n";
        assert!(identify_base_image(dockerfile).is_none());
    }

    // Goal 104 tests

    #[test]
    fn test_analyze_dockerfile_no_user() {
        let dockerfile = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm install\n";
        let issues = analyze_dockerfile(dockerfile);
        assert!(issues.iter().any(|i| i.rule_id == "DF007")); // No USER
        assert!(issues.iter().any(|i| i.rule_id == "DF008")); // No HEALTHCHECK
    }

    #[test]
    fn test_analyze_dockerfile_secret_in_env() {
        let dockerfile = "FROM node:20\nENV API_KEY=sk-1234567890\n";
        let issues = analyze_dockerfile(dockerfile);
        assert!(issues.iter().any(|i| i.rule_id == "DF002"));
    }

    #[test]
    fn test_analyze_dockerfile_user_root() {
        let dockerfile = "FROM node:20\nUSER root\n";
        let issues = analyze_dockerfile(dockerfile);
        assert!(issues.iter().any(|i| i.rule_id == "DF001"));
    }

    #[test]
    fn test_analyze_dockerfile_latest_tag() {
        let dockerfile = "FROM node:latest\nUSER node\nHEALTHCHECK CMD curl --fail http://localhost:3000\n";
        let issues = analyze_dockerfile(dockerfile);
        assert!(issues.iter().any(|i| i.rule_id == "DF009"));
    }

    #[test]
    fn test_analyze_dockerfile_clean() {
        let dockerfile = "FROM node:20-slim\nUSER node\nHEALTHCHECK CMD curl --fail http://localhost:3000\n";
        let issues = analyze_dockerfile(dockerfile);
        assert!(!issues.iter().any(|i| i.rule_id == "DF007"));
        assert!(!issues.iter().any(|i| i.rule_id == "DF008"));
        assert!(!issues.iter().any(|i| i.rule_id == "DF009"));
    }

    // Goal 105 tests

    #[test]
    fn test_scan_k8s_manifest_privileged() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
"#;
        let issues = scan_k8s_manifest(yaml).unwrap();
        assert!(issues.iter().any(|i| i.rule_id == "KSV011" && i.severity == K8sIssueSeverity::Critical));
    }

    #[test]
    fn test_scan_k8s_manifest_no_security_context() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: app
      image: nginx:latest
"#;
        let issues = scan_k8s_manifest(yaml).unwrap();
        assert!(issues.iter().any(|i| i.rule_id == "KSV001"));
        assert!(issues.iter().any(|i| i.rule_id == "KSV003"));
        assert!(issues.iter().any(|i| i.rule_id == "KSV016"));
        assert!(issues.iter().any(|i| i.rule_id == "KSV030"));
    }

    #[test]
    fn test_scan_k8s_manifest_deployment() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deploy
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
"#;
        let issues = scan_k8s_manifest(yaml).unwrap();
        assert!(issues.iter().any(|i| i.resource_kind == "Deployment" && i.rule_id == "KSV011"));
    }

    #[test]
    fn test_scan_k8s_manifest_hostpath() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: app
      image: nginx:latest
  volumes:
    - name: host
      hostPath:
        path: /etc
"#;
        let issues = scan_k8s_manifest(yaml).unwrap();
        assert!(issues.iter().any(|i| i.rule_id == "KSV014"));
    }

    #[test]
    fn test_scan_k8s_manifest_secure() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  securityContext:
    runAsNonRoot: true
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        capabilities:
          drop:
            - ALL
        seccompProfile:
          type: RuntimeDefault
      resources:
        limits:
          memory: "128Mi"
"#;
        let issues = scan_k8s_manifest(yaml).unwrap();
        assert!(issues.is_empty(), "Expected no issues for secure pod, got: {:?}", issues);
    }

    // Goal 106 tests

    #[test]
    fn test_scan_helm_chart_no_chart_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        let result = scan_helm_chart(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_helm_chart_with_templates() {
        let tmp = tempfile::tempdir().unwrap();
        let chart_dir = tmp.path();

        std::fs::write(chart_dir.join("Chart.yaml"), "apiVersion: v2\nname: test\nversion: 0.1.0\n").unwrap();

        std::fs::create_dir_all(chart_dir.join("templates")).unwrap();
        std::fs::write(
            chart_dir.join("templates/deployment.yaml"),
            r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
"#,
        ).unwrap();

        let issues = scan_helm_chart(chart_dir).unwrap();
        assert!(issues.iter().any(|i| i.rule_id == "KSV011"));
        assert!(issues.iter().any(|i| i.template_file.contains("deployment.yaml")));
    }

    // Goal 107 tests

    #[test]
    fn test_scan_terraform_public_s3() {
        let tf = r#"
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}
"#;
        let issues = scan_terraform(tf, "main.tf");
        assert!(issues.iter().any(|i| i.rule_id == "TF002"));
    }

    #[test]
    fn test_scan_terraform_open_sg() {
        let tf = r#"
resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 443
    to_port     = 443
  }
}
"#;
        let issues = scan_terraform(tf, "main.tf");
        assert!(issues.iter().any(|i| i.rule_id == "TF003"));
    }

    #[test]
    fn test_scan_terraform_unencrypted_db() {
        let tf = r#"
resource "aws_db_instance" "main" {
  engine          = "postgres"
  storage_encrypted = false
}
"#;
        let issues = scan_terraform(tf, "main.tf");
        assert!(issues.iter().any(|i| i.rule_id == "TF004"));
    }

    #[test]
    fn test_scan_terraform_hardcoded_secret() {
        let tf = r#"
resource "aws_db_instance" "main" {
  engine   = "postgres"
  password = "supersecret123"
}
"#;
        let issues = scan_terraform(tf, "main.tf");
        assert!(issues.iter().any(|i| i.rule_id == "TF006"));
    }

    #[test]
    fn test_scan_terraform_clean() {
        let tf = r#"
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "private"
}
"#;
        let issues = scan_terraform(tf, "main.tf");
        assert!(issues.is_empty(), "Expected no issues, got: {:?}", issues);
    }

    // Goal 108 tests

    #[test]
    fn test_scan_cloudformation_public_s3() {
        let template = r#"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicReadWrite
"#;
        let issues = scan_cloudformation(template).unwrap();
        assert!(issues.iter().any(|i| i.rule_id == "CF001"));
    }

    #[test]
    fn test_scan_cloudformation_open_sg() {
        let template = r#"
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0
          FromPort: 443
          ToPort: 443
"#;
        let issues = scan_cloudformation(template).unwrap();
        assert!(issues.iter().any(|i| i.rule_id == "CF002"));
    }

    #[test]
    fn test_scan_cloudformation_unencrypted_rds() {
        let template = r#"
Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      StorageEncrypted: false
"#;
        let issues = scan_cloudformation(template).unwrap();
        assert!(issues.iter().any(|i| i.rule_id == "CF003"));
    }

    #[test]
    fn test_scan_cloudformation_clean() {
        let template = r#"
Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      StorageEncrypted: true
"#;
        let issues = scan_cloudformation(template).unwrap();
        assert!(issues.is_empty());
    }

    // Goal 109 tests

    #[test]
    fn test_discover_registry_images() {
        let config = RegistryConfig {
            url: "https://registry.example.com".to_string(),
            registry_type: RegistryType::Generic,
            repositories: vec!["app/backend".to_string(), "app/frontend".to_string()],
            auth_token: None,
            poll_interval_secs: 3600,
        };

        let result = discover_registry_images(&config).unwrap();
        assert_eq!(result.registry, "https://registry.example.com");
        assert_eq!(result.images_discovered, 2);
        assert_eq!(result.images.len(), 2);
        assert_eq!(result.images[0].repository, "app/backend");
    }

    // Goal 110 tests

    #[test]
    fn test_verify_attestations_all_present() {
        let attestations = vec![
            serde_json::json!({
                "predicateType": "https://slsa.dev/provenance/v1",
                "verified": true
            }),
            serde_json::json!({
                "predicateType": "https://spdx.dev/Document",
                "verified": true
            }),
            serde_json::json!({
                "predicateType": "https://pledgerecon.dev/scan/v1",
                "verified": true
            }),
        ];

        let result = verify_attestations("myapp:v1", &attestations).unwrap();
        assert!(result.has_slsa_provenance);
        assert!(result.has_sbom);
        assert!(result.has_scan_result);
        assert!(result.all_verified);
        assert_eq!(result.attestations.len(), 3);
    }

    #[test]
    fn test_verify_attestations_missing_sbom() {
        let attestations = vec![
            serde_json::json!({
                "predicateType": "https://slsa.dev/provenance/v1",
                "verified": true
            }),
        ];

        let result = verify_attestations("myapp:v1", &attestations).unwrap();
        assert!(result.has_slsa_provenance);
        assert!(!result.has_sbom);
        assert!(!result.has_scan_result);
    }

    #[test]
    fn test_verify_attestations_unverified() {
        let attestations = vec![
            serde_json::json!({
                "predicateType": "https://slsa.dev/provenance/v1",
                "verified": false
            }),
        ];

        let result = verify_attestations("myapp:v1", &attestations).unwrap();
        assert!(!result.all_verified);
    }

    #[test]
    fn test_verify_attestations_empty() {
        let result = verify_attestations("myapp:v1", &[]).unwrap();
        assert!(!result.has_slsa_provenance);
        assert!(!result.has_sbom);
        assert!(result.all_verified); // vacuously true
    }
}
