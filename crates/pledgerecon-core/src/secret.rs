//! Secret Detection & Hardening — source code, container, IaC, git history,
//! and manifest secret scanning with entropy detection, verification, and
//! rotation guidance (Goals 121–130).

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

// ─── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretType {
    AwsAccessKey, AwsSecretKey, GitHubToken, GitLabToken, SlackToken,
    StripeKey, GoogleApiKey, GoogleOAuthClientSecret, AzureStorageKey,
    PrivateKeyPem, Jwt, TwilioApiKey, SendGridApiKey, MailgunApiKey,
    GenericApiKey, GenericPassword, GenericToken, Custom(String),
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Custom(n) => write!(f, "{}", n), _ => write!(f, "{:?}", self) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum SecretSeverity { Low, Medium, High, Critical }

impl std::fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Low => "low", Self::Medium => "medium", Self::High => "high", Self::Critical => "critical" }.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IaCKind { Terraform, CloudFormation, Kubernetes, Dockerfile }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretLocation {
    SourceCode { file: String, line: usize },
    ContainerImage { layer: String, file: String, line: usize },
    IaC { file: String, line: usize, kind: IaCKind },
    GitHistory { commit: String, file: String, line: usize },
    EnvFile { file: String, line: usize },
    Manifest { file: String, field: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub secret_type: SecretType,
    pub severity: SecretSeverity,
    pub location: SecretLocation,
    pub fingerprint: String,
    pub redacted_preview: String,
    #[serde(skip_serializing)]
    pub raw_value: String,
    pub pattern_name: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPattern {
    pub name: String,
    pub secret_type: SecretType,
    pub severity: SecretSeverity,
    pub regex: String,
    pub min_entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScanResult {
    pub findings: Vec<SecretFinding>,
    pub files_scanned: usize,
    pub total_secrets: usize,
    pub by_severity: HashMap<String, usize>,
    pub by_type: HashMap<String, usize>,
}

impl SecretScanResult {
    fn from_findings(findings: Vec<SecretFinding>, files_scanned: usize) -> Self {
        let mut by_severity = HashMap::new();
        let mut by_type = HashMap::new();
        for f in &findings {
            *by_severity.entry(f.severity.to_string()).or_insert(0) += 1;
            *by_type.entry(f.secret_type.to_string()).or_insert(0) += 1;
        }
        Self { total_secrets: findings.len(), findings, files_scanned, by_severity, by_type }
    }
}

// ─── Utilities ───────────────────────────────────────────────────────────────

fn redact(value: &str, prefix: usize, suffix: usize) -> String {
    let len = value.len();
    if len <= prefix + suffix + 3 { return "*".repeat(len); }
    format!("{}...{}", &value[..prefix], &value[len - suffix..])
}

fn fingerprint(value: &str) -> String {
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    h.finalize().iter().take(4).map(|b| format!("{:02x}", b)).collect()
}

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() { *counts.entry(c).or_insert(0) += 1; }
    let len = s.len() as f64;
    counts.values().map(|&c| { let p = c as f64 / len; -p * p.log2() }).sum()
}

struct CompiledPattern { pattern: SecretPattern, regex: Regex }

fn compile_patterns(patterns: &[SecretPattern]) -> Result<Vec<CompiledPattern>, SecretError> {
    patterns.iter().map(|p| Ok(CompiledPattern { regex: Regex::new(&p.regex)?, pattern: p.clone() })).collect()
}

// ─── Goal 121: Built-in Patterns & Source Code Scanning ──────────────────────

pub fn builtin_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern { name: "aws_access_key".into(), secret_type: SecretType::AwsAccessKey, severity: SecretSeverity::Critical, regex: r"AKIA[0-9A-Z]{16}".into(), min_entropy: 3.0 },
        SecretPattern { name: "aws_secret_key".into(), secret_type: SecretType::AwsSecretKey, severity: SecretSeverity::Critical, regex: r#"(?i)aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?"#.into(), min_entropy: 4.0 },
        SecretPattern { name: "github_token".into(), secret_type: SecretType::GitHubToken, severity: SecretSeverity::Critical, regex: r"gh[pousr]_[A-Za-z0-9]{36}".into(), min_entropy: 3.5 },
        SecretPattern { name: "github_pat".into(), secret_type: SecretType::GitHubToken, severity: SecretSeverity::Critical, regex: r"github_pat_[A-Za-z0-9_]{82}".into(), min_entropy: 3.5 },
        SecretPattern { name: "gitlab_token".into(), secret_type: SecretType::GitLabToken, severity: SecretSeverity::High, regex: r"glpat-[A-Za-z0-9_-]{20}".into(), min_entropy: 3.0 },
        SecretPattern { name: "slack_token".into(), secret_type: SecretType::SlackToken, severity: SecretSeverity::High, regex: r"xox[baprs]-[A-Za-z0-9-]{10,}".into(), min_entropy: 3.0 },
        SecretPattern { name: "stripe_key".into(), secret_type: SecretType::StripeKey, severity: SecretSeverity::Critical, regex: r"sk_(live|test)_[A-Za-z0-9]{24,}".into(), min_entropy: 3.0 },
        SecretPattern { name: "google_api_key".into(), secret_type: SecretType::GoogleApiKey, severity: SecretSeverity::High, regex: r"AIza[0-9A-Za-z_-]{35}".into(), min_entropy: 3.0 },
        SecretPattern { name: "google_oauth".into(), secret_type: SecretType::GoogleOAuthClientSecret, severity: SecretSeverity::High, regex: r"GOCSPX-[A-Za-z0-9_-]{35}".into(), min_entropy: 3.0 },
        SecretPattern { name: "azure_storage".into(), secret_type: SecretType::AzureStorageKey, severity: SecretSeverity::High, regex: r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}".into(), min_entropy: 4.0 },
        SecretPattern { name: "private_key_pem".into(), secret_type: SecretType::PrivateKeyPem, severity: SecretSeverity::Critical, regex: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----".into(), min_entropy: 0.0 },
        SecretPattern { name: "jwt".into(), secret_type: SecretType::Jwt, severity: SecretSeverity::Medium, regex: r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}".into(), min_entropy: 3.0 },
        SecretPattern { name: "twilio_key".into(), secret_type: SecretType::TwilioApiKey, severity: SecretSeverity::High, regex: r"SK[0-9a-fA-F]{32}".into(), min_entropy: 3.0 },
        SecretPattern { name: "sendgrid_key".into(), secret_type: SecretType::SendGridApiKey, severity: SecretSeverity::High, regex: r"SG\.[A-Za-z0-9_]{22}\.[A-Za-z0-9_]{43}".into(), min_entropy: 3.0 },
        SecretPattern { name: "mailgun_key".into(), secret_type: SecretType::MailgunApiKey, severity: SecretSeverity::High, regex: r"key-[0-9a-zA-Z]{32}".into(), min_entropy: 3.0 },
        SecretPattern { name: "generic_password".into(), secret_type: SecretType::GenericPassword, severity: SecretSeverity::Medium, regex: r#"(?i)(password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{8,})["']"#.into(), min_entropy: 2.0 },
        SecretPattern { name: "generic_api_key".into(), secret_type: SecretType::GenericApiKey, severity: SecretSeverity::Medium, regex: r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*["']([A-Za-z0-9_\-]{20,})["']"#.into(), min_entropy: 3.0 },
        SecretPattern { name: "generic_token".into(), secret_type: SecretType::GenericToken, severity: SecretSeverity::Medium, regex: r#"(?i)(token|secret|auth)\s*[=:]\s*["']([A-Za-z0-9_\-]{20,})["']"#.into(), min_entropy: 3.0 },
    ]
}

fn scan_line(line: &str, line_num: usize, file: &str, patterns: &[CompiledPattern]) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    for cp in patterns {
        for m in cp.regex.find_iter(line) {
            let val = cp.regex.captures(line).and_then(|c| c.get(1)).map(|g| g.as_str().to_string()).unwrap_or_else(|| m.as_str().to_string());
            if cp.pattern.min_entropy > 0.0 && shannon_entropy(&val) < cp.pattern.min_entropy { continue; }
            findings.push(SecretFinding {
                secret_type: cp.pattern.secret_type.clone(), severity: cp.pattern.severity.clone(),
                location: SecretLocation::SourceCode { file: file.to_string(), line: line_num },
                fingerprint: fingerprint(&val), redacted_preview: redact(&val, 4, 4),
                raw_value: val, pattern_name: cp.pattern.name.clone(), verified: false,
            });
        }
    }
    findings
}

fn scan_dir_recursive(dir: &Path, compiled: &[CompiledPattern], findings: &mut Vec<SecretFinding>, files_scanned: &mut usize, exts: &[&str]) -> Result<(), SecretError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') || name == "node_modules" || name == "target" || name == "vendor" { continue; }
            scan_dir_recursive(&path, compiled, findings, files_scanned, exts)?;
        } else if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !exts.contains(&ext) { continue; }
            *files_scanned += 1;
            let content = std::fs::read_to_string(&path)?;
            let file_str = path.to_string_lossy().to_string();
            for (i, line) in content.lines().enumerate() {
                findings.extend(scan_line(line, i + 1, &file_str, compiled));
            }
        }
    }
    Ok(())
}

pub fn scan_source_code(dir: &Path, patterns: &[SecretPattern]) -> Result<SecretScanResult, SecretError> {
    let compiled = compile_patterns(patterns)?;
    let mut findings = Vec::new();
    let mut files_scanned = 0;
    let exts = ["rs","js","ts","jsx","tsx","py","go","java","rb","php","c","cpp","h","cs","swift","kt","scala","clj","ex","erl","hs","r","sh","yaml","yml","json","toml","xml","ini","cfg","conf","env","properties","gradle","pem","key","crt","p12","pfx"];
    scan_dir_recursive(dir, &compiled, &mut findings, &mut files_scanned, &exts)?;
    Ok(SecretScanResult::from_findings(findings, files_scanned))
}

// ─── Goal 122: Container Image Scanning ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerLayer { pub digest: String, pub command: String, pub files: HashMap<String, String> }

pub fn scan_container_secrets(layers: &[ContainerLayer]) -> Result<SecretScanResult, SecretError> {
    let compiled = compile_patterns(&builtin_patterns())?;
    let mut findings = Vec::new();
    let mut files_scanned = 0;
    for layer in layers {
        for (file_path, content) in &layer.files {
            files_scanned += 1;
            for (i, line) in content.lines().enumerate() {
                for cp in &compiled {
                    for m in cp.regex.find_iter(line) {
                        let val = m.as_str().to_string();
                        if cp.pattern.min_entropy > 0.0 && shannon_entropy(&val) < cp.pattern.min_entropy { continue; }
                        findings.push(SecretFinding {
                            secret_type: cp.pattern.secret_type.clone(), severity: cp.pattern.severity.clone(),
                            location: SecretLocation::ContainerImage { layer: layer.digest.clone(), file: file_path.clone(), line: i + 1 },
                            fingerprint: fingerprint(&val), redacted_preview: redact(&val, 4, 4),
                            raw_value: val, pattern_name: cp.pattern.name.clone(), verified: false,
                        });
                    }
                }
            }
        }
    }
    Ok(SecretScanResult::from_findings(findings, files_scanned))
}

// ─── Goal 123: IaC Scanning ──────────────────────────────────────────────────

pub fn scan_iac_files(files: &[(IaCKind, String, String)]) -> Result<SecretScanResult, SecretError> {
    let compiled = compile_patterns(&builtin_patterns())?;
    let mut findings = Vec::new();
    for (kind, file_path, content) in files {
        for (i, line) in content.lines().enumerate() {
            for cp in &compiled {
                for m in cp.regex.find_iter(line) {
                    let val = m.as_str().to_string();
                    if cp.pattern.min_entropy > 0.0 && shannon_entropy(&val) < cp.pattern.min_entropy { continue; }
                    findings.push(SecretFinding {
                        secret_type: cp.pattern.secret_type.clone(), severity: cp.pattern.severity.clone(),
                        location: SecretLocation::IaC { file: file_path.clone(), line: i + 1, kind: kind.clone() },
                        fingerprint: fingerprint(&val), redacted_preview: redact(&val, 4, 4),
                        raw_value: val, pattern_name: cp.pattern.name.clone(), verified: false,
                    });
                }
            }
        }
    }
    Ok(SecretScanResult::from_findings(findings, files.len()))
}

// ─── Goal 124: Entropy-Based Detection ───────────────────────────────────────

pub fn detect_high_entropy(content: &str, file: &str, min_entropy: f64, min_length: usize) -> Vec<SecretFinding> {
    let token_re = Regex::new(r#"[A-Za-z0-9+/=_-]{20,}"#).unwrap();
    let mut findings = Vec::new();
    for (i, line) in content.lines().enumerate() {
        for m in token_re.find_iter(line) {
            let val = m.as_str();
            if val.len() < min_length { continue; }
            let ent = shannon_entropy(val);
            if ent >= min_entropy {
                findings.push(SecretFinding {
                    secret_type: SecretType::GenericApiKey, severity: SecretSeverity::Medium,
                    location: SecretLocation::SourceCode { file: file.to_string(), line: i + 1 },
                    fingerprint: fingerprint(val), redacted_preview: redact(val, 4, 4),
                    raw_value: val.to_string(), pattern_name: format!("entropy({:.2})", ent), verified: false,
                });
            }
        }
    }
    findings
}

// ─── Goal 125: Secret Verification ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult { pub secret_type: SecretType, pub fingerprint: String, pub is_active: bool, pub message: String }

pub fn verify_secrets(findings: &[SecretFinding]) -> Vec<VerificationResult> {
    findings.iter().map(|f| {
        let (active, msg) = verify_single(&f.secret_type, &f.raw_value);
        VerificationResult { secret_type: f.secret_type.clone(), fingerprint: f.fingerprint.clone(), is_active: active, message: msg }
    }).collect()
}

fn verify_single(st: &SecretType, val: &str) -> (bool, String) {
    match st {
        SecretType::AwsAccessKey => if val.len() == 20 && val.starts_with("AKIA") { (true, "Valid AWS key format".into()) } else { (false, "Invalid format".into()) },
        SecretType::GitHubToken => if val.starts_with("ghp_") || val.starts_with("gho_") || val.starts_with("ghu_") || val.starts_with("ghs_") || val.starts_with("ghr_") || val.starts_with("github_pat_") { (true, "Valid GitHub token format".into()) } else { (false, "Invalid format".into()) },
        SecretType::PrivateKeyPem => if val.contains("-----BEGIN") && val.contains("PRIVATE KEY-----") { (true, "Private key detected".into()) } else { (false, "Invalid format".into()) },
        _ => (false, "Verification not implemented for this type".into()),
    }
}

// ─── Goal 126: Custom Secret Patterns ────────────────────────────────────────

pub fn load_custom_patterns(json: &str) -> Result<Vec<SecretPattern>, SecretError> {
    Ok(serde_json::from_str(json)?)
}

pub fn load_custom_patterns_yaml(yaml: &str) -> Result<Vec<SecretPattern>, SecretError> {
    Ok(serde_yaml::from_str(yaml)?)
}

// ─── Goal 127: Git History Scanning ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitCommitContent { pub commit_sha: String, pub files: HashMap<String, String> }

pub fn scan_git_history(commits: &[GitCommitContent]) -> Result<SecretScanResult, SecretError> {
    let compiled = compile_patterns(&builtin_patterns())?;
    let mut findings = Vec::new();
    let mut files_scanned = 0;
    for commit in commits {
        for (file_path, content) in &commit.files {
            files_scanned += 1;
            for (i, line) in content.lines().enumerate() {
                for cp in &compiled {
                    for m in cp.regex.find_iter(line) {
                        let val = m.as_str().to_string();
                        if cp.pattern.min_entropy > 0.0 && shannon_entropy(&val) < cp.pattern.min_entropy { continue; }
                        findings.push(SecretFinding {
                            secret_type: cp.pattern.secret_type.clone(), severity: cp.pattern.severity.clone(),
                            location: SecretLocation::GitHistory { commit: commit.commit_sha.clone(), file: file_path.clone(), line: i + 1 },
                            fingerprint: fingerprint(&val), redacted_preview: redact(&val, 4, 4),
                            raw_value: val, pattern_name: cp.pattern.name.clone(), verified: false,
                        });
                    }
                }
            }
        }
    }
    Ok(SecretScanResult::from_findings(findings, files_scanned))
}

// ─── Goal 128: .env File Scanning ────────────────────────────────────────────

pub fn scan_env_files(files: &[(String, String)]) -> Result<SecretScanResult, SecretError> {
    let compiled = compile_patterns(&builtin_patterns())?;
    let sensitive_re = Regex::new(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|client[_-]?secret|auth)")?;
    let mut findings = Vec::new();
    for (file_path, content) in files {
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
            if let Some(eq) = trimmed.find('=') {
                let key = &trimmed[..eq];
                let val = trimmed[eq + 1..].trim_matches(|c| c == '"' || c == '\'');
                if sensitive_re.is_match(key) && !val.is_empty() {
                    findings.push(SecretFinding {
                        secret_type: SecretType::GenericPassword, severity: SecretSeverity::High,
                        location: SecretLocation::EnvFile { file: file_path.clone(), line: i + 1 },
                        fingerprint: fingerprint(val), redacted_preview: redact(val, 2, 2),
                        raw_value: val.to_string(), pattern_name: "env_sensitive_var".into(), verified: false,
                    });
                    continue;
                }
            }
            for cp in &compiled {
                for m in cp.regex.find_iter(line) {
                    let val = m.as_str().to_string();
                    if cp.pattern.min_entropy > 0.0 && shannon_entropy(&val) < cp.pattern.min_entropy { continue; }
                    findings.push(SecretFinding {
                        secret_type: cp.pattern.secret_type.clone(), severity: cp.pattern.severity.clone(),
                        location: SecretLocation::EnvFile { file: file_path.clone(), line: i + 1 },
                        fingerprint: fingerprint(&val), redacted_preview: redact(&val, 4, 4),
                        raw_value: val, pattern_name: cp.pattern.name.clone(), verified: false,
                    });
                }
            }
        }
    }
    Ok(SecretScanResult::from_findings(findings, files.len()))
}

// ─── Goal 129: Manifest Credential Detection ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestKind { Npmrc, CargoConfig, PipConf, MavenSettings, GradleProperties, NugetConfig, DockerConfig, Generic }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestToScan { pub file: String, pub kind: ManifestKind, pub content: String }

pub fn scan_manifests(manifests: &[ManifestToScan]) -> Result<SecretScanResult, SecretError> {
    let compiled = compile_patterns(&builtin_patterns())?;
    let npm_auth_re = Regex::new(r"(?i)//[^/]+/:_authToken\s*=\s*(.+)")?;
    let cargo_token_re = Regex::new(r#"(?i)token\s*=\s*["']([^"']+)["']"#)?;
    let pip_re = Regex::new(r"(?i)index-url\s*=\s*https?://([^:]+):([^@]+)@")?;
    let maven_re = Regex::new(r#"(?i)<password>([^<]+)</password>"#)?;
    let nuget_re = Regex::new(r#"(?i)<add\s+key="[\w]*[Aa]pi[\w]*"\s+value="([^"]+)"\s*/>"#)?;
    let docker_re = Regex::new(r#""auth"\s*:\s*"([A-Za-z0-9+/=]+)""#)?;
    let gradle_re = Regex::new(r"(?i)(password|apiKey|secret|token)\s*=\s*(.+)")?;
    let mut findings = Vec::new();

    for manifest in manifests {
        for (i, line) in manifest.content.lines().enumerate() {
            let matches: Vec<(SecretType, String)> = match manifest.kind {
                ManifestKind::Npmrc => npm_auth_re.captures(line).map(|c| vec![(SecretType::GenericToken, c[1].trim().to_string())]).unwrap_or_default(),
                ManifestKind::CargoConfig => cargo_token_re.captures(line).map(|c| vec![(SecretType::GenericToken, c[1].to_string())]).unwrap_or_default(),
                ManifestKind::PipConf => pip_re.captures(line).map(|c| vec![(SecretType::GenericPassword, c[2].to_string())]).unwrap_or_default(),
                ManifestKind::MavenSettings => maven_re.captures(line).map(|c| vec![(SecretType::GenericPassword, c[1].to_string())]).unwrap_or_default(),
                ManifestKind::NugetConfig => nuget_re.captures(line).map(|c| vec![(SecretType::GenericApiKey, c[1].to_string())]).unwrap_or_default(),
                ManifestKind::DockerConfig => docker_re.captures(line).map(|c| vec![(SecretType::GenericToken, c[1].to_string())]).unwrap_or_default(),
                ManifestKind::GradleProperties => gradle_re.captures(line).map(|c| vec![(SecretType::GenericPassword, c[2].trim().to_string())]).unwrap_or_default(),
                ManifestKind::Generic => vec![],
            };
            for (st, val) in matches {
                findings.push(SecretFinding {
                    secret_type: st, severity: SecretSeverity::High,
                    location: SecretLocation::Manifest { file: manifest.file.clone(), field: format!("line {}", i + 1) },
                    fingerprint: fingerprint(&val), redacted_preview: redact(&val, 4, 4),
                    raw_value: val, pattern_name: format!("manifest_{:?}", manifest.kind).to_lowercase(), verified: false,
                });
            }
            for cp in &compiled {
                for m in cp.regex.find_iter(line) {
                    let val = m.as_str().to_string();
                    if cp.pattern.min_entropy > 0.0 && shannon_entropy(&val) < cp.pattern.min_entropy { continue; }
                    findings.push(SecretFinding {
                        secret_type: cp.pattern.secret_type.clone(), severity: cp.pattern.severity.clone(),
                        location: SecretLocation::Manifest { file: manifest.file.clone(), field: format!("line {}", i + 1) },
                        fingerprint: fingerprint(&val), redacted_preview: redact(&val, 4, 4),
                        raw_value: val, pattern_name: cp.pattern.name.clone(), verified: false,
                    });
                }
            }
        }
    }
    Ok(SecretScanResult::from_findings(findings, manifests.len()))
}

// ─── Goal 130: Rotation Guidance ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationGuidance {
    pub secret_type: SecretType, pub service: String, pub severity: SecretSeverity,
    pub steps: Vec<String>, pub revoke_url: Option<String>, pub documentation_url: Option<String>,
}

pub fn rotation_guidance(secret_type: &SecretType) -> RotationGuidance {
    match secret_type {
        SecretType::AwsAccessKey | SecretType::AwsSecretKey => RotationGuidance {
            secret_type: secret_type.clone(), service: "AWS IAM".into(), severity: SecretSeverity::Critical,
            steps: vec!["1. Go to AWS IAM Console → Users → Security credentials".into(), "2. Create a new access key pair".into(), "3. Update application configuration".into(), "4. Deactivate and delete the old key".into(), "5. Review CloudTrail for unauthorized usage".into()],
            revoke_url: Some("https://console.aws.amazon.com/iam/".into()), documentation_url: Some("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html".into()),
        },
        SecretType::GitHubToken => RotationGuidance {
            secret_type: secret_type.clone(), service: "GitHub".into(), severity: SecretSeverity::Critical,
            steps: vec!["1. Go to GitHub Settings → Developer settings → Personal access tokens".into(), "2. Regenerate or create a new token".into(), "3. Update CI/CD secrets".into(), "4. Revoke the old token".into(), "5. Review audit log".into()],
            revoke_url: Some("https://github.com/settings/tokens".into()), documentation_url: Some("https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens".into()),
        },
        SecretType::GitLabToken => RotationGuidance {
            secret_type: secret_type.clone(), service: "GitLab".into(), severity: SecretSeverity::High,
            steps: vec!["1. Go to GitLab → User Settings → Access Tokens".into(), "2. Revoke the leaked token".into(), "3. Create a new token".into(), "4. Update CI/CD variables".into()],
            revoke_url: Some("https://gitlab.com/-/profile/personal_access_tokens".into()), documentation_url: None,
        },
        SecretType::SlackToken => RotationGuidance {
            secret_type: secret_type.clone(), service: "Slack".into(), severity: SecretSeverity::High,
            steps: vec!["1. Go to Slack API → Your Apps → OAuth & Permissions".into(), "2. Revoke the token".into(), "3. Reinstall the app".into(), "4. Update integrations".into()],
            revoke_url: Some("https://api.slack.com/apps".into()), documentation_url: None,
        },
        SecretType::StripeKey => RotationGuidance {
            secret_type: secret_type.clone(), service: "Stripe".into(), severity: SecretSeverity::Critical,
            steps: vec!["1. Go to Stripe Dashboard → Developers → API Keys".into(), "2. Roll the API key".into(), "3. Update application".into(), "4. Review logs for unauthorized charges".into()],
            revoke_url: Some("https://dashboard.stripe.com/apikeys".into()), documentation_url: None,
        },
        SecretType::GoogleApiKey | SecretType::GoogleOAuthClientSecret => RotationGuidance {
            secret_type: secret_type.clone(), service: "Google Cloud".into(), severity: SecretSeverity::High,
            steps: vec!["1. Go to Google Cloud Console → APIs & Services → Credentials".into(), "2. Delete the leaked key/secret".into(), "3. Create new credentials with restricted usage".into(), "4. Update application".into()],
            revoke_url: Some("https://console.cloud.google.com/apis/credentials".into()), documentation_url: None,
        },
        SecretType::PrivateKeyPem => RotationGuidance {
            secret_type: secret_type.clone(), service: "SSL/TLS or SSH".into(), severity: SecretSeverity::Critical,
            steps: vec!["1. Revoke and regenerate the private key immediately".into(), "2. For TLS: obtain a new certificate".into(), "3. For SSH: generate a new keypair, update authorized_keys".into(), "4. Deploy new key to all services".into(), "5. Audit access logs".into()],
            revoke_url: None, documentation_url: None,
        },
        SecretType::AzureStorageKey => RotationGuidance {
            secret_type: secret_type.clone(), service: "Azure Storage".into(), severity: SecretSeverity::High,
            steps: vec!["1. Go to Azure Portal → Storage Account → Access keys".into(), "2. Regenerate key".into(), "3. Update applications".into(), "4. Verify new key works".into()],
            revoke_url: Some("https://portal.azure.com/".into()), documentation_url: None,
        },
        SecretType::TwilioApiKey => RotationGuidance {
            secret_type: secret_type.clone(), service: "Twilio".into(), severity: SecretSeverity::High,
            steps: vec!["1. Go to Twilio Console → Settings → API Keys".into(), "2. Delete the leaked key".into(), "3. Create a new key".into()],
            revoke_url: Some("https://console.twilio.com/".into()), documentation_url: None,
        },
        SecretType::SendGridApiKey => RotationGuidance {
            secret_type: secret_type.clone(), service: "SendGrid".into(), severity: SecretSeverity::High,
            steps: vec!["1. Go to SendGrid → Settings → API Keys".into(), "2. Delete the leaked key".into(), "3. Create a new key with restricted permissions".into()],
            revoke_url: Some("https://app.sendgrid.com/settings/api_keys".into()), documentation_url: None,
        },
        SecretType::MailgunApiKey => RotationGuidance {
            secret_type: secret_type.clone(), service: "Mailgun".into(), severity: SecretSeverity::High,
            steps: vec!["1. Go to Mailgun Dashboard → Settings → API Keys".into(), "2. Delete the leaked key".into(), "3. Create a new key".into()],
            revoke_url: Some("https://app.mailgun.com/".into()), documentation_url: None,
        },
        SecretType::Jwt => RotationGuidance {
            secret_type: secret_type.clone(), service: "JWT Authentication".into(), severity: SecretSeverity::Medium,
            steps: vec!["1. Rotate the JWT signing secret".into(), "2. Invalidate all outstanding JWTs".into(), "3. Force re-authentication".into()],
            revoke_url: None, documentation_url: None,
        },
        SecretType::GenericPassword | SecretType::GenericApiKey | SecretType::GenericToken => RotationGuidance {
            secret_type: secret_type.clone(), service: "Unknown".into(), severity: SecretSeverity::Medium,
            steps: vec!["1. Identify which service this credential belongs to".into(), "2. Rotate through the service's admin interface".into(), "3. Update all applications".into(), "4. Move to environment variables or a secrets manager".into()],
            revoke_url: None, documentation_url: None,
        },
        SecretType::Custom(name) => RotationGuidance {
            secret_type: secret_type.clone(), service: name.clone(), severity: SecretSeverity::Medium,
            steps: vec!["1. Identify the service for this custom secret type".into(), "2. Rotate through the service's mechanism".into(), "3. Update all applications".into(), "4. Store in a secrets manager".into()],
            revoke_url: None, documentation_url: None,
        },
    }
}

pub fn rotation_guidance_for_scan(result: &SecretScanResult) -> Vec<RotationGuidance> {
    let mut seen = std::collections::HashSet::new();
    result.findings.iter().filter_map(|f| seen.insert(f.secret_type.to_string()).then(|| rotation_guidance(&f.secret_type))).collect()
}

/// Generate a human-readable report of secret scan findings.
pub fn secret_scan_report(result: &SecretScanResult) -> String {
    let mut out = String::new();
    out.push_str("# PledgeRecon Secret Scan Report\n\n");
    out.push_str(&format!("**Files scanned:** {} | **Secrets found:** {}\n\n", result.files_scanned, result.total_secrets));
    if result.findings.is_empty() { out.push_str("No secrets detected. ✅\n"); return out; }
    let mut sorted = result.findings.clone();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));
    out.push_str("| Severity | Type | Location | Pattern |\n|---|---|---|---|\n");
    for f in &sorted {
        let loc = match &f.location {
            SecretLocation::SourceCode { file, line } => format!("{}:{}", file, line),
            SecretLocation::ContainerImage { layer, file, line } => format!("{}:{}/{}:{}", layer, file, line, ""),
            SecretLocation::IaC { file, line, .. } => format!("{}:{}", file, line),
            SecretLocation::GitHistory { commit, file, line } => format!("{}@{}:{}", commit, file, line),
            SecretLocation::EnvFile { file, line } => format!("{}:{}", file, line),
            SecretLocation::Manifest { file, field } => format!("{}:{}", file, field),
        };
        out.push_str(&format!("| {} | {} | {} | {} |\n", f.severity, f.secret_type, loc, f.pattern_name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn make_finding(st: SecretType, sev: SecretSeverity, val: &str) -> SecretFinding {
        SecretFinding {
            secret_type: st, severity: sev,
            location: SecretLocation::SourceCode { file: "test.rs".into(), line: 1 },
            fingerprint: fingerprint(val), redacted_preview: redact(val, 4, 4),
            raw_value: val.to_string(), pattern_name: "test".into(), verified: false,
        }
    }

    #[test]
    fn test_shannon_entropy() {
        assert!(shannon_entropy("aaaa") < 1.0);
        assert!(shannon_entropy("abcd") > 1.5);
        assert_eq!(shannon_entropy(""), 0.0);
        let high = shannon_entropy("AKIAIOSFODNN7EXAMPLE");
        assert!(high > 3.0, "expected high entropy, got {}", high);
    }

    #[test]
    fn test_redact() {
        assert_eq!(redact("abcdefgh", 2, 2), "ab...gh");
        assert_eq!(redact("ab", 2, 2), "**");
    }

    #[test]
    fn test_builtin_patterns_count() {
        let patterns = builtin_patterns();
        assert!(patterns.len() >= 15);
    }

    #[test]
    fn test_scan_source_code_aws_key() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("config.rs"), "let key = \"AKIAIOSFODNN7EXAMPLE\";\n").unwrap();
        let result = scan_source_code(dir.path(), &builtin_patterns()).unwrap();
        assert!(result.total_secrets >= 1);
        assert!(result.by_severity.contains_key("critical"));
        assert!(result.findings.iter().any(|f| f.secret_type == SecretType::AwsAccessKey));
    }

    #[test]
    fn test_scan_source_code_github_token() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("ci.yml"), "token: ghp_1234567890abcdefghijklmnopqrstuvwxyz\n").unwrap();
        let result = scan_source_code(dir.path(), &builtin_patterns()).unwrap();
        assert!(result.findings.iter().any(|f| f.secret_type == SecretType::GitHubToken));
    }

    #[test]
    fn test_scan_source_code_no_secrets() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() { println!(\"hello\"); }\n").unwrap();
        let result = scan_source_code(dir.path(), &builtin_patterns()).unwrap();
        assert_eq!(result.total_secrets, 0);
    }

    #[test]
    fn test_scan_source_code_private_key() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("key.pem"), "-----BEGIN RSA PRIVATE KEY-----\n").unwrap();
        let result = scan_source_code(dir.path(), &builtin_patterns()).unwrap();
        assert!(result.findings.iter().any(|f| f.secret_type == SecretType::PrivateKeyPem));
    }

    #[test]
    fn test_scan_container_image() {
        let layers = vec![ContainerLayer {
            digest: "sha256:abc".into(), command: "COPY .".into(),
            files: [("etc/config".into(), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n".into())].into(),
        }];
        let result = scan_container_secrets(&layers).unwrap();
        assert!(result.total_secrets >= 1);
        assert!(result.findings.iter().any(|f| matches!(f.location, SecretLocation::ContainerImage { .. })));
    }

    #[test]
    fn test_scan_iac_terraform() {
        let files = vec![(IaCKind::Terraform, "main.tf".into(), "access_key = \"AKIAIOSFODNN7EXAMPLE\"\n".into())];
        let result = scan_iac_files(&files).unwrap();
        assert!(result.total_secrets >= 1);
        assert!(result.findings.iter().any(|f| matches!(f.location, SecretLocation::IaC { kind: IaCKind::Terraform, .. })));
    }

    #[test]
    fn test_detect_high_entropy() {
        let content = "random_base64_string_here_dGhpcyBpcyBhIHZlcnkgbG9uZyBlbnRyb3BpYw==";
        let findings = detect_high_entropy(content, "test.txt", 4.0, 20);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_high_entropy_low_string() {
        let content = "aaaaaaa";
        let findings = detect_high_entropy(content, "test.txt", 3.0, 5);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_verify_aws_key() {
        let f = make_finding(SecretType::AwsAccessKey, SecretSeverity::Critical, "AKIAIOSFODNN7EXAMPLE");
        let results = verify_secrets(&[f]);
        assert!(results[0].is_active);
    }

    #[test]
    fn test_verify_github_token() {
        let f = make_finding(SecretType::GitHubToken, SecretSeverity::Critical, "ghp_1234567890abcdefghijklmnopqrstuvwxyz");
        let results = verify_secrets(&[f]);
        assert!(results[0].is_active);
    }

    #[test]
    fn test_verify_invalid_key() {
        let f = make_finding(SecretType::AwsAccessKey, SecretSeverity::Critical, "INVALID");
        let results = verify_secrets(&[f]);
        assert!(!results[0].is_active);
    }

    #[test]
    fn test_load_custom_patterns_json() {
        let json = r#"[{"name":"custom_pat","secret_type":{"Custom":"MyType"},"severity":"High","regex":"MYPATTERN[0-9]+","min_entropy":0.0}]"#;
        let patterns = load_custom_patterns(json).unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].name, "custom_pat");
    }

    #[test]
    fn test_load_custom_patterns_yaml() {
        let yaml = "- name: custom_yaml\n  secret_type: GenericApiKey\n  severity: High\n  regex: \"YAMLPATTERN\\\\d+\"\n  min_entropy: 0.0\n";
        let patterns = load_custom_patterns_yaml(yaml).unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].name, "custom_yaml");
    }

    #[test]
    fn test_scan_git_history() {
        let commits = vec![GitCommitContent {
            commit_sha: "abc123".into(),
            files: [("config.py".into(), "SECRET = \"AKIAIOSFODNN7EXAMPLE\"\n".into())].into(),
        }];
        let result = scan_git_history(&commits).unwrap();
        assert!(result.total_secrets >= 1);
        assert!(result.findings.iter().any(|f| matches!(&f.location, SecretLocation::GitHistory { commit, .. } if commit == "abc123")));
    }

    #[test]
    fn test_scan_env_files() {
        let files = vec![(".env".into(), "DATABASE_PASSWORD=mysecret123\nAPI_KEY=AKIAIOSFODNN7EXAMPLE\n# comment\n".into())];
        let result = scan_env_files(&files).unwrap();
        assert!(result.total_secrets >= 2);
        assert!(result.findings.iter().any(|f| matches!(f.location, SecretLocation::EnvFile { .. })));
    }

    #[test]
    fn test_scan_env_files_skips_comments() {
        let files = vec![(".env".into(), "# DATABASE_PASSWORD=secret\n\n".into())];
        let result = scan_env_files(&files).unwrap();
        assert_eq!(result.total_secrets, 0);
    }

    #[test]
    fn test_scan_manifests_npmrc() {
        let manifests = vec![ManifestToScan {
            file: ".npmrc".into(), kind: ManifestKind::Npmrc,
            content: "//registry.npmjs.org/:_authToken=abc123def456\n".into(),
        }];
        let result = scan_manifests(&manifests).unwrap();
        assert!(result.findings.iter().any(|f| f.secret_type == SecretType::GenericToken));
    }

    #[test]
    fn test_scan_manifests_cargo_config() {
        let manifests = vec![ManifestToScan {
            file: ".cargo/config.toml".into(), kind: ManifestKind::CargoConfig,
            content: "token = \"my_secret_cargo_token_here\"\n".into(),
        }];
        let result = scan_manifests(&manifests).unwrap();
        assert!(result.findings.iter().any(|f| f.secret_type == SecretType::GenericToken));
    }

    #[test]
    fn test_scan_manifests_maven_settings() {
        let manifests = vec![ManifestToScan {
            file: "settings.xml".into(), kind: ManifestKind::MavenSettings,
            content: "<password>my_super_secret_password</password>\n".into(),
        }];
        let result = scan_manifests(&manifests).unwrap();
        assert!(result.findings.iter().any(|f| f.secret_type == SecretType::GenericPassword));
    }

    #[test]
    fn test_rotation_guidance_aws() {
        let g = rotation_guidance(&SecretType::AwsAccessKey);
        assert_eq!(g.service, "AWS IAM");
        assert_eq!(g.severity, SecretSeverity::Critical);
        assert!(!g.steps.is_empty());
        assert!(g.revoke_url.is_some());
    }

    #[test]
    fn test_rotation_guidance_github() {
        let g = rotation_guidance(&SecretType::GitHubToken);
        assert_eq!(g.service, "GitHub");
        assert_eq!(g.severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_rotation_guidance_private_key() {
        let g = rotation_guidance(&SecretType::PrivateKeyPem);
        assert_eq!(g.severity, SecretSeverity::Critical);
        assert!(g.steps.len() >= 4);
    }

    #[test]
    fn test_rotation_guidance_for_scan() {
        let result = SecretScanResult::from_findings(vec![
            make_finding(SecretType::AwsAccessKey, SecretSeverity::Critical, "AKIAIOSFODNN7EXAMPLE"),
            make_finding(SecretType::GitHubToken, SecretSeverity::Critical, "ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
            make_finding(SecretType::AwsAccessKey, SecretSeverity::Critical, "AKIAEXAMPLE2"),
        ], 1);
        let guides = rotation_guidance_for_scan(&result);
        assert_eq!(guides.len(), 2); // deduped by type
    }

    #[test]
    fn test_secret_scan_report_empty() {
        let result = SecretScanResult::from_findings(vec![], 5);
        let report = secret_scan_report(&result);
        assert!(report.contains("No secrets detected"));
    }

    #[test]
    fn test_secret_scan_report_with_findings() {
        let result = SecretScanResult::from_findings(vec![
            make_finding(SecretType::AwsAccessKey, SecretSeverity::Critical, "AKIAIOSFODNN7EXAMPLE"),
        ], 1);
        let report = secret_scan_report(&result);
        assert!(report.contains("Secret Scan Report"));
        assert!(report.contains("AwsAccessKey"));
    }

    #[test]
    fn test_fingerprint_dedup() {
        let f1 = fingerprint("same_value");
        let f2 = fingerprint("same_value");
        let f3 = fingerprint("different_value");
        assert_eq!(f1, f2);
        assert_ne!(f1, f3);
    }
}
