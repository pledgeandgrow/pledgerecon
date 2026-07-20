//! Configuration — scan options, ignore rules, and advisory sources.
//!
//! Configuration is loaded from a `pledgerecon.toml` file in the project root,
//! or from environment variables. It controls which ecosystems to scan,
//! severity thresholds for CI gating, ignore rules, and advisory database
//! sources.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors when loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error reading config: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parsing failed: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// The scan configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Advisory database sources to query.
    #[serde(default)]
    pub advisory_sources: Vec<AdvisorySource>,

    /// Minimum severity to report (findings below this are filtered out).
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    /// Whether to perform AST-based reachability analysis.
    #[serde(default = "default_true")]
    pub reachability: bool,

    /// Whether to perform LLM-powered triage.
    #[serde(default)]
    pub triage: bool,

    /// LLM triage configuration.
    #[serde(default)]
    pub triage_config: TriageConfig,

    /// Whether to generate an SBOM.
    #[serde(default)]
    pub generate_sbom: bool,

    /// SBOM output format ("spdx" or "cyclonedx").
    #[serde(default = "default_sbom_format")]
    pub sbom_format: String,

    /// SBOM output path.
    #[serde(default = "default_sbom_path")]
    pub sbom_path: PathBuf,

    /// Packages to ignore (by name or advisory ID).
    #[serde(default)]
    pub ignore: Vec<IgnoreRule>,

    /// Output format for findings.
    #[serde(default = "default_output_format")]
    pub output_format: String,

    /// Output file path (stdout if not specified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<PathBuf>,

    /// Whether to fail (non-zero exit code) on findings.
    #[serde(default)]
    pub fail_on_findings: bool,

    /// Whether to enable WASM custom rules.
    #[serde(default)]
    pub wasm_rules: bool,

    /// Path to WASM rule files.
    #[serde(default)]
    pub wasm_rule_paths: Vec<PathBuf>,

    /// WASM plugin configuration (Goals 46–55).
    #[serde(default)]
    pub wasm_plugin_config: WasmPluginConfig,

    /// GitHub API token for GHSA queries (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_token: Option<String>,

    /// Cache directory for advisory database.
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,

    /// Whether to use cached advisory data when offline.
    #[serde(default = "default_true")]
    pub offline: bool,

    /// Maximum number of concurrent scans.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    /// Cache TTL in hours — advisory cache entries expire after this duration.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_hours: u64,

    /// NVD API key (optional, but recommended for higher rate limits).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvd_api_key: Option<String>,
    /// Slack webhook URL for post-scan notifications (Goal 63).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slack_webhook_url: Option<String>,
    /// Microsoft Teams webhook URL for post-scan notifications (Goal 64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams_webhook_url: Option<String>,
    /// SMTP host for email reports (Goal 65).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp_host: Option<String>,
    /// SMTP port for email reports (Goal 65).
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    /// SMTP username for email reports (Goal 65).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp_username: Option<String>,
    /// SMTP password for email reports (Goal 65).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp_password: Option<String>,
    /// From email address for email reports (Goal 65).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_from: Option<String>,
    /// Recipient email addresses for email reports (Goal 65).
    #[serde(default)]
    pub email_to: Vec<String>,
    /// Path to baseline file for baseline comparison (Goal 73).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_path: Option<PathBuf>,
    /// Path for trend history file (Goal 59).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trend_path: Option<PathBuf>,
    /// Whether to fail only on new vulnerabilities not in baseline (Goal 73).
    #[serde(default)]
    pub fail_on_new_only: bool,
    /// Whether to generate auto-fix suggestions (Goal 72).
    #[serde(default)]
    pub generate_autofix: bool,
}

/// An advisory database source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdvisorySource {
    /// OSV.dev (Google's open source vulnerability database).
    Osv,
    /// GitHub Security Advisories.
    Ghsa,
    /// NVD (National Vulnerability Database).
    Nvd,
    /// A local advisory database file.
    Local { path: PathBuf },
}

/// An ignore rule — suppress findings matching specific criteria.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgnoreRule {
    /// Package name to ignore (e.g. "npm:lodash").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Advisory ID to ignore (e.g. "CVE-2024-12345").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_id: Option<String>,
    /// Ignore reason (for audit trail).
    #[serde(default)]
    pub reason: String,
    /// Expiry date (ISO 8601). After this date, the ignore is no longer applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

/// LLM triage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageConfig {
    /// LLM provider ("openai", "anthropic", "ollama", "llamacpp", "local").
    #[serde(default = "default_triage_provider")]
    pub provider: String,
    /// API key for the LLM provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Model name.
    #[serde(default = "default_triage_model")]
    pub model: String,
    /// API endpoint (for self-hosted models).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Maximum tokens for triage response.
    #[serde(default = "default_triage_max_tokens")]
    pub max_tokens: usize,
    /// Batch size for batch LLM calls (Goal 36). 0 = no batching.
    #[serde(default = "default_triage_batch_size")]
    pub batch_size: usize,
    /// Enable streaming responses (Goal 38).
    #[serde(default)]
    pub stream: bool,
    /// Path to llama.cpp model file for local inference (Goal 39).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llamacpp_model_path: Option<PathBuf>,
    /// Path to fine-tuned model file (Goal 40).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fine_tuned_model_path: Option<PathBuf>,
    /// Custom prompt template (Goal 41). Uses {placeholders}.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_template: Option<String>,
    /// Confidence threshold for auto-suppressing findings (Goal 42).
    /// Findings with triage confidence >= threshold and verdict false_positive
    /// are automatically suppressed.
    #[serde(default = "default_triage_confidence_threshold")]
    pub confidence_threshold: f64,
    /// Additional models for multi-model consensus (Goal 43).
    /// Each entry is a "provider:model" string.
    #[serde(default)]
    pub consensus_models: Vec<String>,
    /// Enable triage audit log (Goal 44).
    #[serde(default)]
    pub audit_log: bool,
    /// Path for audit log output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_log_path: Option<PathBuf>,
    /// Enable cost tracking (Goal 45).
    #[serde(default)]
    pub cost_tracking: bool,
    /// Cost per 1K input tokens (USD).
    #[serde(default = "default_cost_per_input_token")]
    pub cost_per_input_token: f64,
    /// Cost per 1K output tokens (USD).
    #[serde(default = "default_cost_per_output_token")]
    pub cost_per_output_token: f64,
    /// Cache directory for triage result caching (Goal 37).
    #[serde(default = "default_triage_cache_dir")]
    pub cache_dir: PathBuf,
    /// Enable triage result caching (Goal 37).
    #[serde(default = "default_true")]
    pub enable_cache: bool,
}

/// WASM plugin configuration (Goals 46–55).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmPluginConfig {
    /// Fuel limit for WASM execution (Goal 46). 0 = unlimited.
    #[serde(default = "default_wasm_fuel")]
    pub fuel_limit: u64,
    /// Enable plugin signature verification (Goal 49).
    #[serde(default)]
    pub verify_signatures: bool,
    /// Path to public key for signature verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_public_key: Option<PathBuf>,
    /// Plugin permissions (Goal 50).
    #[serde(default)]
    pub permissions: Vec<PluginPermission>,
    /// Enable hot-reload of plugins (Goal 51).
    #[serde(default)]
    pub hot_reload: bool,
    /// Enable parallel plugin execution (Goal 52).
    #[serde(default = "default_true")]
    pub parallel: bool,
    /// Plugin registry URL (Goal 48).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_url: Option<String>,
}

/// Granular plugin permissions (Goal 50).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginPermission {
    /// Read dependency manifests.
    ReadManifests,
    /// Read source code files.
    ReadSource,
    /// Read advisory data.
    ReadAdvisories,
    /// Network access.
    Network,
    /// File system write (for generating reports).
    WriteFile,
    /// Environment variable access.
    Environment,
}

impl Default for TriageConfig {
    fn default() -> Self {
        Self {
            provider: default_triage_provider(),
            api_key: None,
            model: default_triage_model(),
            endpoint: None,
            max_tokens: default_triage_max_tokens(),
            batch_size: default_triage_batch_size(),
            stream: false,
            llamacpp_model_path: None,
            fine_tuned_model_path: None,
            prompt_template: None,
            confidence_threshold: default_triage_confidence_threshold(),
            consensus_models: Vec::new(),
            audit_log: false,
            audit_log_path: None,
            cost_tracking: false,
            cost_per_input_token: default_cost_per_input_token(),
            cost_per_output_token: default_cost_per_output_token(),
            cache_dir: default_triage_cache_dir(),
            enable_cache: true,
        }
    }
}

impl Default for WasmPluginConfig {
    fn default() -> Self {
        Self {
            fuel_limit: default_wasm_fuel(),
            verify_signatures: false,
            signature_public_key: None,
            permissions: Vec::new(),
            hot_reload: false,
            parallel: true,
            registry_url: None,
        }
    }
}

impl IgnoreRule {
    /// Check if this ignore rule matches a finding.
    pub fn matches(&self, package: &str, advisory_id: &str) -> bool {
        let pkg_match = self
            .package
            .as_ref()
            .map(|p| package.eq_ignore_ascii_case(p))
            .unwrap_or(true);
        let adv_match = self
            .advisory_id
            .as_ref()
            .map(|a| advisory_id.eq_ignore_ascii_case(a))
            .unwrap_or(true);
        pkg_match && adv_match
    }

    /// Check if this ignore rule has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(ref expires) = self.expires
            && let Ok(date) = chrono::NaiveDateTime::parse_from_str(expires, "%Y-%m-%dT%H:%M:%S")
                .or_else(|_| {
                    chrono::NaiveDate::parse_from_str(expires, "%Y-%m-%d")
                        .map(|d| d.and_hms_opt(0, 0, 0).unwrap())
                })
        {
            return chrono::Utc::now().naive_utc() > date;
        }
        false
    }
}

impl ScanConfig {
    /// Load configuration from a `pledgerecon.toml` file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: ScanConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from the project root, looking for `pledgerecon.toml`.
    pub fn from_root(root: &Path) -> Result<Self, ConfigError> {
        let config_path = root.join("pledgerecon.toml");
        if config_path.exists() {
            Self::from_file(&config_path)
        } else {
            Ok(Self::default())
        }
    }

    /// Save the configuration to a file.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let content =
            toml::to_string_pretty(self).map_err(|e| ConfigError::Invalid(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Validate the configuration.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.concurrency == 0 {
            return Err(ConfigError::Invalid("concurrency must be > 0".to_string()));
        }
        Ok(())
    }

    /// Check if a finding should be ignored.
    pub fn is_ignored(&self, package: &str, advisory_id: &str) -> bool {
        self.ignore
            .iter()
            .any(|rule| !rule.is_expired() && rule.matches(package, advisory_id))
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            advisory_sources: vec![AdvisorySource::Osv, AdvisorySource::Ghsa],
            min_severity: default_min_severity(),
            reachability: true,
            triage: false,
            triage_config: TriageConfig::default(),
            generate_sbom: false,
            sbom_format: default_sbom_format(),
            sbom_path: default_sbom_path(),
            ignore: Vec::new(),
            output_format: default_output_format(),
            output_path: None,
            fail_on_findings: false,
            wasm_rules: false,
            wasm_rule_paths: Vec::new(),
            wasm_plugin_config: WasmPluginConfig::default(),
            github_token: None,
            cache_dir: default_cache_dir(),
            offline: true,
            concurrency: default_concurrency(),
            cache_ttl_hours: default_cache_ttl(),
            nvd_api_key: None,
            slack_webhook_url: None,
            teams_webhook_url: None,
            smtp_host: None,
            smtp_port: default_smtp_port(),
            smtp_username: None,
            smtp_password: None,
            email_from: None,
            email_to: Vec::new(),
            baseline_path: None,
            trend_path: None,
            fail_on_new_only: false,
            generate_autofix: false,
        }
    }
}

/// Load configuration from the project root.
pub fn load_config(root: &Path) -> Result<ScanConfig, ConfigError> {
    ScanConfig::from_root(root)
}

// ─── Default value functions ─────────────────────────────────────────────

fn default_min_severity() -> String {
    "low".to_string()
}

fn default_true() -> bool {
    true
}

fn default_sbom_format() -> String {
    "cyclonedx".to_string()
}

fn default_sbom_path() -> PathBuf {
    PathBuf::from("sbom.json")
}

fn default_output_format() -> String {
    "text".to_string()
}

fn default_cache_dir() -> PathBuf {
    PathBuf::from(".pledgerecon-cache")
}

fn default_concurrency() -> usize {
    8
}

fn default_cache_ttl() -> u64 {
    24
}

fn default_smtp_port() -> u16 {
    587
}

fn default_triage_provider() -> String {
    "openai".to_string()
}

fn default_triage_model() -> String {
    "gpt-4o-mini".to_string()
}

fn default_triage_max_tokens() -> usize {
    1024
}

fn default_triage_batch_size() -> usize {
    5
}

fn default_triage_confidence_threshold() -> f64 {
    0.8
}

fn default_cost_per_input_token() -> f64 {
    0.00001
}

fn default_cost_per_output_token() -> f64 {
    0.00003
}

fn default_triage_cache_dir() -> PathBuf {
    PathBuf::from(".pledgerecon-cache/triage")
}

fn default_wasm_fuel() -> u64 {
    1_000_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ScanConfig::default();
        assert!(config.reachability);
        assert!(!config.triage);
        assert_eq!(config.min_severity, "low");
        assert_eq!(config.concurrency, 8);
    }

    #[test]
    fn test_ignore_rule_match() {
        let rule = IgnoreRule {
            package: Some("npm:lodash".to_string()),
            advisory_id: None,
            reason: "Reviewed and accepted".to_string(),
            expires: None,
        };
        assert!(rule.matches("npm:lodash", "CVE-2021-23337"));
        assert!(!rule.matches("npm:express", "CVE-2021-23337"));
    }

    #[test]
    fn test_ignore_rule_expired() {
        let rule = IgnoreRule {
            package: None,
            advisory_id: Some("CVE-2021-23337".to_string()),
            reason: "".to_string(),
            expires: Some("2020-01-01".to_string()),
        };
        assert!(rule.is_expired());
    }

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
min_severity = "medium"
reachability = true
fail_on_findings = true

[[ignore]]
package = "npm:lodash"
reason = "Accepted risk"
"#;
        let dir = std::env::temp_dir().join("pledgerecon_config_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pledgerecon.toml");
        std::fs::write(&path, toml).unwrap();

        let config = ScanConfig::from_file(&path).unwrap();
        assert_eq!(config.min_severity, "medium");
        assert!(config.fail_on_findings);
        assert_eq!(config.ignore.len(), 1);
        assert!(config.is_ignored("npm:lodash", "CVE-2021-23337"));
    }
}
