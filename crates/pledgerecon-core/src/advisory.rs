//! Advisory database — types and fetching from OSV, NVD, and GitHub Security Advisories.
//!
//! The advisory database is the source of truth for known vulnerabilities.
//! It is fetched from public APIs (OSV.dev, NVD NIST, GHSA) and cached locally
//! for offline use. Each advisory describes a vulnerability in a specific
//! package, with affected version ranges, severity, references, and optional
//! reachable-function metadata for AST-based reachability analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
#[allow(unused_imports)]
use std::collections::HashSet;
use thiserror::Error;

/// Stable identifier for an advisory (e.g. "GHSA-xxxx-xxxx-xxxx", "CVE-2024-12345", "OSV-2024-1").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AdvisoryId(pub String);

impl std::fmt::Display for AdvisoryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Severity levels aligned with CVSS v3.x.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdvisorySeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AdvisorySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdvisorySeverity::None => write!(f, "none"),
            AdvisorySeverity::Low => write!(f, "low"),
            AdvisorySeverity::Medium => write!(f, "medium"),
            AdvisorySeverity::High => write!(f, "high"),
            AdvisorySeverity::Critical => write!(f, "critical"),
        }
    }
}

impl AdvisorySeverity {
    /// Parse from a CVSS v3.x vector string or severity label.
    pub fn from_cvss(score: f64) -> Self {
        match score {
            s if s >= 9.0 => AdvisorySeverity::Critical,
            s if s >= 7.0 => AdvisorySeverity::High,
            s if s >= 4.0 => AdvisorySeverity::Medium,
            s if s > 0.0 => AdvisorySeverity::Low,
            _ => AdvisorySeverity::None,
        }
    }
}

/// An affected version range within an advisory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryRange {
    /// The ecosystem-specific package name (e.g. "npm:lodash", "crates.io:serde").
    pub package: String,
    /// Minimum affected version (inclusive), if specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introduced: Option<String>,
    /// Maximum affected version (exclusive), if specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    /// Last affected version (inclusive), if no fix exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_affected: Option<String>,
}

impl AdvisoryRange {
    /// Check if a given version string falls within this affected range.
    pub fn affects(&self, version: &str) -> bool {
        // Determine ecosystem from the package name prefix.
        let ecosystem = if let Some(pos) = self.package.find(':') {
            &self.package[..pos]
        } else {
            ""
        };

        crate::version::version_in_range(
            version,
            self.introduced.as_deref(),
            self.fixed.as_deref(),
            self.last_affected.as_deref(),
            ecosystem,
        )
    }
}

/// A reference URL (advisory page, patch, exploit, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryReference {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// A known vulnerability advisory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub id: AdvisoryId,
    pub summary: String,
    pub description: String,
    pub severity: AdvisorySeverity,
    /// CVSS v3.x score, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    /// Affected version ranges.
    pub ranges: Vec<AdvisoryRange>,
    /// References (advisory pages, patches, exploits).
    pub references: Vec<AdvisoryReference>,
    /// CWE IDs (e.g. "CWE-79").
    #[serde(default)]
    pub cwes: Vec<String>,
    /// Known vulnerable function names for AST reachability analysis.
    /// If present, the reachability analyzer checks if these functions are called.
    #[serde(default)]
    pub vulnerable_functions: Vec<String>,
    /// Publication date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<DateTime<Utc>>,
    /// Last modification date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<DateTime<Utc>>,
    /// Whether a fix is available.
    #[serde(default)]
    pub fix_available: bool,
    /// Aliases (e.g. CVE IDs that map to this advisory).
    #[serde(default)]
    pub aliases: Vec<String>,
}

impl Advisory {
    /// Check if this advisory affects a given package at a given version.
    pub fn affects_package(&self, package: &str, version: &str) -> bool {
        self.ranges
            .iter()
            .any(|r| r.package.eq_ignore_ascii_case(package) && r.affects(version))
    }

    /// Get the fixed version for a given package, if available.
    pub fn fix_version_for(&self, package: &str) -> Option<&str> {
        self.ranges
            .iter()
            .find(|r| r.package.eq_ignore_ascii_case(package))
            .and_then(|r| r.fixed.as_deref())
    }
}

/// Errors encountered when fetching or parsing advisory data.
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("JSON parsing failed: {0}")]
    Json(String),
    #[error("cache I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no advisories found for package: {0}")]
    NotFound(String),
}

/// The advisory database — a collection of advisories indexed by package name.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdvisoryDatabase {
    /// All advisories, keyed by advisory ID.
    pub advisories: HashMap<String, Advisory>,
    /// Index: package name → advisory IDs that affect it.
    #[serde(default)]
    pub package_index: HashMap<String, Vec<String>>,
    /// When the database was last updated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<DateTime<Utc>>,
}

impl AdvisoryDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an advisory to the database and update the package index.
    pub fn add(&mut self, advisory: Advisory) {
        for range in &advisory.ranges {
            self.package_index
                .entry(range.package.clone())
                .or_default()
                .push(advisory.id.0.clone());
        }
        self.advisories.insert(advisory.id.0.clone(), advisory);
    }

    /// Query advisories that affect a given package.
    pub fn for_package(&self, package: &str) -> Vec<&Advisory> {
        self.package_index
            .get(package)
            .into_iter()
            .flatten()
            .filter_map(|id| self.advisories.get(id))
            .collect()
    }

    /// Query advisories that affect a given package at a specific version.
    pub fn for_package_version(&self, package: &str, version: &str) -> Vec<&Advisory> {
        self.for_package(package)
            .into_iter()
            .filter(|a| a.affects_package(package, version))
            .collect()
    }

    /// Number of advisories in the database.
    pub fn len(&self) -> usize {
        self.advisories.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.advisories.is_empty()
    }

    /// Save the database to disk as JSON.
    pub fn save_to_disk(&self, path: &std::path::Path) -> Result<(), DatabaseError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json =
            serde_json::to_vec_pretty(self).map_err(|e| DatabaseError::Json(e.to_string()))?;
        std::fs::write(path, json)?;
        tracing::info!(
            "Advisory database saved: {} advisories",
            self.advisories.len()
        );
        Ok(())
    }

    /// Load the database from a JSON file on disk.
    pub fn load_from_disk(path: &std::path::Path) -> Result<Self, DatabaseError> {
        let data = std::fs::read(path)?;
        let db: AdvisoryDatabase =
            serde_json::from_slice(&data).map_err(|e| DatabaseError::Json(e.to_string()))?;
        tracing::info!(
            "Advisory database loaded: {} advisories",
            db.advisories.len()
        );
        Ok(db)
    }

    /// Save the database to disk with a checksum file for integrity validation.
    pub fn save_to_disk_with_checksum(&self, path: &std::path::Path) -> Result<(), DatabaseError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json =
            serde_json::to_vec_pretty(self).map_err(|e| DatabaseError::Json(e.to_string()))?;

        // Compute SHA-256 checksum.
        let mut hasher = Sha256::new();
        hasher.update(&json);
        let checksum = hasher.finalize();
        let checksum_hex = hex_encode(&checksum);

        // Write checksum file alongside the cache.
        let checksum_path = path.with_extension("json.sha256");
        std::fs::write(&checksum_path, &checksum_hex)?;

        std::fs::write(path, json)?;
        tracing::info!(
            "Advisory database saved with checksum: {} advisories",
            self.advisories.len()
        );
        Ok(())
    }

    /// Load the database from disk, verifying the checksum if present.
    pub fn load_from_disk_with_checksum(path: &std::path::Path) -> Result<Self, DatabaseError> {
        let data = std::fs::read(path)?;

        // Verify checksum if the checksum file exists.
        let checksum_path = path.with_extension("json.sha256");
        if checksum_path.exists() {
            let stored_checksum = std::fs::read_to_string(&checksum_path)?;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let computed = hasher.finalize();
            let computed_hex = hex_encode(&computed);
            if stored_checksum.trim() != computed_hex {
                return Err(DatabaseError::Json(format!(
                    "Cache checksum mismatch: expected {}, got {}",
                    stored_checksum.trim(),
                    computed_hex
                )));
            }
            tracing::debug!("Advisory cache checksum verified");
        }

        let db: AdvisoryDatabase =
            serde_json::from_slice(&data).map_err(|e| DatabaseError::Json(e.to_string()))?;
        tracing::info!(
            "Advisory database loaded: {} advisories",
            db.advisories.len()
        );
        Ok(db)
    }

    /// Check if the cache at the given path is still fresh based on TTL.
    /// Returns true if the cache is expired or doesn't exist.
    pub fn is_cache_expired(path: &std::path::Path, ttl_hours: u64) -> bool {
        if !path.exists() {
            return true;
        }
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return true,
        };
        let modified = match metadata.modified() {
            Ok(t) => t,
            Err(_) => return true,
        };
        let elapsed = std::time::SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        elapsed.as_secs() > ttl_hours * 3600
    }

    /// Merge advisories from another database into this one, deduplicating by
    /// advisory ID and CVE aliases. When two advisories share the same CVE ID,
    /// their ranges, references, and vulnerable functions are merged.
    pub fn merge_dedup(&mut self, other: AdvisoryDatabase) {
        for (id, advisory) in other.advisories {
            if let Some(existing) = self.advisories.get_mut(&id) {
                // Same ID — merge ranges, references, and vulnerable functions.
                existing.ranges.extend(advisory.ranges);
                existing.references.extend(advisory.references);
                existing
                    .vulnerable_functions
                    .extend(advisory.vulnerable_functions);
                existing.aliases.extend(advisory.aliases);
                // Deduplicate ranges and aliases.
                existing.ranges.dedup_by(|a, b| a.package == b.package);
                existing.aliases.dedup();
                existing.vulnerable_functions.dedup();
            } else {
                // Check if any alias matches an existing advisory, or if the
                // new advisory's ID matches an existing advisory's alias.
                let mut match_id: Option<String> = None;
                for alias in &advisory.aliases {
                    for (existing_id, existing) in &self.advisories {
                        if existing.aliases.contains(alias) || existing_id == alias {
                            match_id = Some(existing_id.clone());
                            break;
                        }
                    }
                    if match_id.is_some() {
                        break;
                    }
                }
                // Also check if the new advisory's ID is an alias of an existing one.
                if match_id.is_none() {
                    for (existing_id, existing) in &self.advisories {
                        if existing.aliases.contains(&id) {
                            match_id = Some(existing_id.clone());
                            break;
                        }
                    }
                }
                if let Some(existing_id) = match_id {
                    if let Some(existing_mut) = self.advisories.get_mut(&existing_id) {
                        existing_mut.ranges.extend(advisory.ranges.clone());
                        existing_mut.references.extend(advisory.references.clone());
                        existing_mut
                            .vulnerable_functions
                            .extend(advisory.vulnerable_functions.clone());
                        existing_mut.aliases.extend(advisory.aliases.clone());
                        existing_mut.ranges.dedup_by(|a, b| a.package == b.package);
                        existing_mut.aliases.dedup();
                        existing_mut.vulnerable_functions.dedup();
                    }
                } else {
                    // Update package index for the new advisory.
                    for range in &advisory.ranges {
                        self.package_index
                            .entry(range.package.clone())
                            .or_default()
                            .push(advisory.id.0.clone());
                    }
                    self.advisories.insert(id, advisory);
                }
            }
        }
    }

    /// Fetch advisories for a package from the OSV.dev API.
    pub fn fetch_osv(
        package: &str,
        version: &str,
        ecosystem: &str,
    ) -> Result<Vec<Advisory>, DatabaseError> {
        let url = "https://api.osv.dev/v1/query";
        let body = serde_json::json!({
            "package": {
                "name": package,
                "ecosystem": ecosystem,
            },
            "version": version,
        });

        let resp = ureq::post(url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| DatabaseError::Http(e.to_string()))?;

        let raw: serde_json::Value = resp
            .into_json()
            .map_err(|e| DatabaseError::Json(e.to_string()))?;

        let vulns: Vec<&serde_json::Value> = raw
            .get("vulns")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().collect())
            .unwrap_or_default();

        if vulns.is_empty() {
            return Ok(Vec::new());
        }

        let mut advisories = Vec::new();
        for vuln in &vulns {
            advisories.push(parse_osv_advisory(vuln));
        }
        Ok(advisories)
    }

    /// Fetch advisories for a GitHub advisory (GHSA) via the GitHub API.
    pub fn fetch_ghsa(
        package: &str,
        ecosystem: &str,
        token: Option<&str>,
    ) -> Result<Vec<Advisory>, DatabaseError> {
        let url = format!(
            "https://api.github.com/advisories?ecosystem={}&affects={}",
            ecosystem, package
        );

        let mut req = ureq::get(&url).set("Accept", "application/vnd.github+json");
        if let Some(t) = token {
            req = req.set("Authorization", &format!("Bearer {t}"));
        }

        let resp = req.call().map_err(|e| DatabaseError::Http(e.to_string()))?;

        let raw: Vec<serde_json::Value> = resp
            .into_json()
            .map_err(|e| DatabaseError::Json(e.to_string()))?;

        let mut advisories = Vec::new();
        for entry in raw.iter() {
            advisories.push(parse_ghsa_advisory(entry));
        }
        Ok(advisories)
    }

    /// Fetch advisories from the NVD API (services.nvd.nist.gov).
    ///
    /// Queries CVEs by keyword (package name). An API key is optional but
    /// recommended for higher rate limits (5 req/30s without key, 50 req/30s with).
    pub fn fetch_nvd(package: &str, api_key: Option<&str>) -> Result<Vec<Advisory>, DatabaseError> {
        let encoded_package = package
            .chars()
            .map(|c| match c {
                ' ' => "%20".to_string(),
                '&' => "%26".to_string(),
                '=' => "%3D".to_string(),
                '?' => "%3F".to_string(),
                _ => c.to_string(),
            })
            .collect::<String>();
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}",
            encoded_package
        );

        let mut req = ureq::get(&url).set("Accept", "application/json");
        if let Some(key) = api_key {
            req = req.set("apiKey", key);
        }

        let resp = req.call().map_err(|e| DatabaseError::Http(e.to_string()))?;

        let raw: serde_json::Value = resp
            .into_json()
            .map_err(|e| DatabaseError::Json(e.to_string()))?;

        let vulns: Vec<&serde_json::Value> = raw
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().collect())
            .unwrap_or_default();

        let mut advisories = Vec::new();
        for entry in vulns {
            if let Some(cve) = entry.get("cve") {
                advisories.push(parse_nvd_advisory(cve));
            }
        }
        Ok(advisories)
    }
}

/// Parse an OSV.dev vulnerability JSON object into an [`Advisory`].
fn parse_osv_advisory(v: &serde_json::Value) -> Advisory {
    let id = v
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("unknown")
        .to_string();

    let summary = v
        .get("summary")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();

    let description = v
        .get("details")
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_string();

    let aliases: Vec<String> = v
        .get("aliases")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let severity = v
        .get("severity")
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|s| s.get("score"))
        .and_then(|s| s.as_str())
        .and_then(|s| {
            // Parse CVSS vector string to extract base score
            if let Some(start) = s.find("CVSS:3.") {
                let _ = &s[start..];
            }
            // Try to extract a numeric score from the vector
            s.split('/')
                .find_map(|part| part.strip_prefix("AV:").map(String::from).or(None))
        })
        .and(None::<f64>)
        .unwrap_or(0.0);

    let cvss_score = v
        .get("severity")
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|s| s.get("score"))
        .and_then(|s| s.as_str())
        .and_then(|s| {
            // Try parsing as a numeric score directly
            s.parse::<f64>().ok()
        });

    let final_cvss = cvss_score.unwrap_or(severity);
    let adv_severity = AdvisorySeverity::from_cvss(final_cvss);

    let mut ranges = Vec::new();
    if let Some(affected) = v.get("affected").and_then(|a| a.as_array()) {
        for aff in affected {
            let pkg = aff
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let ecosystem = aff
                .get("package")
                .and_then(|p| p.get("ecosystem"))
                .and_then(|e| e.as_str())
                .unwrap_or("")
                .to_string();
            let full_pkg = if ecosystem.is_empty() {
                pkg.clone()
            } else {
                format!("{}:{}", ecosystem, pkg)
            };

            if let Some(ranges_arr) = aff.get("ranges").and_then(|r| r.as_array()) {
                for range in ranges_arr {
                    if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                        let mut introduced = None;
                        let mut fixed = None;
                        let mut last_affected = None;
                        for event in events {
                            if let Some(i) = event.get("introduced").and_then(|v| v.as_str()) {
                                introduced = Some(i.to_string());
                            }
                            if let Some(f) = event.get("fixed").and_then(|v| v.as_str()) {
                                fixed = Some(f.to_string());
                            }
                            if let Some(l) = event.get("last_affected").and_then(|v| v.as_str()) {
                                last_affected = Some(l.to_string());
                            }
                        }
                        ranges.push(AdvisoryRange {
                            package: full_pkg.clone(),
                            introduced,
                            fixed,
                            last_affected,
                        });
                    }
                }
            }
        }
    }

    let references: Vec<AdvisoryReference> = v
        .get("references")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let url = r.get("url").and_then(|u| u.as_str())?;
                    let kind = r.get("type").and_then(|t| t.as_str()).map(String::from);
                    Some(AdvisoryReference {
                        url: url.to_string(),
                        kind,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let vulnerable_functions: Vec<String> = v
        .get("affected")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
        .filter_map(|aff| {
            aff.get("ecosystem_specific")
                .and_then(|e| e.get("functions"))
                .and_then(|f| f.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|f| f.as_str().map(String::from))
                        .collect::<Vec<String>>()
                })
        })
        .flatten()
        .collect();

    let fix_available = ranges.iter().any(|r| r.fixed.is_some());

    Advisory {
        id: AdvisoryId(id),
        summary,
        description,
        severity: adv_severity,
        cvss_score: Some(final_cvss),
        ranges,
        references,
        cwes: Vec::new(),
        vulnerable_functions,
        published: None,
        modified: None,
        fix_available,
        aliases,
    }
}

/// Parse a GitHub Security Advisory JSON object into an [`Advisory`].
fn parse_ghsa_advisory(v: &serde_json::Value) -> Advisory {
    let ghsa_id = v
        .get("ghsa_id")
        .and_then(|i| i.as_str())
        .unwrap_or("unknown")
        .to_string();

    let summary = v
        .get("summary")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();

    let description = v
        .get("description")
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_string();

    let severity_str = v
        .get("severity")
        .and_then(|s| s.as_str())
        .unwrap_or("medium");

    let severity = match severity_str.to_lowercase().as_str() {
        "critical" => AdvisorySeverity::Critical,
        "high" => AdvisorySeverity::High,
        "medium" => AdvisorySeverity::Medium,
        "low" => AdvisorySeverity::Low,
        _ => AdvisorySeverity::None,
    };

    let cvss_score = v
        .get("cvss")
        .and_then(|c| c.get("score"))
        .and_then(|s| s.as_f64());

    let cve_id = v.get("cve_id").and_then(|c| c.as_str()).map(String::from);

    let aliases: Vec<String> = cve_id.into_iter().collect();

    let references: Vec<AdvisoryReference> = v
        .get("references")
        .and_then(|r| r.as_str())
        .map(|url| {
            vec![AdvisoryReference {
                url: url.to_string(),
                kind: Some("web".to_string()),
            }]
        })
        .unwrap_or_default();

    let mut ranges = Vec::new();
    if let Some(vulns) = v.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln in vulns {
            let pkg = vuln
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let ecosystem = vuln
                .get("package")
                .and_then(|p| p.get("ecosystem"))
                .and_then(|e| e.as_str())
                .unwrap_or("")
                .to_string();
            let full_pkg = if ecosystem.is_empty() {
                pkg
            } else {
                format!("{}:{}", ecosystem, pkg)
            };

            let vulnerable_range = vuln
                .get("vulnerable_version_range")
                .and_then(|r| r.as_str())
                .unwrap_or("*");

            let patched = vuln
                .get("patched_versions")
                .and_then(|p| p.as_str())
                .map(String::from);

            ranges.push(AdvisoryRange {
                package: full_pkg,
                introduced: Some(vulnerable_range.to_string()),
                fixed: patched,
                last_affected: None,
            });
        }
    }

    let fix_available = ranges.iter().any(|r| r.fixed.is_some());

    Advisory {
        id: AdvisoryId(ghsa_id),
        summary,
        description,
        severity,
        cvss_score,
        ranges,
        references,
        cwes: Vec::new(),
        vulnerable_functions: Vec::new(),
        published: None,
        modified: None,
        fix_available,
        aliases,
    }
}

/// Parse an NVD CVE JSON object into an [`Advisory`].
///
/// NVD 2.0 API CVE format:
/// ```json
/// {
///   "id": "CVE-2024-12345",
///   "descriptions": [{"lang": "en", "value": "..."}],
///   "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/..."}}],
///   "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
///   "configs": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:pkg:*:*:*:*:*:*:*:*", "versionStartIncluding": "1.0.0", "versionEndExcluding": "2.0.0"}]}]}],
///   "references": [{"url": "https://...", "tags": ["Patch"]}]
/// }
/// ```
fn parse_nvd_advisory(cve: &serde_json::Value) -> Advisory {
    let cve_id = cve
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Extract English description.
    let description = cve
        .get("descriptions")
        .and_then(|d| d.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
                .and_then(|d| d.get("value"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("")
        .to_string();

    // Extract CVSS v3.x score and severity.
    let (cvss_score, severity_str) = cve
        .get("metrics")
        .and_then(|m| m.get("cvssMetricV31"))
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|metric| {
            let cvss_data = metric.get("cvssData")?;
            let score = cvss_data.get("baseScore").and_then(|s| s.as_f64());
            let severity = cvss_data
                .get("baseSeverity")
                .and_then(|s| s.as_str())
                .or_else(|| metric.get("baseSeverity").and_then(|s| s.as_str()));
            Some((score, severity))
        })
        .unwrap_or((None, None));

    let severity = match severity_str.map(|s| s.to_uppercase()).as_deref() {
        Some("CRITICAL") => AdvisorySeverity::Critical,
        Some("HIGH") => AdvisorySeverity::High,
        Some("MEDIUM") => AdvisorySeverity::Medium,
        Some("LOW") => AdvisorySeverity::Low,
        _ => cvss_score
            .map(AdvisorySeverity::from_cvss)
            .unwrap_or(AdvisorySeverity::None),
    };

    // Extract CWEs.
    let cwes: Vec<String> = cve
        .get("weaknesses")
        .and_then(|w| w.as_array())
        .into_iter()
        .flatten()
        .filter_map(|w| {
            w.get("description")
                .and_then(|d| d.as_array())
                .and_then(|arr| arr.first())
                .and_then(|d| d.get("value"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect();

    // Extract references.
    let references: Vec<AdvisoryReference> = cve
        .get("references")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let url = r.get("url").and_then(|u| u.as_str())?;
                    let kind = r
                        .get("tags")
                        .and_then(|t| t.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|t| t.as_str())
                        .map(String::from);
                    Some(AdvisoryReference {
                        url: url.to_string(),
                        kind,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Extract affected version ranges from configurations.
    let mut ranges = Vec::new();
    if let Some(configs) = cve.get("configs").and_then(|c| c.as_array()) {
        for config in configs {
            if let Some(nodes) = config.get("nodes").and_then(|n| n.as_array()) {
                for node in nodes {
                    if let Some(cpe_matches) = node.get("cpeMatch").and_then(|c| c.as_array()) {
                        for cpe in cpe_matches {
                            let criteria =
                                cpe.get("criteria").and_then(|c| c.as_str()).unwrap_or("");
                            // Parse CPE match string: cpe:2.3:a:vendor:package:version:...
                            let parts: Vec<&str> = criteria.split(':').collect();
                            if parts.len() < 6 {
                                continue;
                            }
                            let vendor = parts[3];
                            let pkg = parts[4];
                            let full_pkg = format!("{}:{}", vendor, pkg);

                            let introduced = cpe
                                .get("versionStartIncluding")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            let fixed = cpe
                                .get("versionEndExcluding")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            let last_affected = cpe
                                .get("versionEndIncluding")
                                .and_then(|v| v.as_str())
                                .map(String::from);

                            ranges.push(AdvisoryRange {
                                package: full_pkg,
                                introduced,
                                fixed,
                                last_affected,
                            });
                        }
                    }
                }
            }
        }
    }

    let fix_available = ranges.iter().any(|r| r.fixed.is_some());

    Advisory {
        id: AdvisoryId(cve_id.clone()),
        summary: description.chars().take(200).collect(),
        description,
        severity,
        cvss_score,
        ranges,
        references,
        cwes,
        vulnerable_functions: Vec::new(),
        published: None,
        modified: None,
        fix_available,
        aliases: Vec::new(),
    }
}

/// Encode a byte slice as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push_str(&format!("{:02x}", byte));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advisory_range_affects() {
        let range = AdvisoryRange {
            package: "npm:lodash".to_string(),
            introduced: Some("4.0.0".to_string()),
            fixed: Some("4.17.21".to_string()),
            last_affected: None,
        };

        assert!(range.affects("4.17.11"));
        assert!(range.affects("4.0.0"));
        assert!(!range.affects("4.17.21"));
        assert!(!range.affects("3.9.0"));
    }

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(AdvisorySeverity::from_cvss(9.5), AdvisorySeverity::Critical);
        assert_eq!(AdvisorySeverity::from_cvss(7.5), AdvisorySeverity::High);
        assert_eq!(AdvisorySeverity::from_cvss(5.0), AdvisorySeverity::Medium);
        assert_eq!(AdvisorySeverity::from_cvss(2.0), AdvisorySeverity::Low);
        assert_eq!(AdvisorySeverity::from_cvss(0.0), AdvisorySeverity::None);
    }

    #[test]
    fn test_database_add_and_query() {
        let mut db = AdvisoryDatabase::new();
        let advisory = Advisory {
            id: AdvisoryId("CVE-2021-23337".to_string()),
            summary: "Command injection in lodash".to_string(),
            description: "test".to_string(),
            severity: AdvisorySeverity::High,
            cvss_score: Some(7.2),
            ranges: vec![AdvisoryRange {
                package: "npm:lodash".to_string(),
                introduced: Some("4.0.0".to_string()),
                fixed: Some("4.17.21".to_string()),
                last_affected: None,
            }],
            references: vec![],
            cwes: vec![],
            vulnerable_functions: vec!["template".to_string()],
            published: None,
            modified: None,
            fix_available: true,
            aliases: vec![],
        };
        db.add(advisory);

        let results = db.for_package("npm:lodash");
        assert_eq!(results.len(), 1);

        let affected = db.for_package_version("npm:lodash", "4.17.11");
        assert_eq!(affected.len(), 1);

        let not_affected = db.for_package_version("npm:lodash", "4.17.21");
        assert_eq!(not_affected.len(), 0);
    }

    #[test]
    fn test_database_save_load() {
        let mut db = AdvisoryDatabase::new();
        db.add(Advisory {
            id: AdvisoryId("TEST-001".to_string()),
            summary: "Test".to_string(),
            description: "Test advisory".to_string(),
            severity: AdvisorySeverity::Medium,
            cvss_score: Some(5.0),
            ranges: vec![AdvisoryRange {
                package: "crates.io:serde".to_string(),
                introduced: Some("1.0.0".to_string()),
                fixed: None,
                last_affected: None,
            }],
            references: vec![],
            cwes: vec![],
            vulnerable_functions: vec![],
            published: None,
            modified: None,
            fix_available: false,
            aliases: vec![],
        });

        let dir = std::env::temp_dir().join("pledgerecon_db_test");
        let path = dir.join("advisories.json");
        db.save_to_disk(&path).unwrap();
        let loaded = AdvisoryDatabase::load_from_disk(&path).unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn test_cache_checksum_save_load() {
        let mut db = AdvisoryDatabase::new();
        db.add(Advisory {
            id: AdvisoryId("CVE-2024-9999".to_string()),
            summary: "Test".to_string(),
            description: "Checksum test".to_string(),
            severity: AdvisorySeverity::High,
            cvss_score: Some(7.5),
            ranges: vec![AdvisoryRange {
                package: "npm:express".to_string(),
                introduced: Some("4.0.0".to_string()),
                fixed: Some("4.18.0".to_string()),
                last_affected: None,
            }],
            references: vec![],
            cwes: vec![],
            vulnerable_functions: vec![],
            published: None,
            modified: None,
            fix_available: true,
            aliases: vec![],
        });

        let dir = std::env::temp_dir().join("pledgerecon_checksum_test");
        let path = dir.join("advisories.json");
        db.save_to_disk_with_checksum(&path).unwrap();

        // Checksum file should exist.
        let checksum_path = path.with_extension("json.sha256");
        assert!(checksum_path.exists());

        // Load with checksum verification should succeed.
        let loaded = AdvisoryDatabase::load_from_disk_with_checksum(&path).unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn test_cache_checksum_tamper_detection() {
        let mut db = AdvisoryDatabase::new();
        db.add(Advisory {
            id: AdvisoryId("CVE-2024-8888".to_string()),
            summary: "Tamper test".to_string(),
            description: "Tamper detection".to_string(),
            severity: AdvisorySeverity::Medium,
            cvss_score: Some(5.0),
            ranges: vec![AdvisoryRange {
                package: "crates.io:tokio".to_string(),
                introduced: Some("1.0.0".to_string()),
                fixed: None,
                last_affected: None,
            }],
            references: vec![],
            cwes: vec![],
            vulnerable_functions: vec![],
            published: None,
            modified: None,
            fix_available: false,
            aliases: vec![],
        });

        let dir = std::env::temp_dir().join("pledgerecon_tamper_test");
        let path = dir.join("advisories.json");
        db.save_to_disk_with_checksum(&path).unwrap();

        // Tamper with the cache file.
        std::fs::write(&path, b"tampered data").unwrap();

        // Load should fail due to checksum mismatch.
        let result = AdvisoryDatabase::load_from_disk_with_checksum(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_cache_ttl_expired() {
        let dir = std::env::temp_dir().join("pledgerecon_ttl_test");
        let path = dir.join("advisories.json");
        std::fs::create_dir_all(&dir).ok();
        std::fs::write(&path, b"{}").ok();

        // Set file modification time to 2 hours ago.
        let two_hours_ago = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(7201))
            .unwrap();
        let _ = std::fs::File::open(&path).and_then(|f| f.set_modified(two_hours_ago));

        // Re-read metadata to check if set_modified succeeded.
        let metadata = std::fs::metadata(&path).unwrap();
        let modified = metadata.modified().unwrap();
        let elapsed = std::time::SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();

        if elapsed.as_secs() > 3600 {
            // File is old enough — TTL of 1 hour should be expired.
            assert!(AdvisoryDatabase::is_cache_expired(&path, 1));
        }

        // Non-existent path should always be "expired".
        let fake_path = dir.join("nonexistent.json");
        assert!(AdvisoryDatabase::is_cache_expired(&fake_path, 9999));
    }

    #[test]
    fn test_dedup_merge_by_alias() {
        let mut db1 = AdvisoryDatabase::new();
        db1.add(Advisory {
            id: AdvisoryId("GHSA-aaaa-aaaa-aaaa".to_string()),
            summary: "GHSA advisory".to_string(),
            description: "Test GHSA".to_string(),
            severity: AdvisorySeverity::High,
            cvss_score: Some(7.5),
            ranges: vec![AdvisoryRange {
                package: "npm:lodash".to_string(),
                introduced: Some("4.0.0".to_string()),
                fixed: Some("4.17.21".to_string()),
                last_affected: None,
            }],
            references: vec![],
            cwes: vec![],
            vulnerable_functions: vec!["template".to_string()],
            published: None,
            modified: None,
            fix_available: true,
            aliases: vec!["CVE-2021-23337".to_string()],
        });

        let mut db2 = AdvisoryDatabase::new();
        db2.add(Advisory {
            id: AdvisoryId("CVE-2021-23337".to_string()),
            summary: "NVD advisory".to_string(),
            description: "Test NVD".to_string(),
            severity: AdvisorySeverity::High,
            cvss_score: Some(7.2),
            ranges: vec![AdvisoryRange {
                package: "npm:lodash".to_string(),
                introduced: Some("4.0.0".to_string()),
                fixed: None,
                last_affected: None,
            }],
            references: vec![AdvisoryReference {
                url: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337".to_string(),
                kind: Some("web".to_string()),
            }],
            cwes: vec!["CWE-78".to_string()],
            vulnerable_functions: vec![],
            published: None,
            modified: None,
            fix_available: false,
            aliases: vec![],
        });

        // Merge db2 into db1 — should dedup by CVE alias.
        db1.merge_dedup(db2);

        // Should still have only 1 advisory (merged by alias).
        assert_eq!(db1.len(), 1);

        // The merged advisory should have the vulnerable function from GHSA.
        let advisory = db1.for_package("npm:lodash").pop().unwrap();
        // Should have the vulnerable function from GHSA.
        assert!(
            advisory
                .vulnerable_functions
                .contains(&"template".to_string())
        );
        // Should have references from NVD.
        assert_eq!(advisory.references.len(), 1);
    }

    #[test]
    fn test_parse_nvd_advisory() {
        let cve_json = serde_json::json!({
            "id": "CVE-2024-12345",
            "descriptions": [
                {"lang": "en", "value": "A critical vulnerability in test package."}
            ],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                }]
            },
            "weaknesses": [{
                "description": [{"lang": "en", "value": "CWE-78"}]
            }],
            "configs": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:test_vendor:test_pkg:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "1.0.0",
                        "versionEndExcluding": "2.0.0"
                    }]
                }]
            }],
            "references": [
                {"url": "https://example.com/patch", "tags": ["Patch"]}
            ]
        });

        let advisory = parse_nvd_advisory(&cve_json);

        assert_eq!(advisory.id.0, "CVE-2024-12345");
        assert_eq!(advisory.severity, AdvisorySeverity::Critical);
        assert_eq!(advisory.cvss_score, Some(9.8));
        assert_eq!(advisory.ranges.len(), 1);
        assert_eq!(advisory.ranges[0].package, "test_vendor:test_pkg");
        assert_eq!(advisory.ranges[0].introduced.as_deref(), Some("1.0.0"));
        assert_eq!(advisory.ranges[0].fixed.as_deref(), Some("2.0.0"));
        assert!(advisory.cwes.contains(&"CWE-78".to_string()));
        assert!(advisory.fix_available);
        assert_eq!(advisory.references.len(), 1);
    }
}
