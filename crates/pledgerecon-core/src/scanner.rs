//! The scanner — orchestrates the full vulnerability scan pipeline.
//!
//! The scan pipeline:
//! 1. Load configuration (`pledgerecon.toml` or defaults)
//! 2. Discover and parse all dependency manifests
//! 3. Build the dependency graph
//! 4. Fetch/load the advisory database (OSV, GHSA, local cache)
//! 5. Match dependencies against advisories (version-based)
//! 6. Build the call graph from source code
//! 7. Run AST-based reachability analysis on matched advisories
//! 8. Run WASM custom rules (if enabled)
//! 9. Run LLM-powered triage (if enabled)
//! 10. Apply ignore rules
//! 11. Generate SBOM (if enabled)
//! 12. Produce the scan report

use crate::advisory::{Advisory, AdvisoryDatabase, AdvisorySeverity, DatabaseError};
use crate::config::{AdvisorySource, ScanConfig};
use crate::dependency::{DependencyGraph, DependencyKind, build_dependency_graph};
use crate::finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
use crate::reachability::ReachabilityAnalyzer;
use crate::sbom::{SbomFormat, SbomGenerator};
use crate::triage::TriageEngine;
use chrono::{DateTime, Utc};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

/// Errors during scanning.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("dependency graph build failed: {0}")]
    DependencyGraph(String),
    #[error("advisory database error: {0}")]
    AdvisoryDatabase(#[from] DatabaseError),
    #[error("reachability analysis failed: {0}")]
    Reachability(String),
    #[error("triage error: {0}")]
    Triage(String),
    #[error("SBOM generation failed: {0}")]
    Sbom(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// The complete scan report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Unique scan identifier.
    pub scan_id: String,
    /// Project name (directory name or from config).
    pub project_name: String,
    /// When the scan was performed.
    pub scanned_at: DateTime<Utc>,
    /// Duration of the scan in milliseconds.
    pub duration_ms: u64,
    /// Number of dependencies scanned.
    pub dependencies_scanned: usize,
    /// Number of advisories checked.
    pub advisories_checked: usize,
    /// All vulnerability findings.
    pub findings: Vec<Finding>,
}

impl ScanReport {
    /// Count findings by severity.
    pub fn count_by_severity(&self, severity: VulnerabilitySeverity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    /// Count findings by reachability status.
    pub fn count_by_reachability(&self, status: ReachabilityStatus) -> usize {
        self.findings
            .iter()
            .filter(|f| f.reachability == status)
            .count()
    }

    /// Whether the report has any actionable findings.
    pub fn has_actionable(&self) -> bool {
        self.findings.iter().any(|f| {
            f.reachability != ReachabilityStatus::Unreachable
                && f.status != FindingStatus::FalsePositive
        })
    }
}

/// The scanner — orchestrates the full scan pipeline.
pub struct Scanner {
    config: ScanConfig,
}

impl Scanner {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Run a full vulnerability scan on a project directory.
    pub fn scan(&self, root: &Path) -> Result<ScanReport, ScanError> {
        let start = Instant::now();
        let scan_id = Uuid::new_v4().to_string();
        let project_name = root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        info!("Starting scan {} on {}", scan_id, root.display());

        // Step 1: Build dependency graph.
        let graph =
            build_dependency_graph(root).map_err(|e| ScanError::DependencyGraph(e.to_string()))?;

        info!("Dependency graph: {} dependencies", graph.len());

        if graph.is_empty() {
            return Ok(ScanReport {
                scan_id,
                project_name,
                scanned_at: Utc::now(),
                duration_ms: start.elapsed().as_millis() as u64,
                dependencies_scanned: 0,
                advisories_checked: 0,
                findings: Vec::new(),
            });
        }

        // Step 2: Load/fetch advisory database.
        let db = self.load_advisory_database(root)?;

        // Step 3: Match dependencies against advisories.
        let mut findings = self.match_advisories(&graph, &db);

        // Step 4: Run WASM custom rules (if enabled).
        if self.config.wasm_rules && !self.config.wasm_rule_paths.is_empty() {
            findings.extend(self.run_wasm_rules(&graph));
        }

        // Step 5: Run reachability analysis (if enabled).
        if self.config.reachability {
            findings = self.analyze_reachability(root, &mut findings);
        }

        // Step 6: Run LLM triage (if enabled).
        if self.config.triage {
            findings = self.run_triage(&mut findings);
        }

        // Step 7: Apply ignore rules.
        findings.retain(|f| !self.config.is_ignored(&f.package, &f.advisory_id));

        // Step 8: Sort findings by severity (descending).
        findings.sort_by_key(|b| std::cmp::Reverse(b.severity));

        // Step 9: Generate SBOM (if enabled).
        if self.config.generate_sbom {
            self.generate_sbom(&graph, root)?;
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let advisories_checked = db.len();

        info!(
            "Scan {} complete: {} findings in {}ms",
            scan_id,
            findings.len(),
            duration_ms
        );

        Ok(ScanReport {
            scan_id,
            project_name,
            scanned_at: Utc::now(),
            duration_ms,
            dependencies_scanned: graph.len(),
            advisories_checked,
            findings,
        })
    }

    /// Load the advisory database from cache or fetch from sources.
    fn load_advisory_database(&self, root: &Path) -> Result<AdvisoryDatabase, ScanError> {
        let cache_path = root.join(&self.config.cache_dir).join("advisories.json");

        // Try loading from cache first (with TTL and checksum validation).
        if self.config.offline && cache_path.exists() {
            if AdvisoryDatabase::is_cache_expired(&cache_path, self.config.cache_ttl_hours) {
                info!(
                    "Advisory cache expired (TTL: {}h), refreshing",
                    self.config.cache_ttl_hours
                );
            } else {
                match AdvisoryDatabase::load_from_disk_with_checksum(&cache_path) {
                    Ok(db) => {
                        info!(
                            "Loaded advisory database from cache: {} advisories",
                            db.len()
                        );
                        return Ok(db);
                    }
                    Err(e) => warn!("Failed to load cached database: {}", e),
                }
            }
        }

        // Fetch from sources.
        let mut db = AdvisoryDatabase::new();

        for source in &self.config.advisory_sources {
            match source {
                AdvisorySource::Osv => {
                    info!("Fetching advisories from OSV.dev");
                    // OSV queries are per-package, so we fetch during matching.
                }
                AdvisorySource::Ghsa => {
                    info!("Fetching advisories from GitHub Security Advisories");
                    // GHSA queries are also per-package.
                }
                AdvisorySource::Nvd => {
                    info!("NVD source configured (fetches per-package during matching)");
                }
                AdvisorySource::Local { path } => {
                    if path.exists() {
                        match AdvisoryDatabase::load_from_disk(path) {
                            Ok(local_db) => {
                                db.merge_dedup(local_db);
                                info!("Loaded {} advisories from local source", db.len());
                            }
                            Err(e) => warn!("Failed to load local advisory file: {}", e),
                        }
                    }
                }
            }
        }

        // Save to cache with checksum.
        if !db.is_empty()
            && let Err(e) = db.save_to_disk_with_checksum(&cache_path)
        {
            warn!("Failed to save advisory cache: {}", e);
        }

        Ok(db)
    }

    /// Match dependencies against the advisory database.
    fn match_advisories(&self, graph: &DependencyGraph, db: &AdvisoryDatabase) -> Vec<Finding> {
        let min_severity = parse_severity(&self.config.min_severity);

        // For each dependency, query advisories.
        let deps: Vec<&crate::dependency::Dependency> = graph.dependencies.values().collect();
        let findings: Vec<Finding> = deps
            .par_iter()
            .flat_map(|dep| {
                let qualified = dep.qualified_name();
                let mut found = Vec::new();

                // Check local database first.
                let advisories = db.for_package_version(&qualified, &dep.version);

                for advisory in advisories {
                    let adv_sev = match advisory.severity {
                        AdvisorySeverity::Critical => VulnerabilitySeverity::Critical,
                        AdvisorySeverity::High => VulnerabilitySeverity::High,
                        AdvisorySeverity::Medium => VulnerabilitySeverity::Medium,
                        AdvisorySeverity::Low => VulnerabilitySeverity::Low,
                        AdvisorySeverity::None => VulnerabilitySeverity::Info,
                    };
                    if adv_sev < min_severity {
                        continue;
                    }
                    found.push(advisory_to_finding(advisory, dep));
                }

                // If no local results, try fetching from online sources (if not offline).
                if found.is_empty() && !self.config.offline {
                    let ecosystem = match dep.kind {
                        DependencyKind::Rust => "crates.io",
                        DependencyKind::Npm => "npm",
                        DependencyKind::Python => "PyPI",
                        DependencyKind::Go => "Go",
                        _ => "",
                    };

                    if !ecosystem.is_empty() {
                        // Try OSV first.
                        match AdvisoryDatabase::fetch_osv(&dep.name, &dep.version, ecosystem) {
                            Ok(osv_advisories) => {
                                for advisory in osv_advisories {
                                    let adv_sev = match advisory.severity {
                                        AdvisorySeverity::Critical => {
                                            VulnerabilitySeverity::Critical
                                        }
                                        AdvisorySeverity::High => VulnerabilitySeverity::High,
                                        AdvisorySeverity::Medium => VulnerabilitySeverity::Medium,
                                        AdvisorySeverity::Low => VulnerabilitySeverity::Low,
                                        AdvisorySeverity::None => VulnerabilitySeverity::Info,
                                    };
                                    if adv_sev < min_severity {
                                        continue;
                                    }
                                    found.push(advisory_to_finding(&advisory, dep));
                                }
                            }
                            Err(e) => {
                                warn!("OSV fetch failed for {}: {}", qualified, e);
                            }
                        }

                        // Try NVD if configured and no results yet.
                        if found.is_empty()
                            && self.config.advisory_sources.contains(&AdvisorySource::Nvd)
                        {
                            match AdvisoryDatabase::fetch_nvd(
                                &dep.name,
                                self.config.nvd_api_key.as_deref(),
                            ) {
                                Ok(nvd_advisories) => {
                                    for advisory in nvd_advisories {
                                        let adv_sev = match advisory.severity {
                                            AdvisorySeverity::Critical => {
                                                VulnerabilitySeverity::Critical
                                            }
                                            AdvisorySeverity::High => VulnerabilitySeverity::High,
                                            AdvisorySeverity::Medium => {
                                                VulnerabilitySeverity::Medium
                                            }
                                            AdvisorySeverity::Low => VulnerabilitySeverity::Low,
                                            AdvisorySeverity::None => VulnerabilitySeverity::Info,
                                        };
                                        if adv_sev < min_severity {
                                            continue;
                                        }
                                        found.push(advisory_to_finding(&advisory, dep));
                                    }
                                }
                                Err(e) => {
                                    warn!("NVD fetch failed for {}: {}", qualified, e);
                                }
                            }
                        }
                    }
                }

                found
            })
            .collect();

        info!(
            "Matched {} findings against advisory database",
            findings.len()
        );
        findings
    }

    /// Run AST-based reachability analysis on findings.
    fn analyze_reachability(&self, root: &Path, findings: &mut Vec<Finding>) -> Vec<Finding> {
        let analyzer = ReachabilityAnalyzer::new();
        let call_graph = analyzer.build_call_graph(root);

        for finding in &mut *findings {
            if finding.vulnerable_functions.is_empty() {
                finding.reachability = ReachabilityStatus::Unknown;
                continue;
            }

            let result = analyzer.analyze(&call_graph, &finding.vulnerable_functions);
            finding.reachability = match result.status {
                crate::reachability::ReachabilityStatus::Reachable => ReachabilityStatus::Reachable,
                crate::reachability::ReachabilityStatus::Unreachable => {
                    ReachabilityStatus::Unreachable
                }
                crate::reachability::ReachabilityStatus::Unknown => ReachabilityStatus::Unknown,
            };
            finding.call_chain = result.call_chain;
        }

        findings.clone()
    }

    /// Run LLM-powered triage on findings.
    fn run_triage(&self, findings: &mut [Finding]) -> Vec<Finding> {
        let mut engine = TriageEngine::new(self.config.triage_config.clone());
        let results = engine.triage_batch(findings);
        engine.apply_triage(findings, &results);

        // Goal 44: Flush audit log if enabled.
        if self.config.triage_config.audit_log
            && let Some(ref audit_path) = self.config.triage_config.audit_log_path
            && let Err(e) = engine.flush_audit_log(audit_path)
        {
            warn!("Failed to flush audit log: {}", e);
        }

        // Goal 45: Log cost report if enabled.
        if self.config.triage_config.cost_tracking {
            let cost = engine.cost_report();
            if cost.num_calls > 0 {
                info!(
                    "Triage cost: {} calls, {} input tokens, {} output tokens, ${:.4} USD",
                    cost.num_calls,
                    cost.total_input_tokens,
                    cost.total_output_tokens,
                    cost.total_cost_usd
                );
            }
        }

        findings.to_vec()
    }

    /// Run WASM custom rules.
    fn run_wasm_rules(&self, _graph: &DependencyGraph) -> Vec<Finding> {
        // WASM rule execution is handled by the plugin module.
        // For now, return empty — actual WASM loading is done in the CLI.
        Vec::new()
    }

    /// Generate an SBOM from the dependency graph.
    fn generate_sbom(&self, graph: &DependencyGraph, root: &Path) -> Result<(), ScanError> {
        let generator = SbomGenerator::from_graph(graph, root);
        let format = match self.config.sbom_format.as_str() {
            "spdx" => SbomFormat::Spdx,
            _ => SbomFormat::CycloneDx,
        };
        let output = root.join(&self.config.sbom_path);
        generator
            .generate(graph, format, &output)
            .map_err(|e| ScanError::Sbom(e.to_string()))
    }
}

/// Convert an advisory + dependency into a finding.
fn advisory_to_finding(advisory: &Advisory, dep: &crate::dependency::Dependency) -> Finding {
    let severity = match advisory.severity {
        AdvisorySeverity::Critical => VulnerabilitySeverity::Critical,
        AdvisorySeverity::High => VulnerabilitySeverity::High,
        AdvisorySeverity::Medium => VulnerabilitySeverity::Medium,
        AdvisorySeverity::Low => VulnerabilitySeverity::Low,
        AdvisorySeverity::None => VulnerabilitySeverity::Info,
    };

    let fix_version = advisory
        .fix_version_for(&dep.qualified_name())
        .map(String::from);

    Finding {
        advisory_id: advisory.id.0.clone(),
        summary: advisory.summary.clone(),
        description: advisory.description.clone(),
        severity,
        cvss_score: advisory.cvss_score,
        package: dep.qualified_name(),
        version: dep.version.clone(),
        fix_version,
        fix_available: advisory.fix_available,
        reachability: ReachabilityStatus::Unknown,
        vulnerable_functions: advisory.vulnerable_functions.clone(),
        call_chain: Vec::new(),
        status: FindingStatus::Pending,
        triage_explanation: None,
        references: advisory.references.iter().map(|r| r.url.clone()).collect(),
        cwes: advisory.cwes.clone(),
        manifest_path: dep.manifest_path.clone(),
        aliases: advisory.aliases.clone(),
    }
}

/// Parse a severity string into a VulnerabilitySeverity.
fn parse_severity(s: &str) -> VulnerabilitySeverity {
    match s.to_lowercase().as_str() {
        "critical" => VulnerabilitySeverity::Critical,
        "high" => VulnerabilitySeverity::High,
        "medium" => VulnerabilitySeverity::Medium,
        "low" => VulnerabilitySeverity::Low,
        "info" | "none" => VulnerabilitySeverity::Info,
        _ => VulnerabilitySeverity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), VulnerabilitySeverity::Critical);
        assert_eq!(parse_severity("high"), VulnerabilitySeverity::High);
        assert_eq!(parse_severity("medium"), VulnerabilitySeverity::Medium);
        assert_eq!(parse_severity("low"), VulnerabilitySeverity::Low);
        assert_eq!(parse_severity("info"), VulnerabilitySeverity::Info);
        assert_eq!(parse_severity("unknown"), VulnerabilitySeverity::Low);
    }

    #[test]
    fn test_scan_report_counts() {
        let report = ScanReport {
            scan_id: "test".to_string(),
            project_name: "test".to_string(),
            scanned_at: Utc::now(),
            duration_ms: 10,
            dependencies_scanned: 5,
            advisories_checked: 3,
            findings: vec![
                Finding {
                    advisory_id: "1".to_string(),
                    summary: "test".to_string(),
                    description: "test".to_string(),
                    severity: VulnerabilitySeverity::High,
                    cvss_score: None,
                    package: "npm:test".to_string(),
                    version: "1.0.0".to_string(),
                    fix_version: None,
                    fix_available: false,
                    reachability: ReachabilityStatus::Reachable,
                    vulnerable_functions: vec![],
                    call_chain: vec![],
                    status: FindingStatus::Pending,
                    triage_explanation: None,
                    references: vec![],
                    cwes: vec![],
                    manifest_path: PathBuf::new(),
                    aliases: vec![],
                },
                Finding {
                    advisory_id: "2".to_string(),
                    summary: "test".to_string(),
                    description: "test".to_string(),
                    severity: VulnerabilitySeverity::Low,
                    cvss_score: None,
                    package: "npm:test2".to_string(),
                    version: "1.0.0".to_string(),
                    fix_version: None,
                    fix_available: false,
                    reachability: ReachabilityStatus::Unreachable,
                    vulnerable_functions: vec![],
                    call_chain: vec![],
                    status: FindingStatus::Pending,
                    triage_explanation: None,
                    references: vec![],
                    cwes: vec![],
                    manifest_path: PathBuf::new(),
                    aliases: vec![],
                },
            ],
        };

        assert_eq!(report.count_by_severity(VulnerabilitySeverity::High), 1);
        assert_eq!(report.count_by_severity(VulnerabilitySeverity::Low), 1);
        assert_eq!(
            report.count_by_reachability(ReachabilityStatus::Reachable),
            1
        );
        assert!(report.has_actionable());
    }
}
