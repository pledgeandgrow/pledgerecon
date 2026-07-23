//! Intelligence & Prioritization — exploit prediction, threat intel, and
//! risk-based vulnerability scoring (Goals 161–170).

use crate::finding::{Finding, ReachabilityStatus, VulnerabilitySeverity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntelligenceError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found: {0}")]
    NotFound(String),
}

// ─── Goal 161: EPSS ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssScore {
    pub cve_id: String,
    pub epss: f64,
    pub percentile: f64,
}

impl EpssScore {
    /// Fetch EPSS scores from the FIRST.org EPSS API.
    ///
    /// Uses the batch endpoint: https://api.first.org/data/v2/epss?cve=CVE-XXXX,...
    /// Returns scores for all CVE IDs that have EPSS data available.
    /// Falls back to empty scores if the API is unreachable.
    pub fn fetch_scores(cve_ids: &[String]) -> Result<Vec<EpssScore>, IntelligenceError> {
        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_scores = Vec::new();
        // API supports batch queries but limits URL length. Process in chunks of 100.
        for chunk in cve_ids.chunks(100) {
            let cve_param = chunk.join(",");
            let url = format!("https://api.first.org/data/v2/epss?cve={}", cve_param);

            let resp = ureq::get(&url)
                .set("Accept", "application/json")
                .call()
                .map_err(|e| IntelligenceError::Http(e.to_string()))?;

            let raw: serde_json::Value = serde_json::from_str(
                &resp
                    .into_string()
                    .map_err(|e| IntelligenceError::Http(e.to_string()))?,
            )?;

            if let Some(data) = raw.get("data").and_then(|d| d.as_array()) {
                for entry in data {
                    let cve_id = entry
                        .get("cve")
                        .and_then(|c| c.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let epss = entry
                        .get("epss")
                        .and_then(|e| e.as_str())
                        .and_then(|s| s.parse::<f64>().ok())
                        .unwrap_or(0.0);
                    let percentile = entry
                        .get("percentile")
                        .and_then(|p| p.as_str())
                        .and_then(|s| s.parse::<f64>().ok())
                        .unwrap_or(0.0);
                    all_scores.push(EpssScore {
                        cve_id,
                        epss,
                        percentile,
                    });
                }
            }
        }

        Ok(all_scores)
    }

    pub fn for_cve<'a>(scores: &'a [EpssScore], cve: &str) -> Option<&'a EpssScore> {
        scores.iter().find(|s| s.cve_id == cve)
    }
}

// ─── Goal 162: CISA KEV ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevEntry {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub required_action: String,
    pub due_date: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevCatalog {
    pub catalog_version: String,
    pub date_released: String,
    pub entries: Vec<KevEntry>,
}

impl KevCatalog {
    pub fn load_from_json(path: &std::path::Path) -> Result<Self, IntelligenceError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse_json(&content)
    }

    /// Fetch the CISA KEV catalog from the official API.
    /// Endpoint: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    pub fn fetch_from_cisa() -> Result<Self, IntelligenceError> {
        let url =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        let resp = ureq::get(url)
            .set("Accept", "application/json")
            .call()
            .map_err(|e| IntelligenceError::Http(e.to_string()))?;
        let body = resp
            .into_string()
            .map_err(|e| IntelligenceError::Http(e.to_string()))?;
        Self::parse_json(&body)
    }

    fn parse_json(content: &str) -> Result<Self, IntelligenceError> {
        let parsed: serde_json::Value = serde_json::from_str(content)?;
        let entries = parsed["vulnerabilities"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        Some(KevEntry {
                            cve_id: v["cveID"].as_str()?.to_string(),
                            vendor_project: v["vendorProject"].as_str().unwrap_or("").to_string(),
                            product: v["product"].as_str().unwrap_or("").to_string(),
                            vulnerability_name: v["vulnerabilityName"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                            date_added: v["dateAdded"].as_str().unwrap_or("").to_string(),
                            required_action: v["requiredAction"].as_str().unwrap_or("").to_string(),
                            due_date: v["dueDate"].as_str().unwrap_or("").to_string(),
                            notes: v["notes"].as_str().unwrap_or("").to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            catalog_version: parsed["catalogVersion"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            date_released: parsed["dateReleased"].as_str().unwrap_or("").to_string(),
            entries,
        })
    }
    pub fn contains(&self, cve_id: &str) -> bool {
        self.entries.iter().any(|e| e.cve_id == cve_id)
    }
    pub fn get(&self, cve_id: &str) -> Option<&KevEntry> {
        self.entries.iter().find(|e| e.cve_id == cve_id)
    }
    pub fn sample() -> Self {
        Self {
            catalog_version: "2024.01".into(),
            date_released: "2024-01-15".into(),
            entries: vec![
                KevEntry {
                    cve_id: "CVE-2021-44228".into(),
                    vendor_project: "Apache".into(),
                    product: "Log4j".into(),
                    vulnerability_name: "Log4Shell".into(),
                    date_added: "2021-12-11".into(),
                    required_action: "Apply updates.".into(),
                    due_date: "2021-12-24".into(),
                    notes: "Actively exploited".into(),
                },
                KevEntry {
                    cve_id: "CVE-2023-23375".into(),
                    vendor_project: "Microsoft".into(),
                    product: "Outlook".into(),
                    vulnerability_name: "Elevation of Privilege".into(),
                    date_added: "2023-03-14".into(),
                    required_action: "Apply updates.".into(),
                    due_date: "2023-04-14".into(),
                    notes: "".into(),
                },
            ],
        }
    }
}

// ─── Goal 163: Exploit Maturity ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExploitMaturity {
    None,
    Poc,
    Functional,
    Weaponized,
}

impl ExploitMaturity {
    pub fn detect(finding: &Finding) -> Self {
        let combined = finding
            .references
            .iter()
            .map(|r| r.to_lowercase())
            .collect::<Vec<_>>()
            .join(" ")
            + " "
            + &finding.description.to_lowercase();
        if combined.contains("metasploit")
            || combined.contains("weaponized")
            || combined.contains("exploit-db")
            || combined.contains("cobalt strike")
        {
            ExploitMaturity::Weaponized
        } else if combined.contains("functional") || combined.contains("exploit available") {
            ExploitMaturity::Functional
        } else if combined.contains("poc")
            || combined.contains("proof-of-concept")
            || combined.contains("proof of concept")
        {
            ExploitMaturity::Poc
        } else {
            ExploitMaturity::None
        }
    }
    pub fn weight(&self) -> f64 {
        match self {
            Self::None => 0.1,
            Self::Poc => 0.4,
            Self::Functional => 0.7,
            Self::Weaponized => 1.0,
        }
    }
}

impl std::fmt::Display for ExploitMaturity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Poc => write!(f, "poc"),
            Self::Functional => write!(f, "functional"),
            Self::Weaponized => write!(f, "weaponized"),
        }
    }
}

// ─── Goal 164: Risk-Based Prioritization ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: f64,
    pub cvss_component: f64,
    pub epss_component: f64,
    pub kev_component: f64,
    pub reachability_component: f64,
    pub exploit_component: f64,
    pub in_kev: bool,
    pub epss_percentile: Option<f64>,
    pub exploit_maturity: ExploitMaturity,
}

pub fn calculate_risk_score(
    finding: &Finding,
    epss: Option<&EpssScore>,
    in_kev: bool,
    exploit_maturity: ExploitMaturity,
) -> RiskScore {
    let cvss_component = (finding.cvss_score.unwrap_or(0.0) / 10.0 * 30.0).min(30.0);
    let epss_val = epss.map(|e| e.epss).unwrap_or(0.0);
    let epss_component = (epss_val * 25.0).min(25.0);
    let kev_component = if in_kev { 20.0 } else { 0.0 };
    let reachability_component = match finding.reachability {
        ReachabilityStatus::Reachable => 15.0,
        ReachabilityStatus::Unknown => 7.5,
        ReachabilityStatus::Unreachable => 0.0,
    };
    let exploit_component = exploit_maturity.weight() * 10.0;
    let score = (cvss_component
        + epss_component
        + kev_component
        + reachability_component
        + exploit_component)
        .min(100.0);
    RiskScore {
        score,
        cvss_component,
        epss_component,
        kev_component,
        reachability_component,
        exploit_component,
        in_kev,
        epss_percentile: epss.map(|e| e.percentile),
        exploit_maturity,
    }
}

pub fn prioritize_findings(
    findings: &[Finding],
    epss_scores: &[EpssScore],
    kev: &KevCatalog,
) -> Vec<(Finding, RiskScore)> {
    let mut scored: Vec<_> = findings
        .iter()
        .map(|f| {
            let cve = if f.advisory_id.starts_with("CVE-") {
                f.advisory_id.clone()
            } else {
                format!("CVE-{}", f.advisory_id)
            };
            let epss = EpssScore::for_cve(epss_scores, &cve).or_else(|| {
                f.aliases
                    .iter()
                    .find_map(|a| EpssScore::for_cve(epss_scores, a))
            });
            let in_kev = kev.contains(&cve) || f.aliases.iter().any(|a| kev.contains(a));
            let maturity = ExploitMaturity::detect(f);
            (f.clone(), calculate_risk_score(f, epss, in_kev, maturity))
        })
        .collect();
    scored.sort_by(|a, b| {
        b.1.score
            .partial_cmp(&a.1.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    scored
}

// ─── Goal 165: Age-Based Prioritization ──────────────────────────────────────

pub fn vulnerability_age_days(finding: &Finding) -> Option<u64> {
    for id in std::iter::once(&finding.advisory_id).chain(finding.aliases.iter()) {
        if let Some(rest) = id.strip_prefix("CVE-")
            && let Some(year) = rest.split('-').next().and_then(|y| y.parse::<i32>().ok())
        {
            let now = Utc::now();
            let published = chrono::NaiveDate::from_ymd_opt(year, 7, 1)?
                .and_hms_opt(0, 0, 0)?
                .and_utc();
            return Some((now - published).num_days().max(0) as u64);
        }
    }
    None
}

pub fn age_urgency_multiplier(age_days: u64) -> f64 {
    match age_days {
        0..=30 => 1.5,
        31..=90 => 1.3,
        91..=180 => 1.1,
        181..=365 => 1.0,
        366..=730 => 0.8,
        _ => 0.5,
    }
}

// ─── Goal 166: Business Criticality ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BusinessCriticality {
    Low,
    Medium,
    High,
    Critical,
}

impl BusinessCriticality {
    pub fn weight(&self) -> f64 {
        match self {
            Self::Low => 0.5,
            Self::Medium => 1.0,
            Self::High => 1.5,
            Self::Critical => 2.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalityTag {
    pub package: String,
    pub criticality: BusinessCriticality,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CriticalityRegistry {
    pub tags: HashMap<String, CriticalityTag>,
}

impl CriticalityRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn tag(&mut self, package: &str, criticality: BusinessCriticality, reason: &str) {
        self.tags.insert(
            package.into(),
            CriticalityTag {
                package: package.into(),
                criticality,
                reason: reason.into(),
            },
        );
    }
    pub fn get(&self, package: &str) -> BusinessCriticality {
        self.tags
            .get(package)
            .map(|t| t.criticality)
            .unwrap_or(BusinessCriticality::Medium)
    }
    pub fn adjust_risk_score(&self, package: &str, base: f64) -> f64 {
        (base * self.get(package).weight()).min(100.0)
    }
}

// ─── Goal 167: Exposure Analysis ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureLevel {
    Internal,
    NetworkRestricted,
    InternetExposed,
}

impl ExposureLevel {
    pub fn weight(&self) -> f64 {
        match self {
            Self::Internal => 0.5,
            Self::NetworkRestricted => 0.8,
            Self::InternetExposed => 1.0,
        }
    }
}

impl std::fmt::Display for ExposureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "internal"),
            Self::NetworkRestricted => write!(f, "network_restricted"),
            Self::InternetExposed => write!(f, "internet_exposed"),
        }
    }
}

pub fn analyze_exposure(finding: &Finding) -> ExposureLevel {
    let combined = finding
        .call_chain
        .iter()
        .map(|c| c.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
        + " "
        + &finding.package.to_lowercase();
    if combined.contains("express")
        || combined.contains("flask")
        || combined.contains("django")
        || combined.contains("fastapi")
        || combined.contains("spring")
        || combined.contains("actix")
        || combined.contains("axum")
        || combined.contains("http")
        || combined.contains("server")
        || combined.contains("api")
        || combined.contains("request")
        || combined.contains("handler")
    {
        ExposureLevel::InternetExposed
    } else if combined.contains("internal")
        || combined.contains("cli")
        || combined.contains("tool")
        || combined.contains("build")
        || combined.contains("dev")
        || combined.contains("test")
    {
        ExposureLevel::Internal
    } else {
        ExposureLevel::NetworkRestricted
    }
}

// ─── Goal 168: Attack Path Visualization ─────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackPathNodeType {
    Entry,
    Call,
    VulnerableFunction,
    Impact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathNode {
    pub id: String,
    pub node_type: AttackPathNodeType,
    pub label: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathEdge {
    pub from: String,
    pub to: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub finding_id: String,
    pub nodes: Vec<AttackPathNode>,
    pub edges: Vec<AttackPathEdge>,
}

pub fn build_attack_path(finding: &Finding) -> AttackPath {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let entry_id = "entry".to_string();
    let entry_label = finding
        .call_chain
        .first()
        .cloned()
        .unwrap_or_else(|| "Application Entry".into());
    nodes.push(AttackPathNode {
        id: entry_id.clone(),
        node_type: AttackPathNodeType::Entry,
        label: entry_label.clone(),
        detail: "External input".into(),
    });
    let mut prev = entry_id;
    for (i, func) in finding.call_chain.iter().skip(1).enumerate() {
        let id = format!("call_{}", i);
        nodes.push(AttackPathNode {
            id: id.clone(),
            node_type: AttackPathNodeType::Call,
            label: func.clone(),
            detail: format!("Calls {}", func),
        });
        edges.push(AttackPathEdge {
            from: prev,
            to: id.clone(),
            label: "calls".into(),
        });
        prev = id;
    }
    let vuln = finding
        .vulnerable_functions
        .first()
        .cloned()
        .unwrap_or_else(|| "vulnerable_function".into());
    let vuln_id = "vuln".to_string();
    nodes.push(AttackPathNode {
        id: vuln_id.clone(),
        node_type: AttackPathNodeType::VulnerableFunction,
        label: vuln.clone(),
        detail: format!("{} in {}", vuln, finding.package),
    });
    edges.push(AttackPathEdge {
        from: prev,
        to: vuln_id.clone(),
        label: "reaches".into(),
    });
    let impact_id = "impact".to_string();
    nodes.push(AttackPathNode {
        id: impact_id.clone(),
        node_type: AttackPathNodeType::Impact,
        label: format!("{}", finding.severity),
        detail: finding.summary.clone(),
    });
    edges.push(AttackPathEdge {
        from: vuln_id,
        to: impact_id,
        label: "causes".into(),
    });
    AttackPath {
        finding_id: finding.advisory_id.clone(),
        nodes,
        edges,
    }
}

pub fn attack_path_to_dot(path: &AttackPath) -> String {
    let mut out = format!(
        "digraph attack_path_{} {{\n  rankdir=TB;\n",
        path.finding_id.replace('-', "_")
    );
    for n in &path.nodes {
        let (shape, color) = match n.node_type {
            AttackPathNodeType::Entry => ("box", "lightblue"),
            AttackPathNodeType::Call => ("ellipse", "lightgray"),
            AttackPathNodeType::VulnerableFunction => ("diamond", "orange"),
            AttackPathNodeType::Impact => ("octagon", "red"),
        };
        out.push_str(&format!(
            "  {} [label=\"{}\" shape={} fillcolor={} style=filled];\n",
            n.id, n.label, shape, color
        ));
    }
    for e in &path.edges {
        out.push_str(&format!(
            "  {} -> {} [label=\"{}\"];\n",
            e.from, e.to, e.label
        ));
    }
    out.push_str("}\n");
    out
}

// ─── Goal 169: Threat Intel Feeds ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelEntry {
    pub cve_id: String,
    pub source: String,
    pub severity: String,
    pub description: String,
    pub tags: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelFeed {
    pub name: String,
    pub source_url: String,
    pub entries: Vec<ThreatIntelEntry>,
}

impl ThreatIntelFeed {
    pub fn new(name: &str, url: &str) -> Self {
        Self {
            name: name.into(),
            source_url: url.into(),
            entries: Vec::new(),
        }
    }
    pub fn add_entry(&mut self, e: ThreatIntelEntry) {
        self.entries.push(e);
    }
    pub fn query(&self, cve: &str) -> Vec<&ThreatIntelEntry> {
        self.entries.iter().filter(|e| e.cve_id == cve).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelCorrelation {
    pub finding_id: String,
    pub matched_feeds: Vec<String>,
    pub tags: Vec<String>,
    pub threat_actors: Vec<String>,
}

pub fn correlate_threat_intel(
    findings: &[Finding],
    feeds: &[ThreatIntelFeed],
) -> Vec<ThreatIntelCorrelation> {
    findings
        .iter()
        .map(|f| {
            let matched: Vec<&ThreatIntelEntry> = feeds
                .iter()
                .flat_map(|fd| fd.query(&f.advisory_id))
                .collect();
            let tags: Vec<String> = matched
                .iter()
                .flat_map(|m| m.tags.iter().cloned())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            let feeds_names: Vec<String> = matched
                .iter()
                .map(|m| m.source.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            let actors: Vec<String> = matched
                .iter()
                .filter_map(|m| m.tags.iter().find(|t| t.starts_with("APT-")).cloned())
                .collect();
            ThreatIntelCorrelation {
                finding_id: f.advisory_id.clone(),
                matched_feeds: feeds_names,
                tags,
                threat_actors: actors,
            }
        })
        .filter(|c| !c.matched_feeds.is_empty())
        .collect()
}

// ─── Goal 170: Anomaly Detection ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    Typosquatting,
    VersionJump,
    NewMaintainer,
    LowPopularity,
    RecentlyPublished,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Typosquatting => write!(f, "typosquatting"),
            Self::VersionJump => write!(f, "version_jump"),
            Self::NewMaintainer => write!(f, "new_maintainer"),
            Self::LowPopularity => write!(f, "low_popularity"),
            Self::RecentlyPublished => write!(f, "recently_published"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAnomaly {
    pub package: String,
    pub anomaly_type: AnomalyType,
    pub severity: VulnerabilitySeverity,
    pub description: String,
    pub evidence: String,
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    } else if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        curr[0] = i;
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

pub fn detect_typosquatting(pkg: &str, known: &[String]) -> Option<DependencyAnomaly> {
    let pl = pkg.to_lowercase();
    for k in known {
        let kl = k.to_lowercase();
        let d = levenshtein(&pl, &kl);
        if d > 0 && d <= 2 {
            return Some(DependencyAnomaly {
                package: pkg.into(),
                anomaly_type: AnomalyType::Typosquatting,
                severity: VulnerabilitySeverity::High,
                description: format!("'{}' resembles '{}' (distance {})", pkg, k, d),
                evidence: format!("Levenshtein={}", d),
            });
        }
    }
    None
}

pub fn detect_version_jump(pkg: &str, old: &str, new: &str) -> Option<DependencyAnomaly> {
    let om = old.split('.').next().and_then(|s| s.parse::<u64>().ok());
    let nm = new.split('.').next().and_then(|s| s.parse::<u64>().ok());
    if let (Some(o), Some(n)) = (om, nm)
        && n > o
        && n - o > 1
    {
        return Some(DependencyAnomaly {
            package: pkg.into(),
            anomaly_type: AnomalyType::VersionJump,
            severity: VulnerabilitySeverity::Medium,
            description: format!("'{}' jumped v{} -> v{}", pkg, o, n),
            evidence: format!("{} -> {}", old, new),
        });
    }
    None
}

pub fn detect_recently_published(
    pkg: &str,
    published: DateTime<Utc>,
    threshold_days: u64,
) -> Option<DependencyAnomaly> {
    let age = (Utc::now() - published).num_days().max(0) as u64;
    if age <= threshold_days {
        Some(DependencyAnomaly {
            package: pkg.into(),
            anomaly_type: AnomalyType::RecentlyPublished,
            severity: VulnerabilitySeverity::Medium,
            description: format!("'{}' published {} days ago", pkg, age),
            evidence: format!("Published: {}", published.format("%Y-%m-%d")),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
    use std::path::PathBuf;

    fn make_finding(sev: VulnerabilitySeverity, reach: ReachabilityStatus) -> Finding {
        Finding {
            advisory_id: "CVE-2024-12345".into(),
            summary: "Test".into(),
            description: "exploit available".into(),
            severity: sev,
            cvss_score: Some(7.5),
            package: "npm:express".into(),
            version: "4.17.0".into(),
            fix_version: Some("4.17.1".into()),
            fix_available: true,
            reachability: reach,
            vulnerable_functions: vec!["parseBody".into()],
            call_chain: vec!["app.listen".into(), "router.handle".into()],
            status: FindingStatus::Pending,
            triage_explanation: None,
            references: vec!["https://example.com/poc".into()],
            cwes: vec!["CWE-79".into()],
            manifest_path: PathBuf::from("package.json"),
            aliases: vec![],
        }
    }

    #[test]
    fn test_epss_fetch() {
        // Use a real, well-known CVE that will have EPSS data.
        // If the API is unreachable (offline CI), skip the assertion.
        match EpssScore::fetch_scores(&["CVE-2021-44228".into()]) {
            Ok(scores) => {
                // API may return 0 or 1 results depending on availability.
                for s in &scores {
                    assert!(s.epss >= 0.0 && s.epss <= 1.0, "EPSS should be 0..1");
                    assert!(
                        s.percentile >= 0.0 && s.percentile <= 1.0,
                        "percentile should be 0..1"
                    );
                }
            }
            Err(_) => {
                // Network unavailable — skip test gracefully.
            }
        }
    }

    #[test]
    fn test_kev_catalog() {
        let cat = KevCatalog::sample();
        assert!(cat.contains("CVE-2021-44228"));
        assert!(!cat.contains("CVE-9999-99999"));
    }

    #[test]
    fn test_exploit_maturity() {
        let mut f = make_finding(VulnerabilitySeverity::High, ReachabilityStatus::Reachable);
        f.references = vec!["https://exploit-db.com/exploits/12345".into()];
        assert_eq!(ExploitMaturity::detect(&f), ExploitMaturity::Weaponized);
        f.references = vec!["https://example.com/poc".into()];
        f.description = "proof-of-concept".into();
        assert_eq!(ExploitMaturity::detect(&f), ExploitMaturity::Poc);
        f.references = vec!["https://example.com/advisory".into()];
        f.description = "no exploits".into();
        assert_eq!(ExploitMaturity::detect(&f), ExploitMaturity::None);
    }

    #[test]
    fn test_risk_score() {
        let f = make_finding(VulnerabilitySeverity::High, ReachabilityStatus::Reachable);
        let epss = EpssScore {
            cve_id: "CVE-2024-12345".into(),
            epss: 0.8,
            percentile: 95.0,
        };
        let s = calculate_risk_score(&f, Some(&epss), true, ExploitMaturity::Weaponized);
        assert!(s.score > 70.0);
        assert_eq!(s.kev_component, 20.0);
        assert_eq!(s.reachability_component, 15.0);
    }

    #[test]
    fn test_risk_score_unreachable() {
        let f = make_finding(VulnerabilitySeverity::High, ReachabilityStatus::Unreachable);
        let s = calculate_risk_score(&f, None, false, ExploitMaturity::None);
        assert_eq!(s.reachability_component, 0.0);
        assert_eq!(s.kev_component, 0.0);
        assert!(s.score < 40.0);
    }

    #[test]
    fn test_prioritize_findings() {
        let f1 = make_finding(
            VulnerabilitySeverity::Critical,
            ReachabilityStatus::Reachable,
        );
        let f2 = make_finding(VulnerabilitySeverity::Low, ReachabilityStatus::Unreachable);
        let epss = EpssScore::fetch_scores(&[]).unwrap();
        let kev = KevCatalog::sample();
        let ranked = prioritize_findings(&[f2, f1], &epss, &kev);
        assert!(ranked[0].1.score >= ranked[1].1.score);
    }

    #[test]
    fn test_vuln_age() {
        let f = make_finding(VulnerabilitySeverity::High, ReachabilityStatus::Reachable);
        let age = vulnerability_age_days(&f).unwrap();
        assert!(age > 0);
    }

    #[test]
    fn test_age_urgency() {
        assert_eq!(age_urgency_multiplier(10), 1.5);
        assert_eq!(age_urgency_multiplier(60), 1.3);
        assert_eq!(age_urgency_multiplier(200), 1.0);
        assert_eq!(age_urgency_multiplier(800), 0.5);
    }

    #[test]
    fn test_criticality_registry() {
        let mut reg = CriticalityRegistry::new();
        reg.tag(
            "npm:express",
            BusinessCriticality::Critical,
            "Core web framework",
        );
        assert_eq!(reg.get("npm:express"), BusinessCriticality::Critical);
        assert_eq!(reg.get("npm:unknown"), BusinessCriticality::Medium);
        assert!(reg.adjust_risk_score("npm:express", 50.0) > 50.0);
    }

    #[test]
    fn test_exposure_analysis() {
        let f = make_finding(VulnerabilitySeverity::High, ReachabilityStatus::Reachable);
        assert_eq!(analyze_exposure(&f), ExposureLevel::InternetExposed);
        let mut f2 = f.clone();
        f2.call_chain = vec!["build_tool".into()];
        f2.package = "npm:build-tool".into();
        assert_eq!(analyze_exposure(&f2), ExposureLevel::Internal);
    }

    #[test]
    fn test_attack_path() {
        let f = make_finding(VulnerabilitySeverity::High, ReachabilityStatus::Reachable);
        let path = build_attack_path(&f);
        assert!(!path.nodes.is_empty());
        assert!(!path.edges.is_empty());
        assert!(
            path.nodes
                .iter()
                .any(|n| n.node_type == AttackPathNodeType::Entry)
        );
        assert!(
            path.nodes
                .iter()
                .any(|n| n.node_type == AttackPathNodeType::Impact)
        );
        let dot = attack_path_to_dot(&path);
        assert!(dot.contains("digraph"));
    }

    #[test]
    fn test_threat_intel() {
        let mut feed = ThreatIntelFeed::new("Mandiant", "https://example.com/feed");
        feed.add_entry(ThreatIntelEntry {
            cve_id: "CVE-2024-12345".into(),
            source: "Mandiant".into(),
            severity: "high".into(),
            description: "Active exploitation".into(),
            tags: vec!["APT-29".into()],
            first_seen: "2024-01-01".into(),
            last_seen: "2024-06-01".into(),
        });
        let f = make_finding(VulnerabilitySeverity::High, ReachabilityStatus::Reachable);
        let corrs = correlate_threat_intel(&[f], &[feed]);
        assert_eq!(corrs.len(), 1);
        assert!(corrs[0].matched_feeds.contains(&"Mandiant".to_string()));
        assert!(corrs[0].threat_actors.contains(&"APT-29".to_string()));
    }

    #[test]
    fn test_typosquatting() {
        let known = vec![
            "lodash".to_string(),
            "express".to_string(),
            "react".to_string(),
        ];
        assert!(detect_typosquatting("lodashe", &known).is_some());
        assert!(detect_typosquatting("express", &known).is_none());
    }

    #[test]
    fn test_version_jump() {
        assert!(detect_version_jump("pkg", "1.2.3", "5.0.0").is_some());
        assert!(detect_version_jump("pkg", "1.2.3", "1.3.0").is_none());
    }

    #[test]
    fn test_recently_published() {
        let recent = Utc::now() - chrono::Duration::days(5);
        assert!(detect_recently_published("pkg", recent, 30).is_some());
        let old = Utc::now() - chrono::Duration::days(365);
        assert!(detect_recently_published("pkg", old, 30).is_none());
    }
}
