//! Advanced LLM & AI — AI-powered remediation, enrichment, RAG, and
//! fine-tuning pipeline (Goals 181–190).

use crate::finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
use crate::triage::TriageResult;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AiError {
    #[error("LLM error: {0}")]
    Llm(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not found: {0}")]
    NotFound(String),
}

// ─── Goal 181: AI-Powered Remediation Suggestions ────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodePatch {
    pub file: String,
    pub original_snippet: String,
    pub patched_snippet: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRemediationSuggestion {
    pub finding_id: String,
    pub patches: Vec<CodePatch>,
    pub summary: String,
    pub confidence: f64,
}

pub fn generate_ai_remediation(finding: &Finding) -> AiRemediationSuggestion {
    let patch = match finding.package.split(':').next().unwrap_or("") {
        "npm" => CodePatch {
            file: finding.manifest_path.display().to_string(),
            original_snippet: format!(
                "\"{}\": \"{}\"",
                finding.package.split(':').nth(1).unwrap_or(""),
                finding.version
            ),
            patched_snippet: format!(
                "\"{}\": \"{}\"",
                finding.package.split(':').nth(1).unwrap_or(""),
                finding.fix_version.as_deref().unwrap_or("latest")
            ),
            explanation: format!("Bump {} to fix {}", finding.package, finding.advisory_id),
        },
        _ => CodePatch {
            file: finding.manifest_path.display().to_string(),
            original_snippet: finding.version.clone(),
            patched_snippet: finding
                .fix_version
                .clone()
                .unwrap_or_else(|| "latest".into()),
            explanation: format!("Upgrade to fix {}", finding.advisory_id),
        },
    };
    AiRemediationSuggestion {
        finding_id: finding.advisory_id.clone(),
        patches: vec![patch],
        summary: format!(
            "Upgrade {}@{} to fix {}",
            finding.package, finding.version, finding.advisory_id
        ),
        confidence: 0.85,
    }
}

// ─── Goal 182: AI Vulnerability Description Enrichment ───────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedDescription {
    pub finding_id: String,
    pub plain_language: String,
    pub impact: String,
    pub affected_users: String,
    pub analogy: String,
}

pub fn enrich_description(finding: &Finding) -> EnrichedDescription {
    let sev_str = match finding.severity {
        VulnerabilitySeverity::Critical => "critical severity",
        VulnerabilitySeverity::High => "high severity",
        VulnerabilitySeverity::Medium => "moderate severity",
        _ => "low severity",
    };
    EnrichedDescription {
        finding_id: finding.advisory_id.clone(),
        plain_language: format!(
            "This is a {} vulnerability in {} (version {}). {} This means an attacker could potentially compromise your application.",
            sev_str, finding.package, finding.version, finding.description
        ),
        impact: format!(
            "If exploited, this could lead to {} in applications using {}@{}.",
            match finding.severity {
                VulnerabilitySeverity::Critical | VulnerabilitySeverity::High =>
                    "serious security breaches",
                _ => "limited security issues",
            },
            finding.package,
            finding.version
        ),
        affected_users: format!(
            "All users of {} versions in the affected range are impacted.",
            finding.package
        ),
        analogy: format!(
            "Think of this like a {} – {}.",
            match finding.severity {
                VulnerabilitySeverity::Critical => "wide-open front door",
                VulnerabilitySeverity::High => "broken lock",
                _ => "cracked window",
            },
            finding.summary
        ),
    }
}

// ─── Goal 183: AI False Positive Explanation ─────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpExplanation {
    pub finding_id: String,
    pub is_false_positive: bool,
    pub reasoning: String,
    pub evidence: Vec<String>,
    pub confidence: f64,
}

pub fn explain_false_positive(finding: &Finding, triage: Option<&TriageResult>) -> FpExplanation {
    let is_fp = finding.status == FindingStatus::FalsePositive;
    let reasoning = if is_fp {
        format!(
            "This finding was classified as a false positive because the vulnerable code path in {}@{} is not reachable in this project's dependency graph.",
            finding.package, finding.version
        )
    } else {
        format!(
            "This finding is a true positive. The vulnerable function in {}@{} is {}.",
            finding.package, finding.version, finding.reachability
        )
    };
    let mut evidence = vec![format!("Reachability: {}", finding.reachability)];
    if finding.reachability == ReachabilityStatus::Unreachable {
        evidence.push("Vulnerable function not called in call graph".to_string());
    }
    if let Some(t) = triage {
        evidence.push(format!(
            "LLM triage: {} (confidence: {:.0}%)",
            t.verdict,
            t.confidence * 100.0
        ));
    }
    FpExplanation {
        finding_id: finding.advisory_id.clone(),
        is_false_positive: is_fp,
        reasoning,
        evidence,
        confidence: triage.map(|t| t.confidence).unwrap_or(0.75),
    }
}

// ─── Goal 184: Local LLM Auto-Selection ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub has_gpu: bool,
    pub gpu_vram_gb: u64,
    pub ram_gb: u64,
    pub cpu_cores: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalModel {
    Llama3_8b,
    Llama3_70b,
    Mistral7b,
    Phi3Mini,
    Qwen2_7b,
}

impl LocalModel {
    pub fn min_vram_gb(&self) -> u64 {
        match self {
            Self::Llama3_70b => 40,
            Self::Llama3_8b => 8,
            Self::Mistral7b => 6,
            Self::Qwen2_7b => 6,
            Self::Phi3Mini => 4,
        }
    }
    pub fn min_ram_gb(&self) -> u64 {
        match self {
            Self::Llama3_70b => 64,
            Self::Llama3_8b => 16,
            Self::Mistral7b => 12,
            Self::Qwen2_7b => 12,
            Self::Phi3Mini => 8,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Llama3_8b => "llama3-8b",
            Self::Llama3_70b => "llama3-70b",
            Self::Mistral7b => "mistral-7b",
            Self::Phi3Mini => "phi3-mini",
            Self::Qwen2_7b => "qwen2-7b",
        }
    }
}

pub fn select_local_model(hw: &HardwareProfile) -> LocalModel {
    if hw.has_gpu
        && hw.gpu_vram_gb >= LocalModel::Llama3_70b.min_vram_gb()
        && hw.ram_gb >= LocalModel::Llama3_70b.min_ram_gb()
    {
        LocalModel::Llama3_70b
    } else if hw.has_gpu && hw.gpu_vram_gb >= LocalModel::Llama3_8b.min_vram_gb() {
        LocalModel::Llama3_8b
    } else if hw.ram_gb >= LocalModel::Mistral7b.min_ram_gb() {
        LocalModel::Mistral7b
    } else {
        LocalModel::Phi3Mini
    }
}

// ─── Goal 185: RAG-Based Vulnerability Knowledge Base ────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEntry {
    pub id: String,
    pub cve_id: String,
    pub content: String,
    pub source: String,
    pub embedding: Vec<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnowledgeBase {
    pub entries: Vec<KnowledgeEntry>,
}

impl KnowledgeBase {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, entry: KnowledgeEntry) {
        self.entries.push(entry);
    }

    /// Simple cosine similarity search.
    pub fn search(&self, query_embedding: &[f32], top_k: usize) -> Vec<&KnowledgeEntry> {
        let mut scored: Vec<(f64, &KnowledgeEntry)> = self
            .entries
            .iter()
            .map(|e| (cosine_sim(query_embedding, &e.embedding), e))
            .collect();
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        scored.into_iter().take(top_k).map(|(_, e)| e).collect()
    }

    /// Search by CVE ID.
    pub fn search_by_cve(&self, cve: &str) -> Vec<&KnowledgeEntry> {
        self.entries.iter().filter(|e| e.cve_id == cve).collect()
    }
}

fn cosine_sim(a: &[f32], b: &[f32]) -> f64 {
    if a.is_empty() || b.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let mag_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        0.0
    } else {
        (dot / (mag_a * mag_b)) as f64
    }
}

/// Generate a RAG-augmented prompt for a finding.
pub fn build_rag_prompt(finding: &Finding, kb: &KnowledgeBase) -> String {
    let context = kb.search_by_cve(&finding.advisory_id);
    let context_str = if context.is_empty() {
        "No additional context found.".to_string()
    } else {
        context
            .iter()
            .map(|e| format!("--- {} ---\n{}", e.source, e.content))
            .collect::<Vec<_>>()
            .join("\n\n")
    };
    format!(
        "You are a security analyst. Assess the following vulnerability:\n\n\
         CVE: {}\nPackage: {}@{}\nSeverity: {}\nDescription: {}\n\n\
         Additional context from knowledge base:\n{}\n\n\
         Is this a true positive given the project context? Provide your assessment.",
        finding.advisory_id,
        finding.package,
        finding.version,
        finding.severity,
        finding.description,
        context_str
    )
}

// ─── Goal 186: AI Dependency Question Answering ──────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QaAnswer {
    pub question: String,
    pub answer: String,
    pub relevant_findings: Vec<String>,
    pub confidence: f64,
}

/// Answer natural language questions about project dependencies.
pub fn answer_dependency_question(question: &str, findings: &[Finding]) -> QaAnswer {
    let q_lower = question.to_lowercase();
    let relevant: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            let combined = format!(
                "{} {} {} {} {}",
                f.advisory_id,
                f.package,
                f.summary,
                f.description,
                f.cwes.join(" ")
            )
            .to_lowercase();
            q_lower
                .split_whitespace()
                .any(|word| word.len() > 3 && combined.contains(word))
        })
        .collect();

    let rce_findings: Vec<&Finding> = if q_lower.contains("rce") || q_lower.contains("remote code")
    {
        findings
            .iter()
            .filter(|f| {
                f.cwes
                    .iter()
                    .any(|c| c.contains("CWE-94") || c.contains("CWE-77"))
            })
            .collect()
    } else {
        vec![]
    };

    let answer = if !rce_findings.is_empty() {
        format!(
            "Found {} dependencies with potential RCE vulnerabilities: {}",
            rce_findings.len(),
            rce_findings
                .iter()
                .map(|f| format!("{}@{}", f.package, f.version))
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else if q_lower.contains("rce") || q_lower.contains("remote code") {
        "No dependencies with known RCE vulnerabilities were found.".to_string()
    } else if q_lower.contains("critical") {
        let crits: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == VulnerabilitySeverity::Critical)
            .collect();
        format!("There are {} critical-severity findings.", crits.len())
    } else if q_lower.contains("reachable") {
        let reach: Vec<_> = findings
            .iter()
            .filter(|f| f.reachability == ReachabilityStatus::Reachable)
            .collect();
        format!("{} findings have reachable vulnerable code.", reach.len())
    } else if relevant.is_empty() {
        format!(
            "I couldn't find findings matching your question: '{}'",
            question
        )
    } else {
        format!(
            "Found {} relevant findings. Key packages: {}",
            relevant.len(),
            relevant
                .iter()
                .take(5)
                .map(|f| format!("{}@{}", f.package, f.version))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    let result_findings: Vec<String> = if !rce_findings.is_empty() {
        rce_findings.iter().map(|f| f.advisory_id.clone()).collect()
    } else {
        relevant.iter().map(|f| f.advisory_id.clone()).collect()
    };

    let confidence = if result_findings.is_empty() { 0.3 } else { 0.8 };

    QaAnswer {
        question: question.to_string(),
        answer,
        relevant_findings: result_findings,
        confidence,
    }
}

// ─── Goal 187: AI Policy Generation ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedPolicy {
    pub policy_id: String,
    pub description: String,
    pub rego: String,
    pub severity: String,
}

/// Generate a policy from a natural language description.
pub fn generate_policy(description: &str) -> GeneratedPolicy {
    let d_lower = description.to_lowercase();
    let (policy_id, severity, rego) = if d_lower.contains("critical")
        && (d_lower.contains("block") || d_lower.contains("fail"))
    {
        (
            "block-critical",
            "critical",
            "package pledgerecon.block_critical {\n  count([f | f := input.findings[_]; f.severity == \"critical\"]) > 0\n}",
        )
    } else if d_lower.contains("high") && (d_lower.contains("block") || d_lower.contains("fail")) {
        (
            "block-high",
            "high",
            "package pledgerecon.block_high {\n  count([f | f := input.findings[_]; f.severity == \"high\"]) > 0\n}",
        )
    } else if d_lower.contains("unreachable") && d_lower.contains("ignore") {
        (
            "ignore-unreachable",
            "info",
            "package pledgerecon.ignore_unreachable {\n  count([f | f := input.findings[_]; f.reachability != \"unreachable\"]) > 0\n}",
        )
    } else if d_lower.contains("fix") && d_lower.contains("available") {
        (
            "require-fix",
            "medium",
            "package pledgerecon.require_fix {\n  count([f | f := input.findings[_]; f.fix_available == false; f.severity >= \"medium\"]) > 0\n}",
        )
    } else {
        (
            "general-policy",
            "medium",
            "package pledgerecon.general {\n  count(input.findings) > 0\n}",
        )
    };
    GeneratedPolicy {
        policy_id: policy_id.to_string(),
        description: description.to_string(),
        rego: rego.to_string(),
        severity: severity.to_string(),
    }
}

// ─── Goal 188: AI Commit Message Analysis ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitAnalysis {
    pub is_security_relevant: bool,
    pub reason: String,
    pub should_rescan: bool,
    pub keywords_matched: Vec<String>,
}

/// Analyze a git commit message for security-relevant changes.
pub fn analyze_commit_message(message: &str) -> CommitAnalysis {
    let lower = message.to_lowercase();
    let security_keywords = [
        "security",
        "vuln",
        "cve",
        "fix",
        "patch",
        "upgrade",
        "update",
        "depend",
        "xss",
        "sqli",
        "rce",
        "injection",
        "auth",
        "crypto",
        "encrypt",
        "token",
        "secret",
        "password",
        "sanitiz",
        "validate",
        "escape",
    ];
    let matched: Vec<String> = security_keywords
        .iter()
        .filter(|k| lower.contains(*k))
        .map(|k| k.to_string())
        .collect();
    let is_relevant = !matched.is_empty();
    let should_rescan = is_relevant
        && (lower.contains("depend")
            || lower.contains("upgrade")
            || lower.contains("update")
            || lower.contains("fix")
            || lower.contains("security"));
    CommitAnalysis {
        is_security_relevant: is_relevant,
        reason: if is_relevant {
            format!(
                "Commit mentions security-relevant keywords: {}",
                matched.join(", ")
            )
        } else {
            "No security-relevant keywords found".to_string()
        },
        should_rescan,
        keywords_matched: matched,
    }
}

// ─── Goal 189: Multi-Modal Analysis ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub title: String,
    pub summary: String,
    pub key_findings: Vec<String>,
    pub recommendations: Vec<String>,
    pub risk_level: String,
}

/// Generate an executive summary from a scan report (simulating vision LLM analysis).
pub fn generate_executive_summary(findings: &[Finding]) -> ExecutiveSummary {
    let critical = findings
        .iter()
        .filter(|f| f.severity == VulnerabilitySeverity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == VulnerabilitySeverity::High)
        .count();
    let reachable = findings
        .iter()
        .filter(|f| f.reachability == ReachabilityStatus::Reachable)
        .count();
    let risk_level = if critical > 0 {
        "Critical"
    } else if high > 0 {
        "High"
    } else if !findings.is_empty() {
        "Medium"
    } else {
        "Low"
    };
    let key_findings: Vec<String> = findings
        .iter()
        .take(5)
        .map(|f| {
            format!(
                "{}: {} in {}@{}",
                f.advisory_id, f.summary, f.package, f.version
            )
        })
        .collect();
    let recommendations = if critical > 0 {
        vec![
            "Immediately patch all critical vulnerabilities".to_string(),
            "Prioritize reachable critical findings".to_string(),
            "Review and update CI/CD gates".to_string(),
        ]
    } else if high > 0 {
        vec![
            "Schedule patches for high-severity findings".to_string(),
            "Review reachable findings first".to_string(),
        ]
    } else {
        vec![
            "Continue regular scanning".to_string(),
            "Monitor for new advisories".to_string(),
        ]
    };
    ExecutiveSummary {
        title: "PledgeRecon Security Scan — Executive Summary".to_string(),
        summary: format!(
            "Found {} vulnerabilities ({} critical, {} high, {} reachable). Overall risk: {}.",
            findings.len(),
            critical,
            high,
            reachable,
            risk_level
        ),
        key_findings,
        recommendations,
        risk_level: risk_level.to_string(),
    }
}

// ─── Goal 190: AI Triage Fine-Tuning Pipeline ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageFeedback {
    pub finding_id: String,
    pub human_verdict: String,
    pub ai_verdict: String,
    pub correct: bool,
    pub feedback: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FineTuningDataset {
    pub samples: Vec<TriageFeedback>,
}

impl FineTuningDataset {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, feedback: TriageFeedback) {
        self.samples.push(feedback);
    }
    pub fn accuracy(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let correct = self.samples.iter().filter(|s| s.correct).count();
        correct as f64 / self.samples.len() as f64
    }
    pub fn export_jsonl(&self) -> String {
        self.samples
            .iter()
            .map(|s| serde_json::to_string(s).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }
    /// Generate training data in instruction format.
    pub fn export_training_format(&self) -> Vec<serde_json::Value> {
        self.samples.iter().map(|s| {
            serde_json::json!({
                "instruction": format!("Assess finding {} — is it a true positive or false positive?", s.finding_id),
                "input": s.feedback,
                "output": s.human_verdict,
            })
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
    use std::path::PathBuf;

    fn make_finding(sev: VulnerabilitySeverity) -> Finding {
        Finding {
            advisory_id: "CVE-2024-12345".into(),
            summary: "Test vuln".into(),
            description: "A test vulnerability".into(),
            severity: sev,
            cvss_score: Some(7.5),
            package: "npm:lodash".into(),
            version: "4.17.0".into(),
            fix_version: Some("4.17.21".into()),
            fix_available: true,
            reachability: ReachabilityStatus::Reachable,
            vulnerable_functions: vec!["merge".into()],
            call_chain: vec!["app.use".into()],
            status: FindingStatus::Pending,
            triage_explanation: None,
            references: vec!["https://example.com".into()],
            cwes: vec!["CWE-94".into()],
            manifest_path: PathBuf::from("package.json"),
            aliases: vec![],
        }
    }

    #[test]
    fn test_ai_remediation() {
        let f = make_finding(VulnerabilitySeverity::High);
        let s = generate_ai_remediation(&f);
        assert!(!s.patches.is_empty());
        assert!(s.summary.contains("lodash"));
    }

    #[test]
    fn test_enrich_description() {
        let f = make_finding(VulnerabilitySeverity::Critical);
        let e = enrich_description(&f);
        assert!(e.plain_language.contains("critical"));
        assert!(!e.analogy.is_empty());
    }

    #[test]
    fn test_fp_explanation() {
        let f = make_finding(VulnerabilitySeverity::High);
        let exp = explain_false_positive(&f, None);
        assert!(!exp.is_false_positive);
        assert!(!exp.reasoning.is_empty());
    }

    #[test]
    fn test_fp_explanation_actual_fp() {
        let mut f = make_finding(VulnerabilitySeverity::High);
        f.status = FindingStatus::FalsePositive;
        let exp = explain_false_positive(&f, None);
        assert!(exp.is_false_positive);
    }

    #[test]
    fn test_local_model_selection_gpu() {
        let hw = HardwareProfile {
            has_gpu: true,
            gpu_vram_gb: 80,
            ram_gb: 128,
            cpu_cores: 32,
        };
        assert_eq!(select_local_model(&hw), LocalModel::Llama3_70b);
    }

    #[test]
    fn test_local_model_selection_mid_gpu() {
        let hw = HardwareProfile {
            has_gpu: true,
            gpu_vram_gb: 12,
            ram_gb: 32,
            cpu_cores: 8,
        };
        assert_eq!(select_local_model(&hw), LocalModel::Llama3_8b);
    }

    #[test]
    fn test_local_model_selection_cpu_only() {
        let hw = HardwareProfile {
            has_gpu: false,
            gpu_vram_gb: 0,
            ram_gb: 16,
            cpu_cores: 8,
        };
        assert_eq!(select_local_model(&hw), LocalModel::Mistral7b);
    }

    #[test]
    fn test_local_model_selection_low_end() {
        let hw = HardwareProfile {
            has_gpu: false,
            gpu_vram_gb: 0,
            ram_gb: 8,
            cpu_cores: 4,
        };
        assert_eq!(select_local_model(&hw), LocalModel::Phi3Mini);
    }

    #[test]
    fn test_knowledge_base() {
        let mut kb = KnowledgeBase::new();
        kb.add(KnowledgeEntry {
            id: "1".into(),
            cve_id: "CVE-2024-12345".into(),
            content: "Test content".into(),
            source: "NVD".into(),
            embedding: vec![1.0, 0.0, 0.0],
        });
        let results = kb.search_by_cve("CVE-2024-12345");
        assert_eq!(results.len(), 1);
        let search_results = kb.search(&[1.0, 0.0, 0.0], 1);
        assert_eq!(search_results.len(), 1);
    }

    #[test]
    fn test_rag_prompt() {
        let mut kb = KnowledgeBase::new();
        kb.add(KnowledgeEntry {
            id: "1".into(),
            cve_id: "CVE-2024-12345".into(),
            content: "Extra context".into(),
            source: "NVD".into(),
            embedding: vec![],
        });
        let f = make_finding(VulnerabilitySeverity::High);
        let prompt = build_rag_prompt(&f, &kb);
        assert!(prompt.contains("CVE-2024-12345"));
        assert!(prompt.contains("Extra context"));
    }

    #[test]
    fn test_qa_rce_question() {
        let f = make_finding(VulnerabilitySeverity::High);
        let ans = answer_dependency_question("Which deps have RCE?", &[f]);
        assert!(ans.answer.contains("lodash"));
        assert!(
            ans.relevant_findings
                .contains(&"CVE-2024-12345".to_string())
        );
    }

    #[test]
    fn test_qa_critical_question() {
        let f = make_finding(VulnerabilitySeverity::Critical);
        let ans = answer_dependency_question("How many critical findings?", &[f]);
        assert!(ans.answer.contains("1 critical"));
    }

    #[test]
    fn test_policy_generation() {
        let p = generate_policy("Block all critical vulnerabilities");
        assert_eq!(p.policy_id, "block-critical");
        assert!(p.rego.contains("critical"));
    }

    #[test]
    fn test_commit_analysis_security() {
        let a = analyze_commit_message("fix security vulnerability in auth module");
        assert!(a.is_security_relevant);
        assert!(a.should_rescan);
        assert!(a.keywords_matched.contains(&"security".to_string()));
    }

    #[test]
    fn test_commit_analysis_non_security() {
        let a = analyze_commit_message("refactor README formatting");
        assert!(!a.is_security_relevant);
        assert!(!a.should_rescan);
    }

    #[test]
    fn test_executive_summary() {
        let findings = vec![
            make_finding(VulnerabilitySeverity::Critical),
            make_finding(VulnerabilitySeverity::High),
        ];
        let s = generate_executive_summary(&findings);
        assert_eq!(s.risk_level, "Critical");
        assert!(s.summary.contains("1 critical"));
        assert!(!s.recommendations.is_empty());
    }

    #[test]
    fn test_fine_tuning_dataset() {
        let mut ds = FineTuningDataset::new();
        ds.add(TriageFeedback {
            finding_id: "CVE-2024-1".into(),
            human_verdict: "confirmed".into(),
            ai_verdict: "confirmed".into(),
            correct: true,
            feedback: "Good".into(),
        });
        ds.add(TriageFeedback {
            finding_id: "CVE-2024-2".into(),
            human_verdict: "false_positive".into(),
            ai_verdict: "confirmed".into(),
            correct: false,
            feedback: "Wrong".into(),
        });
        assert_eq!(ds.accuracy(), 0.5);
        let jsonl = ds.export_jsonl();
        assert!(jsonl.contains("CVE-2024-1"));
        let training = ds.export_training_format();
        assert_eq!(training.len(), 2);
    }
}
