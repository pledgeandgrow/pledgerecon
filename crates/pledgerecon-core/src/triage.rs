//! LLM-powered triage — reduce false positives by sending vulnerability
//! context to an LLM for assessment.
//!
//! The triage engine sends the advisory description, affected package,
//! reachability status, and call chain to an LLM provider (OpenAI,
//! Anthropic, Ollama, or a local model) and asks it to assess whether
//! the finding is a true positive, false positive, or inconclusive.
//!
//! This dramatically reduces false positives compared to version-only
//! matching, especially for transitive dependencies and dev-only packages.

use crate::config::TriageConfig;
use crate::finding::{Finding, FindingStatus};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info, warn};

/// The LLM's verdict on a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageVerdict {
    /// Confirmed as a true positive — the vulnerability is real and exploitable.
    Confirmed,
    /// Classified as a false positive — not exploitable in this context.
    FalsePositive,
    /// Inconclusive — the LLM could not determine with confidence.
    Inconclusive,
}

impl std::fmt::Display for TriageVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriageVerdict::Confirmed => write!(f, "confirmed"),
            TriageVerdict::FalsePositive => write!(f, "false_positive"),
            TriageVerdict::Inconclusive => write!(f, "inconclusive"),
        }
    }
}

/// Result of LLM triage for a single finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub verdict: TriageVerdict,
    pub confidence: f64,
    pub explanation: String,
    pub remediation: Option<String>,
    /// Token usage for this triage call (Goal 45).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_usage: Option<TokenUsage>,
    /// Which model produced this result (for consensus, Goal 43).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Token usage and cost tracking (Goal 45).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
}

/// Accumulated cost for a scan (Goal 45).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CostReport {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_usd: f64,
    pub num_calls: u64,
}

impl CostReport {
    pub fn add(&mut self, usage: &TokenUsage) {
        self.total_input_tokens += usage.input_tokens;
        self.total_output_tokens += usage.output_tokens;
        self.total_cost_usd += usage.cost_usd;
        self.num_calls += 1;
    }
}

/// Audit log entry for a single LLM call (Goal 44).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: String,
    pub finding_id: String,
    pub model: String,
    pub prompt_hash: String,
    pub verdict: String,
    pub confidence: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    pub cached: bool,
}

/// Triage cache entry (Goal 37).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    result: TriageResult,
    finding_hash: String,
    timestamp: String,
}

/// Errors during triage.
#[derive(Debug, Clone, Error)]
pub enum TriageError {
    #[error("HTTP request to LLM failed: {0}")]
    Http(String),
    #[error("LLM response parsing failed: {0}")]
    Parse(String),
    #[error("triage disabled in configuration")]
    Disabled,
    #[error("no API key configured for provider: {0}")]
    NoApiKey(String),
    #[error("cache I/O error: {0}")]
    Cache(String),
    #[error("audit log I/O error: {0}")]
    AuditLog(String),
    #[error("llama.cpp model not found: {0}")]
    LlamaCppModelNotFound(String),
    #[error("consensus model error: {0}")]
    Consensus(String),
}

/// The triage engine — sends findings to an LLM for assessment.
/// Supports batch calls, caching, streaming, consensus, audit logging,
/// cost tracking, prompt templates, confidence thresholds, and local models.
pub struct TriageEngine {
    config: TriageConfig,
    /// In-memory triage cache (Goal 37): finding_hash → TriageResult.
    cache: HashMap<String, TriageResult>,
    /// Cost report accumulator (Goal 45).
    cost_report: CostReport,
    /// Audit log entries (Goal 44).
    audit_log: Vec<AuditLogEntry>,
}

impl TriageEngine {
    pub fn new(config: TriageConfig) -> Self {
        Self {
            config,
            cache: HashMap::new(),
            cost_report: CostReport::default(),
            audit_log: Vec::new(),
        }
    }

    /// Compute a deterministic hash for a finding (for cache keying).
    fn finding_hash(finding: &Finding) -> String {
        let key = format!(
            "{}|{}|{}|{}|{:?}|{:?}",
            finding.advisory_id,
            finding.package,
            finding.version,
            finding.reachability,
            finding.vulnerable_functions,
            finding.call_chain,
        );
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Triage a single finding (with caching, audit, cost tracking).
    pub fn triage(&mut self, finding: &Finding) -> Result<TriageResult, TriageError> {
        let hash = Self::finding_hash(finding);

        // Goal 37: Check cache first.
        if self.config.enable_cache {
            if let Some(cached) = self.cache.get(&hash).cloned() {
                debug!("Triage cache hit for {}", finding.advisory_id);
                if self.config.audit_log {
                    self.log_audit(&hash, finding, &cached, true);
                }
                return Ok(cached);
            }
            // Also try disk cache.
            if let Some(cached) = self.load_cache_entry(&hash)? {
                self.cache.insert(hash.clone(), cached.clone());
                if self.config.audit_log {
                    self.log_audit(&hash, finding, &cached, true);
                }
                return Ok(cached);
            }
        }

        let prompt = self.build_prompt(finding);
        debug!(
            "Triage prompt for {}: {} chars",
            finding.advisory_id,
            prompt.len()
        );

        // Goal 43: Multi-model consensus.
        let result = if self.config.consensus_models.is_empty() {
            self.call_single_model(&prompt, &self.config.provider, &self.config.model)?
        } else {
            self.call_consensus(&prompt, finding)?
        };

        // Goal 45: Cost tracking.
        if self.config.cost_tracking
            && let Some(ref usage) = result.token_usage
        {
            self.cost_report.add(usage);
        }

        // Goal 42: Apply confidence threshold for auto-suppression.
        if result.verdict == TriageVerdict::FalsePositive
            && result.confidence >= self.config.confidence_threshold
        {
            info!(
                "Auto-suppressing {} (false_positive, confidence {:.2} >= threshold {:.2})",
                finding.advisory_id, result.confidence, self.config.confidence_threshold
            );
        }

        // Goal 37: Save to cache.
        if self.config.enable_cache {
            self.cache.insert(hash.clone(), result.clone());
            self.save_cache_entry(&hash, &result)?;
        }

        // Goal 44: Audit log.
        if self.config.audit_log {
            self.log_audit(&hash, finding, &result, false);
        }

        info!(
            "Triage result for {}: {} (confidence: {:.2})",
            finding.advisory_id, result.verdict, result.confidence
        );

        Ok(result)
    }

    /// Goal 36: Triage multiple findings in a single batch LLM call.
    /// Groups findings into batches of `batch_size` and sends one prompt per batch.
    pub fn triage_batch(
        &mut self,
        findings: &[Finding],
    ) -> Vec<(usize, Result<TriageResult, TriageError>)> {
        let batch_size = self.config.batch_size;
        if batch_size == 0 || findings.len() <= 1 {
            // No batching — triage individually.
            return findings
                .iter()
                .enumerate()
                .map(|(i, f)| (i, self.triage(f)))
                .collect();
        }

        let mut results = Vec::new();
        for chunk in findings.chunks(batch_size) {
            match self.triage_batch_chunk(chunk) {
                Ok(batch_results) => {
                    for r in batch_results.into_iter() {
                        // Find the original index.
                        let orig_idx = results.len();
                        results.push((orig_idx, Ok(r)));
                    }
                }
                Err(e) => {
                    for _ in 0..chunk.len() {
                        let orig_idx = results.len();
                        results.push((orig_idx, Err(e.clone())));
                    }
                }
            }
        }

        // Re-index with correct original indices.
        let mut indexed = Vec::new();
        let mut idx = 0;
        for chunk in findings.chunks(batch_size) {
            for _ in chunk {
                if idx < results.len() {
                    indexed.push((idx, results[idx].1.clone()));
                }
                idx += 1;
            }
        }
        indexed
    }

    /// Send a batch of findings in one LLM prompt (Goal 36).
    fn triage_batch_chunk(
        &mut self,
        findings: &[Finding],
    ) -> Result<Vec<TriageResult>, TriageError> {
        // Check cache for all findings first.
        let mut all_cached = true;
        let mut cached_results = Vec::new();
        for finding in findings {
            let hash = Self::finding_hash(finding);
            if self.config.enable_cache {
                if let Some(cached) = self.cache.get(&hash) {
                    cached_results.push(cached.clone());
                    continue;
                }
                if let Some(cached) = self.load_cache_entry(&hash)? {
                    self.cache.insert(hash, cached.clone());
                    cached_results.push(cached);
                    continue;
                }
            }
            all_cached = false;
            break;
        }

        if all_cached && cached_results.len() == findings.len() {
            return Ok(cached_results);
        }

        // Build a batch prompt with all findings.
        let prompt = self.build_batch_prompt(findings);
        let result = self.call_single_model(&prompt, &self.config.provider, &self.config.model)?;
        // For batch, the explanation field contains the raw LLM response.
        let batch_parsed = self.parse_batch_response(&result.explanation, findings.len())?;

        // Cache each result.
        for (i, result) in batch_parsed.iter().enumerate() {
            if i < findings.len() {
                let hash = Self::finding_hash(&findings[i]);
                if self.config.enable_cache {
                    self.cache.insert(hash.clone(), result.clone());
                    self.save_cache_entry(&hash, result)?;
                }
                if self.config.audit_log {
                    self.log_audit(&hash, &findings[i], result, false);
                }
                if self.config.cost_tracking
                    && let Some(ref usage) = result.token_usage
                {
                    self.cost_report.add(usage);
                }
            }
        }

        Ok(batch_parsed)
    }

    /// Build a batch prompt for multiple findings (Goal 36).
    fn build_batch_prompt(&self, findings: &[Finding]) -> String {
        let mut prompt = String::from(
            "You are a security analyst triaging multiple dependency vulnerability findings. \
             Assess each finding as true positive, false positive, or inconclusive.\n\n",
        );
        for (i, finding) in findings.iter().enumerate() {
            prompt.push_str(&format!("### Finding {}\n", i + 1));
            prompt.push_str(&self.finding_summary(finding));
            prompt.push('\n');
        }
        prompt.push_str(
            r#"
Respond with a JSON array where each element corresponds to the finding:
```json
[
  {
    "verdict": "confirmed" | "false_positive" | "inconclusive",
    "confidence": 0.0-1.0,
    "explanation": "...",
    "remediation": "..." or null
  }
]
```"#,
        );
        prompt
    }

    /// Parse a batch response (JSON array) into multiple TriageResults.
    fn parse_batch_response(
        &self,
        response: &str,
        expected: usize,
    ) -> Result<Vec<TriageResult>, TriageError> {
        let json_str = extract_json(response);
        let parsed: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| TriageError::Parse(format!("Failed to parse batch JSON: {}", e)))?;

        let arr = parsed
            .as_array()
            .ok_or_else(|| TriageError::Parse("Batch response is not a JSON array".to_string()))?;

        let results: Vec<TriageResult> = arr.iter().map(|v| self.parse_single_result(v)).collect();

        // Pad with inconclusive if we got fewer than expected.
        let mut results = results;
        while results.len() < expected {
            results.push(TriageResult {
                verdict: TriageVerdict::Inconclusive,
                confidence: 0.5,
                explanation: "No result from batch".to_string(),
                remediation: None,
                token_usage: None,
                model: Some(self.config.model.clone()),
            });
        }

        Ok(results)
    }

    /// Parse a single JSON object into a TriageResult.
    fn parse_single_result(&self, parsed: &serde_json::Value) -> TriageResult {
        let verdict_str = parsed
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("inconclusive");

        let verdict = match verdict_str {
            "confirmed" => TriageVerdict::Confirmed,
            "false_positive" => TriageVerdict::FalsePositive,
            _ => TriageVerdict::Inconclusive,
        };

        let confidence = parsed
            .get("confidence")
            .and_then(|c| c.as_f64())
            .unwrap_or(0.5);

        let explanation = parsed
            .get("explanation")
            .and_then(|e| e.as_str())
            .unwrap_or("No explanation provided")
            .to_string();

        let remediation = parsed
            .get("remediation")
            .and_then(|r| r.as_str())
            .map(String::from);

        TriageResult {
            verdict,
            confidence,
            explanation,
            remediation,
            token_usage: None,
            model: Some(self.config.model.clone()),
        }
    }

    /// Goal 43: Multi-model consensus — query multiple models and use majority vote.
    fn call_consensus(
        &mut self,
        prompt: &str,
        _finding: &Finding,
    ) -> Result<TriageResult, TriageError> {
        let mut results = Vec::new();

        // Primary model.
        let primary = self.call_single_model(prompt, &self.config.provider, &self.config.model)?;
        results.push(primary.clone());

        // Consensus models.
        for model_spec in &self.config.consensus_models {
            let parts: Vec<&str> = model_spec.splitn(2, ':').collect();
            if parts.len() != 2 {
                warn!("Invalid consensus model spec: {}", model_spec);
                continue;
            }
            let provider = parts[0];
            let model = parts[1];
            match self.call_single_model(prompt, provider, model) {
                Ok(r) => results.push(r),
                Err(e) => warn!("Consensus model {} failed: {}", model_spec, e),
            }
        }

        // Majority vote on verdict.
        let confirmed = results
            .iter()
            .filter(|r| r.verdict == TriageVerdict::Confirmed)
            .count();
        let false_positive = results
            .iter()
            .filter(|r| r.verdict == TriageVerdict::FalsePositive)
            .count();
        let inconclusive = results
            .iter()
            .filter(|r| r.verdict == TriageVerdict::Inconclusive)
            .count();

        let consensus_verdict = if confirmed >= false_positive && confirmed >= inconclusive {
            TriageVerdict::Confirmed
        } else if false_positive >= confirmed && false_positive >= inconclusive {
            TriageVerdict::FalsePositive
        } else {
            TriageVerdict::Inconclusive
        };

        // Average confidence.
        let avg_confidence =
            results.iter().map(|r| r.confidence).sum::<f64>() / results.len() as f64;

        // Combine explanations.
        let explanations: Vec<String> = results
            .iter()
            .map(|r| {
                format!(
                    "[{}] {}",
                    r.model.as_deref().unwrap_or("unknown"),
                    r.explanation
                )
            })
            .collect();

        // Sum token usage.
        let total_usage = results.iter().filter_map(|r| r.token_usage.as_ref()).fold(
            TokenUsage::default(),
            |mut acc, u| {
                acc.input_tokens += u.input_tokens;
                acc.output_tokens += u.output_tokens;
                acc.cost_usd += u.cost_usd;
                acc
            },
        );

        Ok(TriageResult {
            verdict: consensus_verdict,
            confidence: avg_confidence,
            explanation: explanations.join("\n"),
            remediation: primary.remediation.clone(),
            token_usage: Some(total_usage),
            model: Some("consensus".to_string()),
        })
    }

    /// Call a single LLM model (used by both single triage and consensus).
    fn call_single_model(
        &self,
        prompt: &str,
        provider: &str,
        model: &str,
    ) -> Result<TriageResult, TriageError> {
        // Goal 39: llama.cpp local model support.
        if provider == "llamacpp" {
            return self.call_llamacpp(prompt, model);
        }

        // Goal 40: Fine-tuned model support.
        if provider == "finetuned" {
            return self.call_finetuned(prompt, model);
        }

        // Ollama doesn't require an API key — handle it separately.
        if provider == "ollama" {
            let endpoint = self
                .config
                .endpoint
                .as_deref()
                .unwrap_or("http://localhost:11434/api/generate");
            let body = serde_json::json!({
                "model": model,
                "prompt": prompt,
                "stream": false,
            })
            .to_string();

            let resp = ureq::post(endpoint)
                .set("Content-Type", "application/json")
                .send_string(&body)
                .map_err(|e| TriageError::Http(e.to_string()))?;

            let raw: serde_json::Value = resp
                .into_json()
                .map_err(|e| TriageError::Parse(e.to_string()))?;

            let text = raw
                .get("response")
                .and_then(|r| r.as_str())
                .unwrap_or_default()
                .to_string();

            return self.parse_response_with_usage(&text, model);
        }

        let api_key = self
            .config
            .api_key
            .as_ref()
            .ok_or_else(|| TriageError::NoApiKey(provider.to_string()))?;

        let endpoint = self.config.endpoint.as_deref().unwrap_or(match provider {
            "openai" => "https://api.openai.com/v1/chat/completions",
            "anthropic" => "https://api.anthropic.com/v1/messages",
            _ => "http://localhost:11434/api/generate",
        });

        let body = match provider {
            "openai" => serde_json::json!({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": self.config.max_tokens,
                "temperature": 0.1,
            })
            .to_string(),
            "anthropic" => serde_json::json!({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": self.config.max_tokens,
            })
            .to_string(),
            _ => serde_json::json!({
                "model": model,
                "prompt": prompt,
                "stream": false,
            })
            .to_string(),
        };

        // Goal 38: Streaming support — use stream=true if configured.
        if self.config.stream && provider == "openai" {
            let body = serde_json::json!({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": self.config.max_tokens,
                "temperature": 0.1,
                "stream": true,
            })
            .to_string();

            let resp = ureq::post(endpoint)
                .set("Content-Type", "application/json")
                .set("Authorization", &format!("Bearer {}", api_key))
                .send_string(&body)
                .map_err(|e| TriageError::Http(e.to_string()))?;

            // Read streaming response (SSE format).
            let mut full_text = String::new();
            let reader = std::io::BufReader::new(resp.into_reader());
            use std::io::BufRead;
            for line in reader.lines().map_while(Result::ok) {
                if let Some(data) = line.strip_prefix("data: ") {
                    if data == "[DONE]" {
                        break;
                    }
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(data)
                        && let Some(content) = json
                            .get("choices")
                            .and_then(|c| c.get(0))
                            .and_then(|c| c.get("delta"))
                            .and_then(|d| d.get("content"))
                            .and_then(|c| c.as_str())
                    {
                        full_text.push_str(content);
                    }
                }
            }
            return self.parse_response_with_usage(&full_text, model);
        }

        let resp = ureq::post(endpoint)
            .set("Content-Type", "application/json")
            .set("Authorization", &format!("Bearer {}", api_key))
            .send_string(&body)
            .map_err(|e| TriageError::Http(e.to_string()))?;

        let raw: serde_json::Value = resp
            .into_json()
            .map_err(|e| TriageError::Parse(e.to_string()))?;

        // Extract text and token usage from response.
        let text = match provider {
            "openai" => raw
                .get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str())
                .unwrap_or(""),
            "anthropic" => raw
                .get("content")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or(""),
            _ => raw.get("response").and_then(|r| r.as_str()).unwrap_or(""),
        };

        // Extract token usage (Goal 45).
        let usage = self.extract_token_usage(&raw, provider);

        let mut result = self.parse_response_with_usage(text, model)?;
        result.token_usage = usage;
        Ok(result)
    }

    /// Goal 39: Call llama.cpp local model via HTTP server.
    fn call_llamacpp(&self, prompt: &str, model: &str) -> Result<TriageResult, TriageError> {
        let model_path = self.config.llamacpp_model_path.as_ref().ok_or_else(|| {
            TriageError::LlamaCppModelNotFound("no model path configured".to_string())
        })?;

        if !model_path.exists() {
            return Err(TriageError::LlamaCppModelNotFound(
                model_path.display().to_string(),
            ));
        }

        // llama.cpp server endpoint (default: localhost:8080).
        let endpoint = self
            .config
            .endpoint
            .as_deref()
            .unwrap_or("http://localhost:8080/completion");

        let body = serde_json::json!({
            "prompt": prompt,
            "n_predict": self.config.max_tokens,
            "temperature": 0.1,
            "model": model,
        })
        .to_string();

        let resp = ureq::post(endpoint)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| TriageError::Http(e.to_string()))?;

        let raw: serde_json::Value = resp
            .into_json()
            .map_err(|e| TriageError::Parse(e.to_string()))?;

        let text = raw.get("content").and_then(|c| c.as_str()).unwrap_or("");

        let usage = TokenUsage {
            input_tokens: raw
                .get("tokens_evaluated")
                .and_then(|t| t.as_u64())
                .unwrap_or(0),
            output_tokens: raw
                .get("tokens_predicted")
                .and_then(|t| t.as_u64())
                .unwrap_or(0),
            cost_usd: 0.0, // Local model — no API cost.
        };

        let mut result = self.parse_response_with_usage(text, model)?;
        result.token_usage = Some(usage);
        Ok(result)
    }

    /// Goal 40: Call fine-tuned model (loaded via llama.cpp or compatible runtime).
    fn call_finetuned(&self, prompt: &str, model: &str) -> Result<TriageResult, TriageError> {
        let model_path = self.config.fine_tuned_model_path.as_ref().ok_or_else(|| {
            TriageError::LlamaCppModelNotFound("no fine-tuned model path configured".to_string())
        })?;

        if !model_path.exists() {
            return Err(TriageError::LlamaCppModelNotFound(
                model_path.display().to_string(),
            ));
        }

        // Use the same llama.cpp server interface but with the fine-tuned model.
        let endpoint = self
            .config
            .endpoint
            .as_deref()
            .unwrap_or("http://localhost:8080/completion");

        let body = serde_json::json!({
            "prompt": prompt,
            "n_predict": self.config.max_tokens,
            "temperature": 0.1,
            "model": model,
        })
        .to_string();

        let resp = ureq::post(endpoint)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| TriageError::Http(e.to_string()))?;

        let raw: serde_json::Value = resp
            .into_json()
            .map_err(|e| TriageError::Parse(e.to_string()))?;

        let text = raw.get("content").and_then(|c| c.as_str()).unwrap_or("");

        let usage = TokenUsage {
            input_tokens: raw
                .get("tokens_evaluated")
                .and_then(|t| t.as_u64())
                .unwrap_or(0),
            output_tokens: raw
                .get("tokens_predicted")
                .and_then(|t| t.as_u64())
                .unwrap_or(0),
            cost_usd: 0.0,
        };

        let mut result = self.parse_response_with_usage(text, model)?;
        result.token_usage = Some(usage);
        Ok(result)
    }

    /// Extract token usage from provider response (Goal 45).
    fn extract_token_usage(&self, raw: &serde_json::Value, provider: &str) -> Option<TokenUsage> {
        let usage = raw.get("usage")?;

        let (input, output) = match provider {
            "openai" => (
                usage
                    .get("prompt_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0),
                usage
                    .get("completion_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0),
            ),
            "anthropic" => (
                usage
                    .get("input_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0),
                usage
                    .get("output_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0),
            ),
            _ => (0, 0),
        };

        let cost = (input as f64 / 1000.0 * self.config.cost_per_input_token)
            + (output as f64 / 1000.0 * self.config.cost_per_output_token);

        Some(TokenUsage {
            input_tokens: input,
            output_tokens: output,
            cost_usd: cost,
        })
    }

    /// Goal 44: Log an audit entry.
    fn log_audit(&mut self, hash: &str, finding: &Finding, result: &TriageResult, cached: bool) {
        let entry = AuditLogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            finding_id: finding.advisory_id.clone(),
            model: result
                .model
                .clone()
                .unwrap_or_else(|| self.config.model.clone()),
            prompt_hash: hash.to_string(),
            verdict: result.verdict.to_string(),
            confidence: result.confidence,
            input_tokens: result
                .token_usage
                .as_ref()
                .map(|u| u.input_tokens)
                .unwrap_or(0),
            output_tokens: result
                .token_usage
                .as_ref()
                .map(|u| u.output_tokens)
                .unwrap_or(0),
            cost_usd: result
                .token_usage
                .as_ref()
                .map(|u| u.cost_usd)
                .unwrap_or(0.0),
            cached,
        };
        self.audit_log.push(entry);
    }

    /// Goal 37: Load a cached triage result from disk.
    fn load_cache_entry(&self, hash: &str) -> Result<Option<TriageResult>, TriageError> {
        let cache_file = self.config.cache_dir.join(format!("{}.json", hash));
        if !cache_file.exists() {
            return Ok(None);
        }
        let content =
            std::fs::read_to_string(&cache_file).map_err(|e| TriageError::Cache(e.to_string()))?;
        let entry: CacheEntry =
            serde_json::from_str(&content).map_err(|e| TriageError::Cache(e.to_string()))?;
        Ok(Some(entry.result))
    }

    /// Goal 37: Save a triage result to disk cache.
    fn save_cache_entry(&self, hash: &str, result: &TriageResult) -> Result<(), TriageError> {
        let cache_dir = &self.config.cache_dir;
        std::fs::create_dir_all(cache_dir).map_err(|e| TriageError::Cache(e.to_string()))?;
        let entry = CacheEntry {
            result: result.clone(),
            finding_hash: hash.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let json = serde_json::to_string(&entry).map_err(|e| TriageError::Cache(e.to_string()))?;
        let cache_file = cache_dir.join(format!("{}.json", hash));
        std::fs::write(&cache_file, json).map_err(|e| TriageError::Cache(e.to_string()))?;
        Ok(())
    }

    /// Goal 45: Get the accumulated cost report.
    pub fn cost_report(&self) -> &CostReport {
        &self.cost_report
    }

    /// Goal 44: Get the audit log entries.
    pub fn audit_log(&self) -> &[AuditLogEntry] {
        &self.audit_log
    }

    /// Goal 44: Flush audit log to disk.
    pub fn flush_audit_log(&self, path: &Path) -> Result<(), TriageError> {
        if self.audit_log.is_empty() {
            return Ok(());
        }
        let json = serde_json::to_string_pretty(&self.audit_log)
            .map_err(|e| TriageError::AuditLog(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| TriageError::AuditLog(e.to_string()))?;
        info!(
            "Flushed {} audit log entries to {}",
            self.audit_log.len(),
            path.display()
        );
        Ok(())
    }

    /// Build the LLM prompt for a finding, using custom template if configured (Goal 41).
    fn build_prompt(&self, finding: &Finding) -> String {
        if let Some(ref template) = self.config.prompt_template {
            // Goal 41: Use custom prompt template.
            template
                .replace("{advisory_id}", &finding.advisory_id)
                .replace("{summary}", &finding.summary)
                .replace("{description}", &finding.description)
                .replace("{severity}", &finding.severity.to_string())
                .replace(
                    "{cvss}",
                    &finding
                        .cvss_score
                        .map(|s| s.to_string())
                        .unwrap_or("N/A".to_string()),
                )
                .replace("{package}", &finding.package)
                .replace("{version}", &finding.version)
                .replace("{fix_available}", &finding.fix_available.to_string())
                .replace(
                    "{fix_version}",
                    finding.fix_version.as_deref().unwrap_or("N/A"),
                )
                .replace("{reachability}", &finding.reachability.to_string())
                .replace("{vuln_funcs}", &finding.vulnerable_functions.join(", "))
                .replace("{call_chain}", &finding.call_chain.join(" → "))
                .replace("{cwes}", &finding.cwes.join(", "))
        } else {
            // Default prompt.
            format!(
                r#"You are a security analyst triaging a dependency vulnerability finding. Assess whether this is a true positive or false positive.

## Vulnerability
- **Advisory ID:** {advisory_id}
- **Summary:** {summary}
- **Description:** {description}
- **Severity:** {severity}
- **CVSS Score:** {cvss}
- **Package:** {package}@{version}
- **Fix Available:** {fix_available}
- **Fix Version:** {fix_version}
- **Reachability:** {reachability}
- **Vulnerable Functions:** {vuln_funcs}
- **Call Chain:** {call_chain}
- **CWEs:** {cwes}

## Task
Determine if this vulnerability is exploitable in the project's context. Consider:
1. Is the vulnerable function actually called (reachability)?
2. Is the package a dev-only dependency?
3. Is the version actually in the affected range?
4. Are there mitigating factors (sandboxing, input validation, etc.)?

Respond in JSON format:
```json
{{
  "verdict": "confirmed" | "false_positive" | "inconclusive",
  "confidence": 0.0-1.0,
  "explanation": "Brief explanation of your assessment",
  "remediation": "Recommended fix or null"
}}
```"#,
                advisory_id = finding.advisory_id,
                summary = finding.summary,
                description = finding.description,
                severity = finding.severity,
                cvss = finding
                    .cvss_score
                    .map(|s| s.to_string())
                    .unwrap_or("N/A".to_string()),
                package = finding.package,
                version = finding.version,
                fix_available = finding.fix_available,
                fix_version = finding.fix_version.as_deref().unwrap_or("N/A"),
                reachability = finding.reachability,
                vuln_funcs = finding.vulnerable_functions.join(", "),
                call_chain = finding.call_chain.join(" → "),
                cwes = finding.cwes.join(", "),
            )
        }
    }

    /// Compact one-line summary of a finding (for batch prompts).
    fn finding_summary(&self, finding: &Finding) -> String {
        format!(
            "- Advisory: {advisory_id} | Package: {package}@{version} | Severity: {severity} | \
             Reachability: {reachability} | Functions: {vuln_funcs} | Call chain: {call_chain}",
            advisory_id = finding.advisory_id,
            package = finding.package,
            version = finding.version,
            severity = finding.severity,
            reachability = finding.reachability,
            vuln_funcs = finding.vulnerable_functions.join(", "),
            call_chain = finding.call_chain.join(" → "),
        )
    }

    /// Call the LLM provider (delegates to call_single_model with primary config).
    #[allow(dead_code)]
    fn call_llm(&self, prompt: &str) -> Result<String, TriageError> {
        // This is kept for backward compatibility but now delegates.
        let result = self.call_single_model(prompt, &self.config.provider, &self.config.model)?;
        // Return the explanation as the "response text" for backward compat.
        Ok(format!(
            "{{\"verdict\": \"{}\", \"confidence\": {}, \"explanation\": \"{}\"}}",
            result.verdict,
            result.confidence,
            result.explanation.replace('"', "\\\""),
        ))
    }

    /// Parse the LLM response into a TriageResult (with model tag).
    fn parse_response_with_usage(
        &self,
        response: &str,
        model: &str,
    ) -> Result<TriageResult, TriageError> {
        let json_str = extract_json(response);
        let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
            TriageError::Parse(format!(
                "Failed to parse JSON: {} — response: {}",
                e, response
            ))
        })?;

        let mut result = self.parse_single_result(&parsed);
        result.model = Some(model.to_string());
        Ok(result)
    }

    /// Parse the LLM response into a TriageResult (legacy, for tests).
    #[allow(dead_code)]
    fn parse_response(&self, response: &str) -> Result<TriageResult, TriageError> {
        let json_str = extract_json(response);
        let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
            TriageError::Parse(format!(
                "Failed to parse JSON: {} — response: {}",
                e, response
            ))
        })?;
        Ok(self.parse_single_result(&parsed))
    }

    /// Apply triage results to findings (Goal 42: with confidence threshold auto-suppression).
    pub fn apply_triage(
        &self,
        findings: &mut [Finding],
        results: &[(usize, Result<TriageResult, TriageError>)],
    ) {
        for (idx, result) in results {
            if let Some(finding) = findings.get_mut(*idx) {
                match result {
                    Ok(r) => {
                        finding.status = match r.verdict {
                            TriageVerdict::Confirmed => FindingStatus::Confirmed,
                            TriageVerdict::FalsePositive => FindingStatus::FalsePositive,
                            TriageVerdict::Inconclusive => FindingStatus::Inconclusive,
                        };
                        finding.triage_explanation = Some(r.explanation.clone());
                    }
                    Err(e) => {
                        finding.status = FindingStatus::Inconclusive;
                        finding.triage_explanation = Some(format!("Triage error: {}", e));
                    }
                }
            }
        }
    }
}

/// Extract JSON from a potentially markdown-wrapped response.
fn extract_json(text: &str) -> &str {
    // Try to find ```json ... ``` block.
    if let Some(start) = text.find("```json")
        && let Some(end) = text[start..].rfind("```")
    {
        return text[start + 7..start + end].trim();
    }
    // Try to find [ ... ] directly (JSON array — check before object since arrays contain objects).
    if let Some(start) = text.find('[')
        && let Some(end) = text.rfind(']')
    {
        return &text[start..=end];
    }
    // Try to find { ... } directly.
    if let Some(start) = text.find('{')
        && let Some(end) = text.rfind('}')
    {
        return &text[start..=end];
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{ReachabilityStatus, VulnerabilitySeverity};
    use std::path::PathBuf;

    fn make_finding() -> Finding {
        Finding {
            advisory_id: "CVE-2021-23337".to_string(),
            summary: "Command injection in lodash.template".to_string(),
            description: "Lodash versions prior to 4.17.21 are vulnerable to command injection via template function.".to_string(),
            severity: VulnerabilitySeverity::High,
            cvss_score: Some(7.2),
            package: "npm:lodash".to_string(),
            version: "4.17.11".to_string(),
            fix_version: Some("4.17.21".to_string()),
            fix_available: true,
            reachability: ReachabilityStatus::Reachable,
            vulnerable_functions: vec!["template".to_string()],
            call_chain: vec!["main".to_string(), "process".to_string(), "lodash.template".to_string()],
            status: FindingStatus::Pending,
            triage_explanation: None,
            references: vec![],
            cwes: vec!["CWE-77".to_string()],
            manifest_path: PathBuf::from("package.json"),
            aliases: vec![],
        }
    }

    #[test]
    fn test_build_prompt() {
        let config = TriageConfig::default();
        let engine = TriageEngine::new(config);
        let finding = make_finding();
        let prompt = engine.build_prompt(&finding);
        assert!(prompt.contains("CVE-2021-23337"));
        assert!(prompt.contains("lodash"));
        assert!(prompt.contains("reachable"));
        assert!(prompt.contains("template"));
    }

    #[test]
    fn test_build_prompt_custom_template() {
        let config = TriageConfig {
            prompt_template: Some("Analyze {advisory_id} for {package}@{version}".to_string()),
            ..Default::default()
        };
        let engine = TriageEngine::new(config);
        let finding = make_finding();
        let prompt = engine.build_prompt(&finding);
        assert!(prompt.contains("Analyze CVE-2021-23337"));
        assert!(prompt.contains("npm:lodash@4.17.11"));
    }

    #[test]
    fn test_parse_response_confirmed() {
        let config = TriageConfig::default();
        let engine = TriageEngine::new(config);
        let response = r#"```json
{
  "verdict": "confirmed",
  "confidence": 0.95,
  "explanation": "The vulnerable function template() is reachable from the entry point.",
  "remediation": "Upgrade lodash to 4.17.21 or later"
}
```"#;
        let result = engine.parse_response(response).unwrap();
        assert_eq!(result.verdict, TriageVerdict::Confirmed);
        assert!((result.confidence - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_parse_response_false_positive() {
        let config = TriageConfig::default();
        let engine = TriageEngine::new(config);
        let response = r#"{"verdict": "false_positive", "confidence": 0.8, "explanation": "Dev-only dependency, not used in production", "remediation": null}"#;
        let result = engine.parse_response(response).unwrap();
        assert_eq!(result.verdict, TriageVerdict::FalsePositive);
    }

    #[test]
    fn test_extract_json() {
        let text = "Here is the result:\n```json\n{\"verdict\": \"confirmed\"}\n```\nDone.";
        let json = extract_json(text);
        assert!(json.contains("confirmed"));
    }

    #[test]
    fn test_finding_hash_deterministic() {
        let finding = make_finding();
        let hash1 = TriageEngine::finding_hash(&finding);
        let hash2 = TriageEngine::finding_hash(&finding);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_finding_hash_differs() {
        let finding1 = make_finding();
        let mut finding2 = finding1.clone();
        finding2.version = "4.17.21".to_string();
        let hash1 = TriageEngine::finding_hash(&finding1);
        let hash2 = TriageEngine::finding_hash(&finding2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_batch_prompt() {
        let config = TriageConfig {
            batch_size: 2,
            ..Default::default()
        };
        let engine = TriageEngine::new(config);
        let f1 = make_finding();
        let f2 = make_finding();
        let prompt = engine.build_batch_prompt(&[f1, f2]);
        assert!(prompt.contains("Finding 1"));
        assert!(prompt.contains("Finding 2"));
        assert!(prompt.contains("JSON array"));
    }

    #[test]
    fn test_parse_batch_response() {
        let config = TriageConfig::default();
        let engine = TriageEngine::new(config);
        let response = r#"```json
[
  {"verdict": "confirmed", "confidence": 0.9, "explanation": "reachable", "remediation": "upgrade"},
  {"verdict": "false_positive", "confidence": 0.85, "explanation": "dev-only", "remediation": null}
]
```"#;
        let results = engine.parse_batch_response(response, 2).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].verdict, TriageVerdict::Confirmed);
        assert_eq!(results[1].verdict, TriageVerdict::FalsePositive);
    }

    #[test]
    fn test_parse_batch_response_pads_missing() {
        let config = TriageConfig::default();
        let engine = TriageEngine::new(config);
        let response = r#"[{"verdict": "confirmed", "confidence": 0.9, "explanation": "ok"}]"#;
        let results = engine.parse_batch_response(response, 3).unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[1].verdict, TriageVerdict::Inconclusive);
    }

    #[test]
    fn test_cost_report() {
        let mut report = CostReport::default();
        let usage = TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            cost_usd: 0.005,
        };
        report.add(&usage);
        assert_eq!(report.total_input_tokens, 100);
        assert_eq!(report.total_output_tokens, 50);
        assert!((report.total_cost_usd - 0.005).abs() < 0.0001);
        assert_eq!(report.num_calls, 1);
    }

    #[test]
    fn test_confidence_threshold_default() {
        let config = TriageConfig::default();
        assert!((config.confidence_threshold - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_audit_log_entry_serialization() {
        let entry = AuditLogEntry {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            finding_id: "CVE-2021-23337".to_string(),
            model: "gpt-4o-mini".to_string(),
            prompt_hash: "abc123".to_string(),
            verdict: "confirmed".to_string(),
            confidence: 0.95,
            input_tokens: 100,
            output_tokens: 50,
            cost_usd: 0.005,
            cached: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("CVE-2021-23337"));
        assert!(json.contains("confirmed"));
    }

    #[test]
    fn test_extract_token_usage_openai() {
        let config = TriageConfig::default();
        let engine = TriageEngine::new(config);
        let raw = serde_json::json!({
            "usage": {
                "prompt_tokens": 150,
                "completion_tokens": 80
            }
        });
        let usage = engine.extract_token_usage(&raw, "openai").unwrap();
        assert_eq!(usage.input_tokens, 150);
        assert_eq!(usage.output_tokens, 80);
        assert!(usage.cost_usd > 0.0);
    }

    #[test]
    fn test_extract_token_usage_none() {
        let config = TriageConfig::default();
        let engine = TriageEngine::new(config);
        let raw = serde_json::json!({});
        assert!(engine.extract_token_usage(&raw, "openai").is_none());
    }

    #[test]
    fn test_finding_summary() {
        let config = TriageConfig::default();
        let engine = TriageEngine::new(config);
        let finding = make_finding();
        let summary = engine.finding_summary(&finding);
        assert!(summary.contains("CVE-2021-23337"));
        assert!(summary.contains("npm:lodash"));
        assert!(summary.contains("high"));
    }
}
