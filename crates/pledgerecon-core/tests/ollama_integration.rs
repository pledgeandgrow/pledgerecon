//! Integration tests for Ollama LLM triage.
//!
//! These tests verify the Ollama integration works when a local Ollama
//! instance is available. They are skipped gracefully when Ollama is not running.

use pledgerecon_core::config::TriageConfig;
use pledgerecon_core::triage::{TriageEngine, TriageVerdict};
use pledgerecon_core::finding::{Finding, FindingStatus, ReachabilityStatus, VulnerabilitySeverity};
use std::path::PathBuf;

fn make_test_finding() -> Finding {
    Finding {
        advisory_id: "CVE-2021-23337".to_string(),
        summary: "Command injection in lodash".to_string(),
        description: "Lodash 4.17.11 is vulnerable to command injection via template()".to_string(),
        severity: VulnerabilitySeverity::High,
        cvss_score: Some(7.5),
        package: "lodash".to_string(),
        version: "4.17.11".to_string(),
        fix_version: Some("4.17.21".to_string()),
        fix_available: true,
        reachability: ReachabilityStatus::Reachable,
        vulnerable_functions: vec!["template".to_string()],
        call_chain: vec!["main".to_string(), "render".to_string(), "lodash.template".to_string()],
        status: FindingStatus::Pending,
        triage_explanation: None,
        references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23337".to_string()],
        cwes: vec!["CWE-77".to_string()],
        manifest_path: PathBuf::from("package.json"),
        aliases: vec![],
    }
}

fn ollama_available() -> bool {
    match ureq::get("http://localhost:11434/api/tags")
        .set("Accept", "application/json")
        .call()
    {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[test]
fn test_ollama_triage_integration() {
    if !ollama_available() {
        eprintln!("Skipping Ollama integration test — Ollama not running on localhost:11434");
        return;
    }

    let config = TriageConfig {
        provider: "ollama".to_string(),
        model: "llama3.2".to_string(),
        api_key: None,
        endpoint: Some("http://localhost:11434/api/generate".to_string()),
        ..TriageConfig::default()
    };

    let mut engine = TriageEngine::new(config);
    let finding = make_test_finding();

    match engine.triage(&finding) {
        Ok(result) => {
            // The verdict should be one of the valid options.
            assert!(
                matches!(
                    result.verdict,
                    TriageVerdict::Confirmed
                        | TriageVerdict::FalsePositive
                        | TriageVerdict::Inconclusive
                ),
                "verdict should be valid"
            );
            assert!(!result.explanation.is_empty(), "explanation should not be empty");
        }
        Err(e) => {
            // If the model isn't available, that's okay for CI.
            eprintln!("Ollama triage returned error (model may not be pulled): {}", e);
        }
    }
}

#[test]
fn test_ollama_config_no_api_key_required() {
    // Verify that Ollama config doesn't require an API key.
    let config = TriageConfig {
        provider: "ollama".to_string(),
        model: "llama3.2".to_string(),
        api_key: None,
        ..TriageConfig::default()
    };

    let mut engine = TriageEngine::new(config);
    let finding = make_test_finding();

    if !ollama_available() {
        eprintln!("Skipping Ollama config test — Ollama not running");
        return;
    }

    match engine.triage(&finding) {
        Ok(_) => {}
        Err(e) => {
            let err_str = format!("{}", e);
            assert!(
                !err_str.contains("No API key"),
                "Ollama should not require an API key, got: {}",
                err_str
            );
        }
    }
}

#[test]
fn test_triage_engine_creation() {
    let config = TriageConfig {
        provider: "ollama".to_string(),
        model: "llama3.2".to_string(),
        api_key: None,
        ..TriageConfig::default()
    };

    let engine = TriageEngine::new(config);
    let cost = engine.cost_report();
    assert_eq!(cost.num_calls, 0);
    assert_eq!(cost.total_cost_usd, 0.0);
}
