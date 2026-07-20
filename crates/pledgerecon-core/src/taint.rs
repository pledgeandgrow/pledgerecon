//! Advanced reachability & code analysis features (Goals 111–120).
//!
//! - Data flow analysis (Goal 111)
//! - Taint tracking for JS/TS (Goal 112)
//! - Taint tracking for Python (Goal 113)
//! - Taint tracking for Rust (Goal 114)
//! - Cross-language call resolution (Goal 115)
//! - Framework-aware reachability (Goal 116)
//! - Conditional reachability (Goal 117)
//! - Reachability for C/C++ vendored code (Goal 118)
//! - Interprocedural analysis (Goal 119)
//! - Reachability caching with CAS (Goal 120)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TaintError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid: {0}")]
    Invalid(String),
}

// ─── Goal 111: Data Flow Analysis ───────────────────────────────────────────

/// A taint source — where untrusted data enters the program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// Source type (e.g. `user_input`, `file_read`, `network`).
    pub source_type: String,
    /// Function/API that introduces the taint (e.g. `req.query`, `fs.readFile`).
    pub function_name: String,
    /// Variable name that receives the tainted data.
    pub variable: String,
    /// Source file path.
    pub file: String,
    /// Line number (1-indexed).
    pub line: usize,
}

/// A taint sink — where tainted data could cause harm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    /// Sink type (e.g. `sql_query`, `command_exec`, `html_output`).
    pub sink_type: String,
    /// Function/API that is the sink (e.g. `db.query`, `child_process.exec`).
    pub function_name: String,
    /// Argument index that receives the tainted data (0-indexed).
    pub arg_index: usize,
    /// Source file path.
    pub file: String,
    /// Line number (1-indexed).
    pub line: usize,
}

/// A sanitizer — a function that cleans tainted data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sanitizer {
    /// Function that sanitizes (e.g. `escapeHtml`, `parameterize`).
    pub function_name: String,
    /// Source file path.
    pub file: String,
    /// Line number (1-indexed).
    pub line: usize,
}

/// A taint flow path from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    pub source: TaintSource,
    pub sink: TaintSink,
    /// Intermediate steps in the flow.
    #[serde(default)]
    pub steps: Vec<TaintStep>,
    /// Whether the flow is sanitized.
    pub is_sanitized: bool,
    /// Sanitizers applied (if any).
    #[serde(default)]
    pub sanitizers: Vec<Sanitizer>,
    /// Vulnerability type (e.g. `xss`, `sqli`, `command_injection`).
    pub vuln_type: String,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
}

/// A single step in a taint flow path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintStep {
    pub function: String,
    pub file: String,
    pub line: usize,
    pub description: String,
}

/// The taint analyzer — tracks data flow from sources to sinks.
pub struct TaintAnalyzer {
    /// Known taint sources by language.
    sources: HashMap<String, Vec<TaintSourcePattern>>,
    /// Known taint sinks by language.
    sinks: HashMap<String, Vec<TaintSinkPattern>>,
    /// Known sanitizers by language.
    sanitizers: HashMap<String, Vec<String>>,
}

/// A pattern for identifying taint sources.
#[derive(Debug, Clone)]
struct TaintSourcePattern {
    source_type: String,
    function_patterns: Vec<String>,
}

/// A pattern for identifying taint sinks.
#[derive(Debug, Clone)]
struct TaintSinkPattern {
    sink_type: String,
    function_patterns: Vec<String>,
    vuln_type: String,
}

impl Default for TaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        let mut sources: HashMap<String, Vec<TaintSourcePattern>> = HashMap::new();
        let mut sinks: HashMap<String, Vec<TaintSinkPattern>> = HashMap::new();
        let mut sanitizers: HashMap<String, Vec<String>> = HashMap::new();

        // JS/TS sources.
        sources.insert("javascript".to_string(), vec![
            TaintSourcePattern {
                source_type: "user_input".to_string(),
                function_patterns: vec![
                    "req.query".to_string(), "req.body".to_string(),
                    "req.params".to_string(), "req.headers".to_string(),
                    "req.cookies".to_string(), "window.location".to_string(),
                    "document.cookie".to_string(),
                ],
            },
            TaintSourcePattern {
                source_type: "file_read".to_string(),
                function_patterns: vec![
                    "fs.readFile".to_string(), "fs.readFileSync".to_string(),
                    "fs.createReadStream".to_string(),
                ],
            },
        ]);

        // JS/TS sinks.
        sinks.insert("javascript".to_string(), vec![
            TaintSinkPattern {
                sink_type: "sql_query".to_string(),
                function_patterns: vec!["db.query".to_string(), "connection.query".to_string(), "pool.query".to_string()],
                vuln_type: "sqli".to_string(),
            },
            TaintSinkPattern {
                sink_type: "command_exec".to_string(),
                function_patterns: vec!["child_process.exec".to_string(), "child_process.execSync".to_string(), "exec".to_string()],
                vuln_type: "command_injection".to_string(),
            },
            TaintSinkPattern {
                sink_type: "html_output".to_string(),
                function_patterns: vec!["res.send".to_string(), "res.write".to_string(), "innerHTML".to_string()],
                vuln_type: "xss".to_string(),
            },
            TaintSinkPattern {
                sink_type: "eval".to_string(),
                function_patterns: vec!["eval".to_string(), "Function".to_string()],
                vuln_type: "code_injection".to_string(),
            },
        ]);

        // JS/TS sanitizers.
        sanitizers.insert("javascript".to_string(), vec![
            "escapeHtml".to_string(), "encodeURIComponent".to_string(),
            "DOMPurify.sanitize".to_string(), "validator.escape".to_string(),
        ]);

        // Python sources.
        sources.insert("python".to_string(), vec![
            TaintSourcePattern {
                source_type: "user_input".to_string(),
                function_patterns: vec![
                    "request.args".to_string(), "request.form".to_string(),
                    "request.json".to_string(), "request.cookies".to_string(),
                    "request.headers".to_string(), "input".to_string(),
                    "sys.argv".to_string(),
                ],
            },
            TaintSourcePattern {
                source_type: "file_read".to_string(),
                function_patterns: vec!["open".to_string(), "os.path.join".to_string()],
            },
        ]);

        // Python sinks.
        sinks.insert("python".to_string(), vec![
            TaintSinkPattern {
                sink_type: "sql_query".to_string(),
                function_patterns: vec!["cursor.execute".to_string(), "db.execute".to_string()],
                vuln_type: "sqli".to_string(),
            },
            TaintSinkPattern {
                sink_type: "command_exec".to_string(),
                function_patterns: vec!["os.system".to_string(), "subprocess.run".to_string(), "subprocess.call".to_string(), "os.popen".to_string()],
                vuln_type: "command_injection".to_string(),
            },
            TaintSinkPattern {
                sink_type: "eval".to_string(),
                function_patterns: vec!["eval".to_string(), "exec".to_string(), "pickle.loads".to_string()],
                vuln_type: "code_injection".to_string(),
            },
            TaintSinkPattern {
                sink_type: "ssrf".to_string(),
                function_patterns: vec!["requests.get".to_string(), "urllib.request.urlopen".to_string(), "httpx.get".to_string()],
                vuln_type: "ssrf".to_string(),
            },
        ]);

        // Python sanitizers.
        sanitizers.insert("python".to_string(), vec![
            "html.escape".to_string(), "shlex.quote".to_string(),
            "markupsafe.escape".to_string(),
        ]);

        // Rust sources.
        sources.insert("rust".to_string(), vec![
            TaintSourcePattern {
                source_type: "user_input".to_string(),
                function_patterns: vec![
                    "std::env::args".to_string(), "std::env::var".to_string(),
                    "std::io::stdin".to_string(),
                ],
            },
            TaintSourcePattern {
                source_type: "ffi".to_string(),
                function_patterns: vec!["std::ffi::CString".to_string(), "unsafe".to_string()],
            },
        ]);

        // Rust sinks.
        sinks.insert("rust".to_string(), vec![
            TaintSinkPattern {
                sink_type: "command_exec".to_string(),
                function_patterns: vec!["std::process::Command::new".to_string()],
                vuln_type: "command_injection".to_string(),
            },
            TaintSinkPattern {
                sink_type: "unsafe".to_string(),
                function_patterns: vec!["unsafe".to_string()],
                vuln_type: "unsafe_block".to_string(),
            },
        ]);

        Self { sources, sinks, sanitizers }
    }

    /// Detect taint sources in source code.
    pub fn detect_sources(&self, content: &str, file: &str, language: &str) -> Vec<TaintSource> {
        let mut found = Vec::new();
        let patterns = match self.sources.get(language) {
            Some(p) => p,
            None => return found,
        };

        for (i, line) in content.lines().enumerate() {
            let line_num = i + 1;
            for pattern in patterns {
                for func in &pattern.function_patterns {
                    if line.contains(func) {
                        // Try to extract the variable being assigned.
                        let variable = if let Some(eq_idx) = line.find('=') {
                            line[..eq_idx].trim().trim_start_matches("let ").trim_start_matches("const ").trim_start_matches("var ").trim().to_string()
                        } else {
                            func.clone()
                        };
                        found.push(TaintSource {
                            source_type: pattern.source_type.clone(),
                            function_name: func.clone(),
                            variable,
                            file: file.to_string(),
                            line: line_num,
                        });
                    }
                }
            }
        }
        found
    }

    /// Detect taint sinks in source code.
    pub fn detect_sinks(&self, content: &str, file: &str, language: &str) -> Vec<TaintSink> {
        let mut found = Vec::new();
        let patterns = match self.sinks.get(language) {
            Some(p) => p,
            None => return found,
        };

        for (i, line) in content.lines().enumerate() {
            let line_num = i + 1;
            for pattern in patterns {
                for func in &pattern.function_patterns {
                    if line.contains(func) {
                        found.push(TaintSink {
                            sink_type: pattern.sink_type.clone(),
                            function_name: func.clone(),
                            arg_index: 0,
                            file: file.to_string(),
                            line: line_num,
                        });
                    }
                }
            }
        }
        found
    }

    /// Detect sanitizers in source code.
    pub fn detect_sanitizers(&self, content: &str, file: &str, language: &str) -> Vec<Sanitizer> {
        let mut found = Vec::new();
        let patterns = match self.sanitizers.get(language) {
            Some(p) => p,
            None => return found,
        };

        for (i, line) in content.lines().enumerate() {
            let line_num = i + 1;
            for func in patterns {
                if line.contains(func) {
                    found.push(Sanitizer {
                        function_name: func.clone(),
                        file: file.to_string(),
                        line: line_num,
                    });
                }
            }
        }
        found
    }

    /// Analyze a file for taint flows.
    pub fn analyze_file(&self, content: &str, file: &str, language: &str) -> Vec<TaintFlow> {
        let sources = self.detect_sources(content, file, language);
        let sinks = self.detect_sinks(content, file, language);
        let sanitizers = self.detect_sanitizers(content, file, language);

        let mut flows = Vec::new();

        for source in &sources {
            for sink in &sinks {
                // Check if a sanitizer exists between source and sink.
                let has_sanitizer = sanitizers.iter().any(|s| s.line > source.line && s.line < sink.line);

                // Determine vuln type from sink.
                let vuln_type = self.sinks.get(language)
                    .and_then(|pats| {
                        pats.iter().find(|p| p.function_patterns.iter().any(|f| sink.function_name.contains(f)))
                            .map(|p| p.vuln_type.clone())
                    })
                    .unwrap_or("unknown".to_string());

                // Confidence: higher if source and sink are close, lower if sanitized.
                let distance = (sink.line as i64 - source.line as i64).abs();
                let mut confidence = 1.0 - (distance as f64 / 100.0).min(0.7);
                if has_sanitizer {
                    confidence *= 0.2;
                }
                if confidence < 0.1 {
                    confidence = 0.1;
                }

                flows.push(TaintFlow {
                    source: source.clone(),
                    sink: sink.clone(),
                    steps: Vec::new(),
                    is_sanitized: has_sanitizer,
                    sanitizers: if has_sanitizer {
                        sanitizers.iter().filter(|s| s.line > source.line && s.line < sink.line).cloned().collect()
                    } else {
                        Vec::new()
                    },
                    vuln_type,
                    confidence,
                });
            }
        }

        flows
    }

    /// Analyze an entire project directory for taint flows.
    pub fn analyze_project(&self, root: &Path) -> Vec<TaintFlow> {
        let mut all_flows = Vec::new();

        let walker = ignore::WalkBuilder::new(root)
            .hidden(true)
            .ignore(true)
            .git_ignore(true)
            .build();

        for entry in walker.flatten() {
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let language = match ext {
                "js" | "mjs" | "cjs" => "javascript",
                "ts" | "tsx" | "jsx" => "javascript",
                "py" => "python",
                "rs" => "rust",
                _ => continue,
            };

            // Skip common non-source directories.
            let path_str = path.to_string_lossy();
            if path_str.contains("node_modules") || path_str.contains("/target/")
                || path_str.contains("\\target\\") || path_str.contains("/dist/")
                || path_str.contains("\\dist\\")
            {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(path) {
                let file_str = path.to_string_lossy().to_string();
                let flows = self.analyze_file(&content, &file_str, language);
                all_flows.extend(flows);
            }
        }

        all_flows
    }
}

// ─── Goal 112-114: Language-Specific Taint Tracking ─────────────────────────

/// Result of JS/TS taint analysis (Goal 112).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsTaintResult {
    pub flows: Vec<TaintFlow>,
    pub xss_count: usize,
    pub sqli_count: usize,
    pub command_injection_count: usize,
    pub code_injection_count: usize,
}

/// Analyze JavaScript/TypeScript source for taint flows.
pub fn analyze_javascript(content: &str, file: &str) -> JsTaintResult {
    let analyzer = TaintAnalyzer::new();
    let flows = analyzer.analyze_file(content, file, "javascript");

    let xss_count = flows.iter().filter(|f| f.vuln_type == "xss").count();
    let sqli_count = flows.iter().filter(|f| f.vuln_type == "sqli").count();
    let command_injection_count = flows.iter().filter(|f| f.vuln_type == "command_injection").count();
    let code_injection_count = flows.iter().filter(|f| f.vuln_type == "code_injection").count();

    JsTaintResult {
        flows,
        xss_count,
        sqli_count,
        command_injection_count,
        code_injection_count,
    }
}

/// Result of Python taint analysis (Goal 113).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonTaintResult {
    pub flows: Vec<TaintFlow>,
    pub sqli_count: usize,
    pub command_injection_count: usize,
    pub ssrf_count: usize,
    pub code_injection_count: usize,
}

/// Analyze Python source for taint flows.
pub fn analyze_python(content: &str, file: &str) -> PythonTaintResult {
    let analyzer = TaintAnalyzer::new();
    let flows = analyzer.analyze_file(content, file, "python");

    let sqli_count = flows.iter().filter(|f| f.vuln_type == "sqli").count();
    let command_injection_count = flows.iter().filter(|f| f.vuln_type == "command_injection").count();
    let ssrf_count = flows.iter().filter(|f| f.vuln_type == "ssrf").count();
    let code_injection_count = flows.iter().filter(|f| f.vuln_type == "code_injection").count();

    PythonTaintResult {
        flows,
        sqli_count,
        command_injection_count,
        ssrf_count,
        code_injection_count,
    }
}

/// Result of Rust taint analysis (Goal 114).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustTaintResult {
    pub flows: Vec<TaintFlow>,
    pub command_injection_count: usize,
    pub unsafe_count: usize,
}

/// Analyze Rust source for taint flows.
pub fn analyze_rust(content: &str, file: &str) -> RustTaintResult {
    let analyzer = TaintAnalyzer::new();
    let flows = analyzer.analyze_file(content, file, "rust");

    let command_injection_count = flows.iter().filter(|f| f.vuln_type == "command_injection").count();
    let unsafe_count = flows.iter().filter(|f| f.vuln_type == "unsafe_block").count();

    RustTaintResult { flows, command_injection_count, unsafe_count }
}

// ─── Goal 115: Cross-Language Call Resolution ───────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossLanguageCall {
    pub source_language: String,
    pub target_language: String,
    pub source_function: String,
    pub target_function: String,
    pub binding_type: String,
    pub source_file: String,
    pub line: usize,
}

pub fn detect_cross_language_calls(content: &str, file: &str, language: &str) -> Vec<CrossLanguageCall> {
    let mut calls = Vec::new();
    let patterns: &[(&str, &str, &str, &[&str])] = match language {
        "javascript" => &[
            ("javascript", "rust", "napi", &["require(", "napi_", "node-addon"]),
            ("javascript", "c", "ffi", &["ffi-napi", "ref-napi", "dlopen"]),
        ],
        "python" => &[
            ("python", "c", "cffi", &["cffi", "ctypes", "CDLL"]),
            ("python", "rust", "pyo3", &["pyo3", "PyModule"]),
        ],
        "rust" => &[("rust", "c", "ffi", &["extern \"C\"", "std::ffi", "libc::"])],
        _ => &[],
    };
    for (src, tgt, binding, funcs) in patterns {
        for (i, line) in content.lines().enumerate() {
            for func in *funcs {
                if line.contains(func) {
                    calls.push(CrossLanguageCall {
                        source_language: src.to_string(), target_language: tgt.to_string(),
                        source_function: func.to_string(), target_function: String::new(),
                        binding_type: binding.to_string(), source_file: file.to_string(), line: i + 1,
                    });
                }
            }
        }
    }
    calls
}

pub fn resolve_cross_language(calls: &[CrossLanguageCall], exports: &[String]) -> Vec<CrossLanguageCall> {
    calls.iter().map(|c| {
        let mut r = c.clone();
        for e in exports { if e.contains(&c.source_function) { r.target_function = e.clone(); break; } }
        r
    }).collect()
}

// ─── Goal 116: Framework-Aware Reachability ─────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkEntry {
    pub framework: String, pub language: String, pub entry_type: String, pub pattern: String,
}

pub fn framework_entry_points() -> Vec<FrameworkEntry> {
    vec![
        FrameworkEntry { framework: "express".into(), language: "javascript".into(), entry_type: "route".into(), pattern: "app.get".into() },
        FrameworkEntry { framework: "express".into(), language: "javascript".into(), entry_type: "route".into(), pattern: "app.post".into() },
        FrameworkEntry { framework: "flask".into(), language: "python".into(), entry_type: "route".into(), pattern: "@app.route".into() },
        FrameworkEntry { framework: "fastapi".into(), language: "python".into(), entry_type: "route".into(), pattern: "@app.get".into() },
        FrameworkEntry { framework: "django".into(), language: "python".into(), entry_type: "view".into(), pattern: "@api_view".into() },
        FrameworkEntry { framework: "actix".into(), language: "rust".into(), entry_type: "handler".into(), pattern: "web::get".into() },
        FrameworkEntry { framework: "axum".into(), language: "rust".into(), entry_type: "handler".into(), pattern: "Router::new".into() },
    ]
}

pub fn detect_framework_entries(content: &str, _file: &str) -> Vec<FrameworkEntry> {
    framework_entry_points().into_iter().filter(|e| content.contains(&e.pattern)).collect()
}

// ─── Goal 117: Conditional Reachability ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalBranch {
    pub condition: String, pub line: usize, pub branches: Vec<BranchPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchPath {
    pub label: String, pub is_taken: bool, pub functions_called: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalReachabilityResult {
    pub function: String, pub is_reachable: bool,
    pub conditional_confidence: f64, pub branches: Vec<ConditionalBranch>,
    pub feature_flags: Vec<String>,
}

pub fn analyze_conditional_reachability(content: &str, target_function: &str) -> ConditionalReachabilityResult {
    let mut branches = Vec::new();
    let mut feature_flags = Vec::new();
    let mut current_condition = String::new();
    let mut current_line = 0;
    let mut branch_paths: Vec<BranchPath> = Vec::new();

    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        let line_num = i + 1;
        if trimmed.starts_with("if ") || trimmed.starts_with("if(") {
            if !current_condition.is_empty() {
                branches.push(ConditionalBranch { condition: std::mem::take(&mut current_condition), line: current_line, branches: std::mem::take(&mut branch_paths) });
            }
            current_condition = trimmed.trim_end_matches('{').to_string();
            current_line = line_num;
            branch_paths.push(BranchPath { label: "if".into(), is_taken: true, functions_called: Vec::new() });
        } else if trimmed.starts_with("else if") || trimmed.starts_with("elif ") {
            branch_paths.push(BranchPath { label: "else_if".into(), is_taken: false, functions_called: Vec::new() });
        } else if trimmed == "else" || trimmed.starts_with("else {") {
            branch_paths.push(BranchPath { label: "else".into(), is_taken: false, functions_called: Vec::new() });
        }
        if trimmed.contains("FEATURE_") || trimmed.contains("feature_flag") {
            feature_flags.push(trimmed.to_string());
        }
        if !branch_paths.is_empty() && line.contains(target_function) {
            if let Some(last) = branch_paths.last_mut() { last.functions_called.push(target_function.to_string()); }
        }
    }
    if !current_condition.is_empty() {
        branches.push(ConditionalBranch { condition: current_condition, line: current_line, branches: branch_paths });
    }
    let is_reachable = branches.iter().any(|b| b.branches.iter().any(|bp| bp.functions_called.iter().any(|f| f == target_function)));
    let conditional_confidence = if is_reachable { (1.0 - (branches.len() as f64 * 0.15)).max(0.1) } else { 0.0 };
    ConditionalReachabilityResult { function: target_function.to_string(), is_reachable, conditional_confidence, branches, feature_flags }
}

// ─── Goal 118: C/C++ Vendored Code Reachability ─────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CFunction {
    pub name: String, pub return_type: String, pub params: Vec<String>,
    pub file: String, pub line: usize, pub calls: Vec<String>,
}

pub fn parse_c_source(content: &str, file: &str) -> Vec<CFunction> {
    let mut functions = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.contains('(') && trimmed.contains(')')
            && !trimmed.starts_with("//") && !trimmed.starts_with("#")
            && !trimmed.starts_with("if") && !trimmed.starts_with("for")
            && !trimmed.starts_with("while") && !trimmed.starts_with("switch")
            && !trimmed.starts_with("return")
        {
            if let Some(paren_idx) = trimmed.find('(') {
                let before = &trimmed[..paren_idx];
                let name = before.split_whitespace().last().unwrap_or("").to_string();
                if !name.is_empty() {
                    let mut calls: Vec<String> = Vec::new();
                    let mut j = i + 1;
                    let mut brace_count = 1;
                    while j < lines.len() && brace_count > 0 {
                        let inner = lines[j].trim();
                        if inner.contains('{') { brace_count += 1; }
                        if inner.contains('}') { brace_count -= 1; }
                        for word in inner.split(|c: char| !c.is_alphanumeric() && c != '_') {
                            if !word.is_empty() && word != name && inner.contains(&format!("{}(", word)) && !calls.iter().any(|c| c == word) {
                                calls.push(word.to_string());
                            }
                        }
                        j += 1;
                    }
                    functions.push(CFunction {
                        name: name.clone(), return_type: before.split_whitespace().next().unwrap_or("void").to_string(),
                        params: Vec::new(), file: file.to_string(), line: i + 1, calls,
                    });
                }
            }
        }
        i += 1;
    }
    functions
}

pub fn build_c_call_graph(root: &Path) -> HashMap<String, Vec<String>> {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    let walker = ignore::WalkBuilder::new(root).hidden(true).git_ignore(true).build();
    for entry in walker.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) { continue; }
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !["c", "cpp", "cc", "h", "hpp"].contains(&ext) { continue; }
        if let Ok(content) = std::fs::read_to_string(path) {
            for func in parse_c_source(&content, &path.to_string_lossy()) {
                graph.insert(func.name, func.calls);
            }
        }
    }
    graph
}

// ─── Goal 119: Interprocedural Analysis ─────────────────────────────────────

use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterproceduralNode {
    pub function: String, pub file: String, pub line: usize,
    pub callees: Vec<String>, pub is_entry: bool,
}

pub fn build_interprocedural_graph(root: &Path) -> Vec<InterproceduralNode> {
    let mut nodes = Vec::new();
    let mut file_functions: HashMap<PathBuf, Vec<(String, usize, Vec<String>, bool)>> = HashMap::new();
    let walker = ignore::WalkBuilder::new(root).hidden(true).git_ignore(true).build();
    for entry in walker.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) { continue; }
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !["js","ts","jsx","tsx","mjs","cjs","py","rs","go","java"].contains(&ext) { continue; }
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Some(p) = crate::tree_sitter_parser::parse_source(&content, path) {
                let funcs: Vec<(String, usize, Vec<String>, bool)> = p.functions.iter()
                    .map(|f| (f.name.clone(), f.line, f.calls.iter().map(|c| c.target.clone()).collect(), f.is_entry))
                    .collect();
                file_functions.insert(path.to_path_buf(), funcs);
            }
        }
    }
    let mut global_functions: HashMap<String, String> = HashMap::new();
    for (path, funcs) in &file_functions {
        for (name, _, _, _) in funcs {
            global_functions.entry(name.clone()).or_insert_with(|| path.to_string_lossy().to_string());
        }
    }
    for (path, funcs) in &file_functions {
        for (name, line, calls, is_entry) in funcs {
            let resolved: Vec<String> = calls.iter().map(|c| {
                global_functions.get(c).map(|f| format!("{}::{}", f, c)).unwrap_or_else(|| c.clone())
            }).collect();
            nodes.push(InterproceduralNode {
                function: name.clone(), file: path.to_string_lossy().to_string(),
                line: *line, callees: resolved, is_entry: *is_entry,
            });
        }
    }
    nodes
}

pub fn find_interprocedural_paths(nodes: &[InterproceduralNode], target: &str) -> Vec<Vec<String>> {
    let mut paths = Vec::new();
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    let mut entries: Vec<String> = Vec::new();
    for node in nodes {
        let key = format!("{}::{}", node.file, node.function);
        if node.is_entry { entries.push(key.clone()); }
        graph.insert(key, node.callees.clone());
    }
    for entry in &entries {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
        queue.push_back((entry.clone(), vec![entry.clone()]));
        while let Some((current, path)) = queue.pop_front() {
            if current.contains(target) { paths.push(path); continue; }
            if !visited.insert(current.clone()) { continue; }
            if let Some(callees) = graph.get(&current) {
                for callee in callees {
                    if !visited.contains(callee) {
                        let mut np = path.clone(); np.push(callee.clone());
                        queue.push_back((callee.clone(), np));
                    }
                }
            }
        }
    }
    paths
}

// ─── Goal 120: Reachability Caching with CAS ────────────────────────────────

pub struct ReachabilityCache {
    cache_dir: PathBuf,
    index: HashMap<String, String>,
}

impl ReachabilityCache {
    pub fn new(cache_dir: &Path) -> Result<Self, TaintError> {
        std::fs::create_dir_all(cache_dir)?;
        let index_path = cache_dir.join("index.json");
        let index = if index_path.exists() {
            serde_json::from_str(&std::fs::read_to_string(&index_path)?).unwrap_or_default()
        } else { HashMap::new() };
        Ok(Self { cache_dir: cache_dir.to_path_buf(), index })
    }

    pub fn content_hash(content: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(content.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    pub fn is_cached(&self, file_path: &str, content: &str) -> bool {
        self.index.get(file_path) == Some(&Self::content_hash(content))
    }

    pub fn get(&self, file_path: &str) -> Option<String> {
        let hash = self.index.get(file_path)?;
        std::fs::read_to_string(self.cache_dir.join(format!("{}.json", hash))).ok()
    }

    pub fn put(&mut self, file_path: &str, content: &str, result: &str) -> Result<(), TaintError> {
        let hash = Self::content_hash(content);
        std::fs::write(self.cache_dir.join(format!("{}.json", hash)), result)?;
        self.index.insert(file_path.to_string(), hash);
        std::fs::write(self.cache_dir.join("index.json"), serde_json::to_string_pretty(&self.index)?)?;
        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), TaintError> {
        self.index.clear();
        let index_path = self.cache_dir.join("index.json");
        if index_path.exists() { std::fs::remove_file(&index_path)?; }
        for entry in std::fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("json") { let _ = std::fs::remove_file(&p); }
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize { self.index.len() }
    pub fn is_empty(&self) -> bool { self.index.is_empty() }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Goal 111 tests

    #[test]
    fn test_detect_sources_javascript() {
        let code = "const name = req.query.name;";
        let analyzer = TaintAnalyzer::new();
        let sources = analyzer.detect_sources(code, "test.js", "javascript");
        assert!(sources.iter().any(|s| s.function_name == "req.query"));
    }

    #[test]
    fn test_detect_sinks_javascript() {
        let code = "db.query('SELECT * FROM users');";
        let analyzer = TaintAnalyzer::new();
        let sinks = analyzer.detect_sinks(code, "test.js", "javascript");
        assert!(sinks.iter().any(|s| s.function_name == "db.query"));
    }

    #[test]
    fn test_analyze_file_xss_flow() {
        let code = "app.get('/', (req, res) => { const name = req.query.name; res.send(name); });";
        let analyzer = TaintAnalyzer::new();
        let flows = analyzer.analyze_file(code, "test.js", "javascript");
        assert!(flows.iter().any(|f| f.vuln_type == "xss"));
    }

    #[test]
    fn test_analyze_file_sanitized() {
        let code = "const name = req.query.name;\nconst safe = escapeHtml(name);\nres.send(safe);";
        let analyzer = TaintAnalyzer::new();
        let flows = analyzer.analyze_file(code, "test.js", "javascript");
        assert!(flows.iter().any(|f| f.is_sanitized));
    }

    // Goal 112 tests

    #[test]
    fn test_analyze_javascript() {
        let code = "const cmd = req.body.cmd;\nchild_process.exec(cmd);";
        let result = analyze_javascript(code, "test.js");
        assert!(result.command_injection_count > 0);
    }

    // Goal 113 tests

    #[test]
    fn test_analyze_python_sqli() {
        let code = "q = request.args.get('q')\ncursor.execute('SELECT * FROM items WHERE name=' + q)";
        let result = analyze_python(code, "test.py");
        assert!(result.sqli_count > 0);
    }

    #[test]
    fn test_analyze_python_ssrf() {
        let code = "url = request.args.get('url')\nresponse = requests.get(url)";
        let result = analyze_python(code, "test.py");
        assert!(result.ssrf_count > 0);
    }

    // Goal 114 tests

    #[test]
    fn test_analyze_rust_unsafe() {
        let code = "let input = std::env::args().nth(1).unwrap();\nunsafe { println!(\"{}\", input); }";
        let result = analyze_rust(code, "test.rs");
        assert!(result.unsafe_count > 0);
    }

    // Goal 115 tests

    #[test]
    fn test_detect_cross_language_js_rust() {
        let calls = detect_cross_language_calls("require('./native')", "test.js", "javascript");
        assert!(calls.iter().any(|c| c.target_language == "rust"));
    }

    #[test]
    fn test_detect_cross_language_python_c() {
        let calls = detect_cross_language_calls("from ctypes import CDLL", "test.py", "python");
        assert!(calls.iter().any(|c| c.target_language == "c"));
    }

    #[test]
    fn test_resolve_cross_language() {
        let calls = vec![CrossLanguageCall {
            source_language: "js".into(), target_language: "rust".into(),
            source_function: "my_func".into(), target_function: String::new(),
            binding_type: "napi".into(), source_file: "test.js".into(), line: 1,
        }];
        let resolved = resolve_cross_language(&calls, &["my_func".to_string()]);
        assert_eq!(resolved[0].target_function, "my_func");
    }

    // Goal 116 tests

    #[test]
    fn test_framework_entry_points() {
        let entries = framework_entry_points();
        assert!(entries.iter().any(|e| e.framework == "express"));
        assert!(entries.iter().any(|e| e.framework == "actix"));
    }

    #[test]
    fn test_detect_framework_entries() {
        let entries = detect_framework_entries("app.get('/', handler)", "test.js");
        assert!(entries.iter().any(|e| e.framework == "express"));
    }

    // Goal 117 tests

    #[test]
    fn test_conditional_reachability_reachable() {
        let code = "if (enabled) { vulnerable_func(); }";
        let result = analyze_conditional_reachability(code, "vulnerable_func");
        assert!(result.is_reachable);
    }

    #[test]
    fn test_conditional_reachability_not_reachable() {
        let code = "if (enabled) { safe_func(); }";
        let result = analyze_conditional_reachability(code, "vulnerable_func");
        assert!(!result.is_reachable);
    }

    #[test]
    fn test_conditional_reachability_feature_flag() {
        let code = "if (FEATURE_NEW_API) { vulnerable_func(); }";
        let result = analyze_conditional_reachability(code, "vulnerable_func");
        assert!(!result.feature_flags.is_empty());
    }

    // Goal 118 tests

    #[test]
    fn test_parse_c_source() {
        let code = "void vulnerable(char *input) {\n    system(input);\n}\nint main() {\n    vulnerable(buf);\n}";
        let functions = parse_c_source(code, "test.c");
        assert!(functions.iter().any(|f| f.name == "vulnerable"));
        let vuln = functions.iter().find(|f| f.name == "vulnerable").unwrap();
        assert!(vuln.calls.contains(&"system".to_string()));
    }

    #[test]
    fn test_build_c_call_graph() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("test.c"), "void foo() { bar(); }\nvoid bar() {}\n").unwrap();
        let graph = build_c_call_graph(tmp.path());
        assert!(graph.contains_key("foo"));
    }

    // Goal 119 tests

    #[test]
    fn test_find_interprocedural_paths() {
        let nodes = vec![
            InterproceduralNode { function: "main".into(), file: "app.rs".into(), line: 1, callees: vec!["lib.rs::process".into()], is_entry: true },
            InterproceduralNode { function: "process".into(), file: "lib.rs".into(), line: 10, callees: vec!["lib.rs::vulnerable_func".into()], is_entry: false },
        ];
        let paths = find_interprocedural_paths(&nodes, "vulnerable_func");
        assert!(!paths.is_empty());
    }

    #[test]
    fn test_find_interprocedural_paths_not_found() {
        let nodes = vec![
            InterproceduralNode { function: "main".into(), file: "app.rs".into(), line: 1, callees: vec!["safe".into()], is_entry: true },
        ];
        let paths = find_interprocedural_paths(&nodes, "vulnerable");
        assert!(paths.is_empty());
    }

    // Goal 120 tests

    #[test]
    fn test_reachability_cache_put_get() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cache = ReachabilityCache::new(tmp.path()).unwrap();
        let content = "fn foo() { bar(); }";
        let result = "{\"reachable\": true}";
        assert!(!cache.is_cached("src/main.rs", content));
        cache.put("src/main.rs", content, result).unwrap();
        assert!(cache.is_cached("src/main.rs", content));
        assert_eq!(cache.get("src/main.rs").unwrap(), result);
    }

    #[test]
    fn test_reachability_cache_changed_content() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cache = ReachabilityCache::new(tmp.path()).unwrap();
        cache.put("file.rs", "fn foo() {}", "result1").unwrap();
        assert!(!cache.is_cached("file.rs", "fn bar() {}"));
        assert!(cache.is_cached("file.rs", "fn foo() {}"));
    }

    #[test]
    fn test_reachability_cache_clear() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cache = ReachabilityCache::new(tmp.path()).unwrap();
        cache.put("file.rs", "content", "result").unwrap();
        assert_eq!(cache.len(), 1);
        cache.clear().unwrap();
        assert!(cache.is_empty());
    }
}
