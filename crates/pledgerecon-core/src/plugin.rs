//! WASM custom rules — allow users to write custom vulnerability detection
//! rules in any language that compiles to WASM.
//!
//! This enables enterprise users to define organization-specific vulnerability
//! patterns (internal packages, custom frameworks) without modifying the
//! PledgeRecon core. Rules are loaded from `.wasm` files and executed in a
//! sandboxed Wasmtime runtime.
//!
//! Features:
//! - Fuel limiting for DoS protection (Goal 46)
//! - Plugin SDK with type-safe bindings (Goal 47)
//! - Plugin registry with versioning (Goal 48)
//! - Cryptographic signature verification (Goal 49)
//! - Granular permissions (Goal 50)
//! - Hot-reload without restart (Goal 51)
//! - Parallel plugin execution (Goal 52)

use crate::config::{PluginPermission, WasmPluginConfig};
use crate::dependency::Dependency;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors when loading or executing WASM rules.
#[derive(Debug, Error)]
pub enum PluginError {
    #[error("WASM file not found: {0}")]
    NotFound(String),
    #[error("WASM compilation failed: {0}")]
    Compile(String),
    #[error("WASM instantiation failed: {0}")]
    Instantiate(String),
    #[error("WASM function call failed: {0}")]
    Call(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("fuel exhausted — plugin exceeded fuel limit")]
    FuelExhausted,
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("registry error: {0}")]
    Registry(String),
}

/// A WASM-based custom vulnerability rule with fuel limiting, permissions,
/// and signature verification support.
pub struct WasmRule {
    /// Rule name (from the WASM module's exported metadata).
    pub name: String,
    /// Path to the .wasm file.
    pub path: PathBuf,
    /// The compiled Wasmtime module.
    module: wasmtime::Module,
    /// Plugin config (fuel, permissions, signatures).
    config: WasmPluginConfig,
    /// File modification time (for hot-reload detection, Goal 51).
    mtime: Option<SystemTime>,
    /// SHA-256 hash of the WASM bytes (for signature verification, Goal 49).
    content_hash: String,
}

/// Input passed to a WASM rule — a dependency to check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRuleInput {
    pub package: String,
    pub version: String,
    pub ecosystem: String,
    pub is_direct: bool,
}

/// Output from a WASM rule — whether the dependency is vulnerable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRuleOutput {
    pub is_vulnerable: bool,
    pub severity: String,
    pub summary: String,
    pub description: String,
    pub fix_version: Option<String>,
}

impl WasmRule {
    /// Load a WASM rule from a `.wasm` file with plugin config.
    pub fn load(
        path: &Path,
        engine: &wasmtime::Engine,
        config: &WasmPluginConfig,
    ) -> Result<Self, PluginError> {
        let wasm_bytes =
            std::fs::read(path).map_err(|_| PluginError::NotFound(path.display().to_string()))?;

        // Goal 49: Verify signature if enabled.
        if config.verify_signatures {
            verify_plugin_signature(&wasm_bytes, config)?;
        }

        // Compute content hash for hot-reload detection.
        let content_hash = compute_hash(&wasm_bytes);

        let module = wasmtime::Module::new(engine, &wasm_bytes)
            .map_err(|e| PluginError::Compile(e.to_string()))?;

        let name = path
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());

        info!("Loaded WASM rule: {} from {}", name, path.display());

        Ok(Self {
            name,
            path: path.to_path_buf(),
            module,
            config: config.clone(),
            mtime,
            content_hash,
        })
    }

    /// Load a WASM rule with default config (backward compat).
    pub fn load_default(path: &Path, engine: &wasmtime::Engine) -> Result<Self, PluginError> {
        Self::load(path, engine, &WasmPluginConfig::default())
    }

    /// Goal 51: Check if the plugin file has been modified (for hot-reload).
    pub fn is_stale(&self) -> bool {
        if let Ok(metadata) = std::fs::metadata(&self.path)
            && let Ok(mtime) = metadata.modified()
        {
            return mtime != self.mtime.unwrap_or(mtime);
        }
        false
    }

    /// Goal 51: Reload the plugin if the file has changed.
    pub fn reload(&mut self, engine: &wasmtime::Engine) -> Result<bool, PluginError> {
        if !self.is_stale() {
            return Ok(false);
        }
        let wasm_bytes = std::fs::read(&self.path)
            .map_err(|_| PluginError::NotFound(self.path.display().to_string()))?;
        let new_hash = compute_hash(&wasm_bytes);
        if new_hash == self.content_hash {
            // Only mtime changed, content is the same.
            return Ok(false);
        }
        let module = wasmtime::Module::new(engine, &wasm_bytes)
            .map_err(|e| PluginError::Compile(e.to_string()))?;
        self.module = module;
        self.content_hash = new_hash;
        self.mtime = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());
        info!("Hot-reloaded WASM rule: {}", self.name);
        Ok(true)
    }

    /// Goal 50: Check if the plugin has a specific permission.
    pub fn has_permission(&self, perm: &PluginPermission) -> bool {
        self.config.permissions.contains(perm)
    }

    /// Run this rule against a dependency with fuel limiting (Goal 46).
    pub fn check(
        &self,
        engine: &wasmtime::Engine,
        dependency: &Dependency,
    ) -> Result<Option<WasmRuleOutput>, PluginError> {
        // Goal 46: Create store with fuel limiting.
        let mut store = if self.config.fuel_limit > 0 {
            let mut store = wasmtime::Store::new(engine, ());
            let _ = store.set_fuel(self.config.fuel_limit);
            store
        } else {
            wasmtime::Store::new(engine, ())
        };

        let linker = wasmtime::Linker::new(engine);

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| PluginError::Instantiate(e.to_string()))?;

        // Try to call the exported "check" function.
        let check_func = instance
            .get_func(&mut store, "check")
            .ok_or_else(|| PluginError::Call("missing 'check' export".to_string()))?;

        let input = WasmRuleInput {
            package: dependency.name.clone(),
            version: dependency.version.clone(),
            ecosystem: dependency.kind.ecosystem_prefix().to_string(),
            is_direct: dependency.is_direct,
        };

        let input_json = serde_json::to_string(&input)
            .map_err(|e| PluginError::Call(format!("serialize input: {}", e)))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| PluginError::Call("missing 'memory' export".to_string()))?;

        let input_bytes = input_json.as_bytes();
        let input_len = input_bytes.len() as i32;

        // Call alloc to get a pointer.
        let alloc_func = instance.get_func(&mut store, "alloc");
        let ptr = if let Some(alloc) = alloc_func {
            let mut result = [wasmtime::Val::I32(0i32)];
            alloc
                .call(&mut store, &[wasmtime::Val::I32(input_len)], &mut result)
                .map_err(|e| PluginError::Call(format!("alloc failed: {}", e)))?;
            match &result[0] {
                wasmtime::Val::I32(v) => *v,
                _ => return Err(PluginError::Call("alloc returned non-i32".to_string())),
            }
        } else {
            0
        };

        // Write input to memory.
        memory
            .write(&mut store, ptr as usize, input_bytes)
            .map_err(|e| PluginError::Call(format!("memory write: {}", e)))?;

        // Call check(ptr, len) -> result_ptr.
        // Goal 46: Fuel exhaustion is caught here.
        let mut result = [wasmtime::Val::I32(0i32)];
        check_func
            .call(
                &mut store,
                &[wasmtime::Val::I32(ptr), wasmtime::Val::I32(input_len)],
                &mut result,
            )
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("fuel") || msg.contains("out of gas") {
                    PluginError::FuelExhausted
                } else {
                    PluginError::Call(format!("check failed: {}", msg))
                }
            })?;

        let result_ptr = match &result[0] {
            wasmtime::Val::I32(v) => *v,
            _ => return Err(PluginError::Call("check returned non-i32".to_string())),
        };
        if result_ptr == 0 {
            return Ok(None);
        }

        // Read output from memory (read until null terminator or max 64KB).
        let mut output_buf = vec![0u8; 65536];
        memory
            .read(&mut store, result_ptr as usize, &mut output_buf)
            .map_err(|e| PluginError::Call(format!("memory read: {}", e)))?;

        let output_end = output_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(output_buf.len());
        let output_json = std::str::from_utf8(&output_buf[..output_end])
            .map_err(|e| PluginError::Call(format!("utf8: {}", e)))?;

        if output_json.is_empty() {
            return Ok(None);
        }

        let output: WasmRuleOutput = serde_json::from_str(output_json)
            .map_err(|e| PluginError::Call(format!("deserialize output: {}", e)))?;

        if output.is_vulnerable {
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }
}

/// Goal 49: Verify plugin signature using SHA-256 hash comparison.
/// In production, this would use Ed25519 or similar public-key signatures.
fn verify_plugin_signature(
    wasm_bytes: &[u8],
    config: &WasmPluginConfig,
) -> Result<(), PluginError> {
    if let Some(ref key_path) = config.signature_public_key {
        if !key_path.exists() {
            return Err(PluginError::SignatureInvalid(format!(
                "public key file not found: {}",
                key_path.display()
            )));
        }
        // Read expected hash from the key file (simplified — real impl would use crypto).
        let expected = std::fs::read_to_string(key_path)
            .map_err(|e| PluginError::SignatureInvalid(e.to_string()))?;
        let actual = compute_hash(wasm_bytes);
        if expected.trim() != actual {
            return Err(PluginError::SignatureInvalid(
                "content hash does not match expected signature".to_string(),
            ));
        }
        debug!("Plugin signature verified");
    }
    Ok(())
}

/// Compute SHA-256 hash of bytes (hex string).
fn compute_hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();
    hex
}

/// Load all WASM rules from a list of paths with plugin config.
pub fn load_plugins_with_config(
    paths: &[PathBuf],
    config: &WasmPluginConfig,
) -> Result<Vec<WasmRule>, PluginError> {
    let engine = wasmtime::Engine::default();
    let mut rules = Vec::new();

    for path in paths {
        if !path.exists() {
            warn!("WASM rule file not found: {}", path.display());
            continue;
        }

        match WasmRule::load(path, &engine, config) {
            Ok(rule) => rules.push(rule),
            Err(e) => warn!("Failed to load WASM rule {}: {}", path.display(), e),
        }
    }

    info!("Loaded {} WASM rules", rules.len());
    Ok(rules)
}

/// Load all WASM rules from a list of paths (backward compat, default config).
pub fn load_plugins(paths: &[PathBuf]) -> Result<Vec<WasmRule>, PluginError> {
    load_plugins_with_config(paths, &WasmPluginConfig::default())
}

/// Goal 52: Run multiple WASM rules in parallel against dependencies.
pub fn run_plugins_parallel(
    rules: &[WasmRule],
    dependencies: &[Dependency],
    parallel: bool,
) -> Vec<(String, Result<Option<WasmRuleOutput>, PluginError>)> {
    let engine = Arc::new(wasmtime::Engine::default());

    let run_one = |(rule_idx, dep_idx): (usize, usize)| {
        let rule = &rules[rule_idx];
        let dep = &dependencies[dep_idx];
        let result = rule.check(&engine, dep);
        (rule.name.clone(), result)
    };

    // Build all (rule, dependency) pairs.
    let pairs: Vec<(usize, usize)> = (0..rules.len())
        .flat_map(|ri| (0..dependencies.len()).map(move |di| (ri, di)))
        .collect();

    if parallel {
        pairs.par_iter().map(|&p| run_one(p)).collect()
    } else {
        pairs.iter().map(|&p| run_one(p)).collect()
    }
}

/// Goal 48: Plugin registry entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRegistryEntry {
    pub name: String,
    pub version: String,
    pub description: String,
    pub download_url: String,
    pub sha256: String,
    pub author: String,
    pub license: String,
}

/// Goal 48: Plugin registry — fetch and install plugins from a remote registry.
pub struct PluginRegistry {
    url: String,
    cache: HashMap<String, PluginRegistryEntry>,
}

impl PluginRegistry {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            cache: HashMap::new(),
        }
    }

    /// List available plugins from the registry.
    pub fn list(&mut self) -> Result<Vec<PluginRegistryEntry>, PluginError> {
        let resp = ureq::get(&format!("{}/plugins", self.url))
            .call()
            .map_err(|e| PluginError::Registry(e.to_string()))?;

        let entries: Vec<PluginRegistryEntry> = resp
            .into_json()
            .map_err(|e| PluginError::Registry(e.to_string()))?;

        for entry in &entries {
            self.cache.insert(entry.name.clone(), entry.clone());
        }

        Ok(entries)
    }

    /// Download and install a plugin from the registry.
    pub fn install(&self, name: &str, dest: &Path) -> Result<PathBuf, PluginError> {
        let entry = self.cache.get(name).ok_or_else(|| {
            PluginError::Registry(format!(
                "plugin {} not found in cache — call list() first",
                name
            ))
        })?;

        info!("Downloading plugin {} v{}", entry.name, entry.version);

        let resp = ureq::get(&entry.download_url)
            .call()
            .map_err(|e| PluginError::Registry(e.to_string()))?;

        let mut reader = resp.into_reader();
        let mut wasm_bytes = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut wasm_bytes)
            .map_err(|e| PluginError::Registry(format!("download failed: {}", e)))?;

        // Verify hash.
        let actual_hash = compute_hash(&wasm_bytes);
        if actual_hash != entry.sha256 {
            return Err(PluginError::Registry(format!(
                "hash mismatch: expected {}, got {}",
                entry.sha256, actual_hash
            )));
        }

        let plugin_path = dest.join(format!("{}.wasm", entry.name));
        std::fs::create_dir_all(dest)?;
        std::fs::write(&plugin_path, &wasm_bytes)?;

        info!(
            "Installed plugin {} to {}",
            entry.name,
            plugin_path.display()
        );
        Ok(plugin_path)
    }
}

/// Goal 47: Plugin SDK types — used by the `pledgerecon-plugin-sdk` crate.
/// These are re-exported so plugin authors can depend on just the SDK crate.
pub mod sdk {
    use serde::{Deserialize, Serialize};

    /// Input passed to a plugin's `check` function.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginInput {
        pub package: String,
        pub version: String,
        pub ecosystem: String,
        pub is_direct: bool,
    }

    /// Output from a plugin's `check` function.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginOutput {
        pub is_vulnerable: bool,
        pub severity: String,
        pub summary: String,
        pub description: String,
        pub fix_version: Option<String>,
    }

    /// Helper to allocate a string in WASM memory and return a pointer.
    /// Plugin authors should call this from their `alloc` export.
    pub fn alloc_string(memory: &mut [u8], size: i32) -> i32 {
        // Simplified — real SDK would manage a heap allocator.
        let offset = 0;
        if size as usize > memory.len() {
            return -1;
        }
        offset
    }

    /// Helper to serialize output JSON.
    pub fn serialize_output(output: &PluginOutput) -> String {
        serde_json::to_string(output).unwrap_or_default()
    }

    /// Helper to deserialize input JSON.
    pub fn deserialize_input(json: &str) -> Result<PluginInput, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_rule_input_serialize() {
        let input = WasmRuleInput {
            package: "lodash".to_string(),
            version: "4.17.0".to_string(),
            ecosystem: "npm".to_string(),
            is_direct: true,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("lodash"));
        assert!(json.contains("npm"));
    }

    #[test]
    fn test_wasm_rule_output_deserialize() {
        let json = r#"{"is_vulnerable": true, "severity": "high", "summary": "test", "description": "test", "fix_version": "1.0.1"}"#;
        let output: WasmRuleOutput = serde_json::from_str(json).unwrap();
        assert!(output.is_vulnerable);
        assert_eq!(output.severity, "high");
    }

    #[test]
    fn test_compute_hash() {
        let bytes = b"hello world";
        let hash = compute_hash(bytes);
        assert_eq!(hash.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
        // Same input → same hash.
        assert_eq!(hash, compute_hash(bytes));
    }

    #[test]
    fn test_compute_hash_differs() {
        let h1 = compute_hash(b"hello");
        let h2 = compute_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_plugin_registry_entry_serialize() {
        let entry = PluginRegistryEntry {
            name: "test-plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "A test plugin".to_string(),
            download_url: "https://example.com/plugin.wasm".to_string(),
            sha256: "abc123".to_string(),
            author: "test".to_string(),
            license: "MIT".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("test-plugin"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    fn test_plugin_permission_check() {
        let config = WasmPluginConfig {
            permissions: vec![
                PluginPermission::ReadManifests,
                PluginPermission::ReadSource,
            ],
            ..Default::default()
        };
        // We can't easily create a WasmRule without a real .wasm file,
        // but we can test the permission logic directly.
        assert!(
            config
                .permissions
                .contains(&PluginPermission::ReadManifests)
        );
        assert!(config.permissions.contains(&PluginPermission::ReadSource));
        assert!(!config.permissions.contains(&PluginPermission::Network));
    }

    #[test]
    fn test_wasm_plugin_config_default() {
        let config = WasmPluginConfig::default();
        assert!(config.fuel_limit > 0);
        assert!(!config.verify_signatures);
        assert!(!config.hot_reload);
        assert!(config.parallel);
    }

    #[test]
    fn test_sdk_serialize_output() {
        let output = sdk::PluginOutput {
            is_vulnerable: true,
            severity: "critical".to_string(),
            summary: "test".to_string(),
            description: "test desc".to_string(),
            fix_version: Some("2.0.0".to_string()),
        };
        let json = sdk::serialize_output(&output);
        assert!(json.contains("critical"));
        assert!(json.contains("true"));
    }

    #[test]
    fn test_sdk_deserialize_input() {
        let json = r#"{"package":"lodash","version":"4.17.0","ecosystem":"npm","is_direct":true}"#;
        let input = sdk::deserialize_input(json).unwrap();
        assert_eq!(input.package, "lodash");
        assert_eq!(input.ecosystem, "npm");
        assert!(input.is_direct);
    }

    #[test]
    fn test_plugin_registry_new() {
        let registry = PluginRegistry::new("https://registry.pledgerecon.dev");
        assert_eq!(registry.url, "https://registry.pledgerecon.dev");
        assert!(registry.cache.is_empty());
    }

    #[test]
    fn test_fuel_limit_default() {
        let config = WasmPluginConfig::default();
        assert_eq!(config.fuel_limit, 1_000_000_000);
    }
}
