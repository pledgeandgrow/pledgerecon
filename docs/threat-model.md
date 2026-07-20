# Threat Model

## Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│                    User Machine                      │
│                                                     │
│  ┌─────────────┐    ┌──────────────┐               │
│  │  Source Code │    │  Manifests   │               │
│  │  (trusted)   │    │  (trusted)   │               │
│  └──────┬───────┘    └──────┬───────┘               │
│         │                   │                       │
│         ↓                   ↓                       │
│  ┌──────────────────────────────────┐               │
│  │       PledgeRecon Scanner         │  ← TRUSTED   │
│  │     (Rust binary, local)          │               │
│  └──────────┬────────────────────────┘               │
│             │                                       │
│     ┌───────┴───────┐                               │
│     ↓               ↓                               │
│  ┌──────┐    ┌──────────────┐                       │
│  │ OSV  │    │   GHSA API   │  ← UNTRUSTED          │
│  │ API  │    │  (GitHub)    │    (network)          │
│  └──────┘    └──────────────┘                       │
│                                                     │
│     ┌───────────────┐                               │
│     │   LLM API     │  ← UNTRUSTED                  │
│     │ (OpenAI/etc)  │    (network)                  │
│     └───────────────┘                               │
│                                                     │
│     ┌───────────────┐                               │
│     │  WASM Rules   │  ← SEMI-TRUSTED               │
│     │  (.wasm files)│    (sandboxed)                │
│     └───────────────┘                               │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Assets

1. **Source code** — Parsed for call graph building. Not sent to any external service.
2. **Dependency manifests** — Parsed locally. Package names/versions may be sent to OSV/GHSA APIs.
3. **Advisory data** — Fetched from public APIs, cached locally.
4. **Vulnerability findings** — Generated locally. May be sent to LLM for triage (metadata only, no source code).
5. **SBOM** — Generated locally from dependency graph.

## Threats & Mitigations

### T1: Malicious Advisory Data
- **Threat**: Advisory API returns crafted data to cause false negatives or false positives
- **Mitigation**: Advisory data is parsed with strict JSON validation. Severity and version ranges are validated. Multiple sources can be cross-referenced.
- **Residual risk**: Low — advisories are public data from reputable sources

### T2: LLM Data Exfiltration
- **Threat**: LLM provider receives sensitive project information
- **Mitigation**: Only vulnerability metadata is sent (advisory ID, package name, version, severity). No source code, no secrets, no internal package names beyond what's in public manifests.
- **Mitigation**: Ollama option for fully local triage (no data leaves the machine)
- **Residual risk**: Low — package names and versions are already public

### T3: Malicious WASM Rule
- **Threat**: WASM rule module attempts to access file system, network, or exfiltrate data
- **Mitigation**: Wasmtime sandbox — no host access by default. WASM modules cannot read files, make network requests, or access environment variables.
- **Residual risk**: Very low — Wasmtime is a production-grade sandbox

### T4: Supply Chain Attack on PledgeRecon
- **Threat**: PledgeRecon binary itself is compromised
- **Mitigation**: Open source (MIT), reproducible builds, `cargo-deny` for dependency auditing, Rust memory safety
- **Residual risk**: Standard for any tool — verify checksums, build from source

### T5: Cache Poisoning
- **Threat**: Local advisory cache is modified to suppress vulnerabilities
- **Mitigation**: Cache is JSON, human-readable, can be verified against upstream sources. `--offline` flag is explicit.
- **Residual risk**: Low — cache is local, user-controlled

### T6: Regex Injection in Call Graph Parsing
- **Threat**: Malicious source code contains patterns that cause regex catastrophic backtracking
- **Mitigation**: Regex patterns are simple and anchored. Source code is trusted (it's the user's own code).
- **Residual risk**: Very low

### T7: API Key Leakage
- **Threat**: LLM API keys or GitHub tokens are exposed
- **Mitigation**: Keys are stored in `pledgerecon.toml` (should be gitignored) or environment variables. Keys are never logged. `tracing` output redacts sensitive values.
- **Residual risk**: Low — standard secret management practices apply

## Security Recommendations

1. **Add `pledgerecon.toml` to `.gitignore`** if it contains API keys
2. **Use environment variables** for API keys instead of config files
3. **Use Ollama** for triage if source code confidentiality is critical
4. **Verify WASM rules** before use — only run rules from trusted sources
5. **Pin PledgeRecon version** in CI for reproducible scans
6. **Review ignore rules** periodically — expired rules automatically re-enable findings
7. **Use `--offline`** in CI with a pre-populated cache for deterministic results
