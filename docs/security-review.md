# PledgeRecon Security Review Preparation

## Overview

This document outlines the preparation for an external security review of PledgeRecon.
It serves as a guide for reviewers and tracks completed and pending security hardening items.

## Architecture Summary

PledgeRecon is a Rust-native dependency vulnerability scanner with the following trust boundaries:

1. **User input** — project directories, config files, manifest files (untrusted)
2. **Network APIs** — OSV.dev, GHSA, NVD, EPSS, CISA KEV (semi-trusted)
3. **LLM providers** — OpenAI, Anthropic, Ollama (semi-trusted, user-configured)
4. **WASM plugins** — user-supplied rules (untrusted, sandboxed)
5. **Output** — JSON, SARIF, SBOM, reports (trusted, generated)

## Security Measures Already in Place

### Input Validation
- All manifest parsing uses dedicated parsers (toml, serde_json, serde_yaml) with error handling
- Regex patterns are compiled with error handling — invalid patterns won't crash
- File paths are validated before I/O operations
- Advisory cache uses SHA-256 checksums for integrity verification

### Network Security
- All HTTP calls use `ureq` with TLS (HTTPS endpoints only)
- API keys are optional and never logged
- GitHub token passed via Authorization header, not URL
- NVD API key passed via header, not URL
- Advisory cache supports offline mode (no network calls when `offline: true`)

### Secrets Handling
- Secret scanning detects patterns but does NOT transmit raw secrets to any API
- Secret verification checks format only (prefix/length) — does NOT call cloud APIs to verify
- Secret fingerprints use SHA-256 hashing for deduplication
- Raw secret values are not included in reports by default

### WASM Sandbox
- WASM plugins run in wasmtime sandbox with resource limits
- Plugins cannot access filesystem, network, or host processes
- Plugin execution is timeout-bounded

### Memory Safety
- Rust's type system prevents buffer overflows, use-after-free, null dereferences
- `unsafe` code is avoided throughout the codebase
- No `unwrap()` calls in production code paths (only in tests)

## Items for External Review

### High Priority
- [ ] Review all `ureq` HTTP calls for SSRF vulnerabilities (user-controlled URLs in config)
- [ ] Audit WASM sandbox configuration for escape vectors
- [ ] Review regex patterns for ReDoS (Regular Expression Denial of Service)
- [ ] Audit LLM prompt construction for prompt injection via advisory descriptions
- [ ] Review advisory cache deserialization for memory safety
- [ ] Audit file traversal for path traversal attacks (symlink following)

### Medium Priority
- [ ] Review SBOM generation for XML/JSON injection in output
- [ ] Audit SARIF output for injection in finding descriptions
- [ ] Review CI/CD pipeline for supply chain attacks
- [ ] Audit dependency tree for known vulnerabilities (cargo-deny is configured)
- [ ] Review error messages for information leakage

### Low Priority
- [ ] Review logging for sensitive data exposure (API keys, secrets)
- [ ] Audit progress reporting for timing attacks
- [ ] Review config file parsing for injection

## Recommended Reviewer Tooling

- `cargo audit` — scan dependencies for known CVEs
- `cargo deny` — check licenses, advisories, bans, sources
- `cargo clippy` — static analysis (configured with `-D warnings`)
- `cargo fuzz` — fuzzing harnesses for parsers
- Manual code review of all `unsafe` blocks (none expected)
- Manual review of all network calls (grep for `ureq::`)

## Threat Model Reference

See `docs/threat-model.md` for the complete threat model including:
- Trust boundaries diagram
- Asset inventory
- Threat enumeration (STRIDE)
- Mitigation mapping
- Security recommendations

## Running Security Checks

```bash
# Check dependencies for vulnerabilities
cargo audit

# Check licenses, advisories, bans, sources
cargo deny check

# Static analysis
cargo clippy --workspace --all-targets -- -D warnings

# Run all tests (438 tests)
cargo test --workspace

# Run benchmarks
cargo bench -p pledgerecon-core
```
