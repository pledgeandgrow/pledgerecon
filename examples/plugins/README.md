# PledgeRecon Example WASM Plugins

This directory contains example WASM plugins for PledgeRecon, written in different languages.
Each plugin implements the same simple rule: flag banned or outdated packages.

## Available Examples

| Language | Directory | Build Tool |
|---|---|---|
| **AssemblyScript** | [`assemblyscript/`](./assemblyscript/) | `asc` (AssemblyScript compiler) |
| **C** | [`c/`](./c/) | `clang` (with WASI target) |
| **Go** | [`go/`](./go/) | `tinygo` (with WASI target) |

## Plugin Interface

Every PledgeRecon WASM plugin must export:

1. **`alloc(size: i32) -> i32`** — Allocate memory for input JSON
2. **`check(ptr: i32, len: i32) -> i32`** — Check a dependency, return pointer to output JSON or 0

### Input (JSON)

```json
{
  "package": "lodash",
  "version": "4.17.0",
  "ecosystem": "npm",
  "is_direct": true
}
```

### Output (JSON)

```json
{
  "is_vulnerable": true,
  "severity": "high",
  "summary": "lodash 4.17.0 has known prototype pollution",
  "description": "Upgrade to lodash 4.17.21 or later to fix CVE-2021-23337.",
  "fix_version": "4.17.21"
}
```

If `is_vulnerable` is `false` or `check` returns `0`, no finding is created.

## Using Plugins

```bash
# Single plugin
pledgerecon scan . --wasm-rules --wasm-rule ./examples/plugins/c/banned_packages.wasm

# Multiple plugins
pledgerecon scan . --wasm-rules \
  --wasm-rule ./examples/plugins/c/banned_packages.wasm \
  --wasm-rule ./examples/plugins/go/banned_packages.wasm

# Via config
# pledgerecon.toml
# wasm_rules = true
# wasm_rule_paths = ["examples/plugins/c/banned_packages.wasm"]
```

## Plugin SDK

PledgeRecon also provides a Rust SDK (`plugin::sdk` module) for writing plugins in Rust
with type-safe bindings. See the [WASM Plugins documentation](../../docs/wasm-plugins.md)
for details.

## Features Demonstrated

All three examples demonstrate:

- **Memory management**: Bump allocator pattern for WASM linear memory
- **Input parsing**: Reading JSON from host-provided memory
- **Rule logic**: Simple package name + version matching
- **Output serialization**: Writing JSON results back to memory
- **No finding case**: Returning 0 when the dependency is not vulnerable
