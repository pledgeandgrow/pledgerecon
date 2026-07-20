# WASM Custom Rules

PledgeRecon supports custom vulnerability detection rules compiled to WebAssembly (WASM). This enables enterprise users to define organization-specific vulnerability patterns without modifying the PledgeRecon core.

## Why WASM?

- **Language-agnostic**: Write rules in Rust, C, Go, AssemblyScript, or any language that compiles to WASM
- **Sandboxed**: Rules run in a Wasmtime sandbox — no file system or network access
- **Portable**: Same `.wasm` file works on Linux, macOS, and Windows
- **Fast**: Near-native execution speed via Wasmtime's Cranelift JIT
- **Safe**: Memory isolation, resource limits, no host access

## WASM Module Interface

A PledgeRecon WASM rule module must export:

### Required Exports

| Export | Signature | Description |
|---|---|---|
| `memory` | WASM memory | Shared linear memory for data exchange |
| `check` | `fn(ptr: i32, len: i32) -> i32` | Check a dependency. Returns pointer to output JSON, or 0 if no finding. |

### Optional Exports

| Export | Signature | Description |
|---|---|---|
| `alloc` | `fn(size: i32) -> i32` | Allocate memory for input string. If absent, offset 0 is used. |

### Input (JSON passed via memory)

```json
{
  "package": "lodash",
  "version": "4.17.0",
  "ecosystem": "npm",
  "is_direct": true
}
```

### Output (JSON returned via memory)

```json
{
  "is_vulnerable": true,
  "severity": "high",
  "summary": "Custom rule: unsafe lodash version detected",
  "description": "This version of lodash has known issues with prototype pollution",
  "fix_version": "4.17.21"
}
```

If `is_vulnerable` is `false` or the function returns `0`, no finding is created.

## Writing a Rule

### Example: Rust WASM Rule

```rust
// rules/unsafe_config.rs
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Input {
    package: String,
    version: String,
    ecosystem: String,
    is_direct: bool,
}

#[derive(Serialize)]
struct Output {
    is_vulnerable: bool,
    severity: String,
    summary: String,
    description: String,
    fix_version: Option<String>,
}

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let mut buffer = Vec::with_capacity(size as usize);
    let ptr = buffer.as_mut_ptr() as i32;
    std::mem::forget(buffer); // Prevent deallocation
    ptr
}

#[no_mangle]
pub extern "C" fn check(ptr: i32, len: i32) -> i32 {
    let input_str = unsafe {
        std::str::from_utf8_unchecked(
            std::slice::from_raw_parts(ptr as *const u8, len as usize)
        )
    };

    let input: Input = match serde_json::from_str(input_str) {
        Ok(i) => i,
        Err(_) => return 0,
    };

    // Custom rule: flag any dependency on "unsafe-pkg"
    let output = if input.package == "unsafe-pkg" {
        Output {
            is_vulnerable: true,
            severity: "critical".to_string(),
            summary: "Internal package 'unsafe-pkg' is banned".to_string(),
            description: "This package has been flagged by security policy.".to_string(),
            fix_version: None,
        }
    } else {
        Output {
            is_vulnerable: false,
            severity: "info".to_string(),
            summary: String::new(),
            description: String::new(),
            fix_version: None,
        }
    };

    let output_json = serde_json::to_string(&output).unwrap();
    let bytes = output_json.as_bytes();
    let ptr = bytes.as_ptr() as i32;
    std::mem::forget(output_json); // Keep alive in WASM memory
    ptr
}
```

### Compiling

```bash
# Add WASM target
rustup target add wasm32-wasi

# Compile
cargo build --target wasm32-wasi --release -- -C link-arg=--export=check -C link-arg=--export=alloc

# Or use wasm-pack
wasm-pack build --target wasi
```

## Using Rules

### CLI

```bash
# Single rule
pledgerecon scan . --wasm-rules --wasm-rule ./rules/unsafe_config.wasm

# Multiple rules
pledgerecon scan . --wasm-rules \
  --wasm-rule ./rules/unsafe_config.wasm \
  --wasm-rule ./rules/internal_banned.wasm \
  --wasm-rule ./rules/license_check.wasm
```

### Configuration

```toml
# pledgerecon.toml
wasm_rules = true
wasm_rule_paths = [
  "rules/unsafe_config.wasm",
  "rules/internal_banned.wasm",
]
```

## Runtime Architecture

```
┌──────────────────────────────────────────┐
│         PledgeRecon Scanner               │
├──────────────────────────────────────────┤
│                                          │
│  for each dependency:                    │
│    1. Serialize WasmRuleInput to JSON    │
│    2. alloc(size) → ptr                  │
│    3. Write JSON to WASM memory at ptr   │
│    4. check(ptr, len) → result_ptr       │
│    5. Read JSON from WASM memory         │
│    6. Deserialize WasmRuleOutput         │
│    7. If vulnerable → create Finding     │
│                                          │
└──────────────────────────────────────────┘
         ↕ (Wasmtime sandbox)
┌──────────────────────────────────────────┐
│         WASM Rule Module                  │
│  (no file system, no network access)     │
└──────────────────────────────────────────┘
```

## Security Considerations

- WASM modules run in a **sandboxed Wasmtime runtime** with no host access
- No file system reads/writes from WASM (unless explicitly granted via permissions)
- No network access from WASM (unless explicitly granted via permissions)
- Memory is isolated per module instance
- **Fuel limiting (Goal 46)**: CPU time is bounded — plugins that exceed their fuel budget are terminated
- **Signature verification (Goal 49)**: Plugin integrity verified via SHA-256 hash and optional cryptographic signatures
- **Permissions (Goal 50)**: Granular permission system controls what host resources plugins can access
- **Hot-reload (Goal 51)**: Plugins can be updated without restarting the scan

## Use Cases

1. **Banned packages**: Flag internal packages that should not be used
2. **License compliance**: Check dependency licenses against corporate policy
3. **Version pinning**: Flag dependencies that aren't pinned to approved versions
4. **Custom frameworks**: Detect vulnerabilities in internal frameworks
5. **Security policies**: Enforce organization-specific security rules
6. **Supply chain**: Flag dependencies from untrusted sources

## Fuel Limiting (Goal 46)

WASM plugins are executed with a fuel budget that limits CPU consumption. This prevents malicious or buggy plugins from running indefinitely:

```toml
[wasm_plugin_config]
fuel_limit = 1000000000  # Default: 1 billion instructions (0 = unlimited)
```

When a plugin exhausts its fuel, execution is terminated immediately and a `FuelExhausted` error is returned.

## Plugin SDK (Goal 47)

PledgeRecon provides a Rust SDK module (`plugin::sdk`) for plugin authors. It includes type-safe bindings for input/output serialization:

```rust
use pledgerecon_core::plugin::sdk::{PluginInput, PluginOutput};

// Deserialize input from host
let input = PluginInput::from_ptr(ptr, len);

// Build output
let output = PluginOutput {
    is_vulnerable: true,
    severity: "high".to_string(),
    summary: "Custom rule detected issue".to_string(),
    description: "Detailed explanation".to_string(),
    fix_version: Some("2.0.0".to_string()),
};

// Serialize and return pointer
let ptr = output.to_ptr();
ptr
```

## Plugin Registry (Goal 48)

PledgeRecon supports a community plugin registry for discovering and installing plugins:

```toml
[wasm_plugin_config]
registry_url = "https://registry.pledgerecon.dev/plugins.json"
```

### Registry Operations

```rust
use pledgerecon_core::plugin::PluginRegistry;

// List available plugins
let registry = PluginRegistry::new("https://registry.pledgerecon.dev/plugins.json")?;
let entries = registry.list()?;

// Install a plugin
registry.install("banned-packages", "./rules/banned_packages.wasm")?;
```

Registry entries include:
- Plugin name and version
- Description and author
- Download URL
- SHA-256 hash for integrity verification

## Signature Verification (Goal 49)

Verify plugin integrity with cryptographic signatures:

```toml
[wasm_plugin_config]
verify_signatures = true
signature_public_key = "/path/to/public-key.pem"
```

When enabled, each plugin's WASM binary is hashed (SHA-256) and the hash is compared against the expected value. If a public key is configured, the plugin's signature is verified against it.

## Plugin Permissions (Goal 50)

Granular permissions control what host resources plugins can access:

```toml
[wasm_plugin_config]
permissions = ["ReadManifests", "ReadSource"]
```

Available permissions:

| Permission | Description |
|---|---|
| `ReadManifests` | Read dependency manifest files (package.json, Cargo.toml, etc.) |
| `ReadSource` | Read source code files |
| `ReadAdvisories` | Read advisory database entries |
| `Network` | Make network requests |
| `WriteFile` | Write files (e.g., reports) |
| `Environment` | Access environment variables |

Plugins without the required permissions are rejected at load time.

## Hot-Reload (Goal 51)

Plugins can be hot-reloaded without restarting the scan:

```toml
[wasm_plugin_config]
hot_reload = true
```

When enabled, PledgeRecon checks if plugin files have been modified (via mtime + content hash) and automatically reloads them. This is useful during plugin development.

## Parallel Execution (Goal 52)

Multiple plugins can be executed concurrently per dependency for better performance:

```toml
[wasm_plugin_config]
parallel = true  # Default: true
```

When enabled, plugins are executed in parallel using rayon. Each plugin runs in its own Wasmtime instance, maintaining full isolation.

## Example Plugins (Goals 53–55)

PledgeRecon includes example plugins in three languages:

| Language | Location | Build Tool |
|---|---|---|
| **AssemblyScript** | `examples/plugins/assemblyscript/` | `asc` compiler |
| **C** | `examples/plugins/c/` | `clang` (WASI target) |
| **Go** | `examples/plugins/go/` | `tinygo` (WASI target) |

Each example implements the same rule: flag banned or outdated packages.

### Building Examples

```bash
# AssemblyScript
cd examples/plugins/assemblyscript
npm install && npm run build

# C
clang --target=wasm32-wasi -O2 \
  -Wl,--export=check -Wl,--export=alloc \
  -o banned_packages.wasm banned_packages.c

# Go (TinyGo)
tinygo build -o banned_packages.wasm \
  -target wasi -wasm-abi generic \
  banned_packages.go
```

See `examples/plugins/README.md` for detailed build instructions.
