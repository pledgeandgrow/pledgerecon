# AST-Based Reachability Analysis

The core differentiator of PledgeRecon. Instead of only checking if a package version matches an advisory's affected range, PledgeRecon determines whether the vulnerable function is actually **reachable** from the project's entry points.

## The Problem

Traditional scanners (Trivy, Grype, Dependabot) produce high false positive rates:

```
❌ Trivy: "lodash@4.17.11 is vulnerable to CVE-2021-23337"
   → But what if template() is never called?
   → Developer wastes time investigating a non-issue
```

## The Solution

PledgeRecon builds a **call graph** from the project's source code and traces whether vulnerable functions are reachable:

```
✅ PledgeRecon: "lodash@4.17.11 is vulnerable to CVE-2021-23337 [UNREACHABLE]"
   → template() not found in call graph → deprioritized

✅ PledgeRecon: "lodash@4.17.11 is vulnerable to CVE-2021-23337 [REACHABLE]"
   → Call chain: main → processRequest → lodash.template
   → High priority — needs immediate attention
```

## How It Works

### Step 1: Build the Call Graph

The `ReachabilityAnalyzer` walks the project directory (respecting `.gitignore`) and parses source files:

| Language | Extensions | What's Parsed |
|---|---|---|
| Rust | `.rs` | `use` statements, `fn` definitions, function calls |
| JS/TS | `.js`, `.ts`, `.jsx`, `.tsx` | `import`/`require`, function/arrow definitions, calls |
| Python | `.py` | `import`/`from...import`, `def` definitions, calls |
| Go | `.go` | `import`, `func` definitions, calls |

**Skipped directories**: `node_modules/`, `target/`, `vendor/`, `dist/`

### Step 2: Identify Entry Points

Entry points are detected heuristically:
- **Rust**: `fn main()`, files named `main.rs` or `lib.rs`
- **JS/TS**: `export default`, `module.exports`, `if (require.main === module)`, files named `index.*`
- **Python**: `if __name__ ==`, files named `main.py` or `app.py`
- **Go**: `func main()`, files named `main.go`

### Step 3: BFS Reachability Check

For each advisory with `vulnerable_functions`, PledgeRecon performs a BFS from all entry points:

```
Entry Points: [main, handler, serve]
                    ↓
Call Graph:
  main → processRequest → lodash.template    ← VULNERABLE FUNCTION
  main → safeFunction
  handler → validateInput
                    ↓
BFS: main → processRequest → lodash.template ✓ REACHABLE
     Call chain: ["main", "processRequest", "lodash.template"]
```

### Step 4: Enrich Findings

Each finding is updated with:
- `reachability`: `Reachable` / `Unreachable` / `Unknown`
- `call_chain`: The traced path from entry point to vulnerable function

## Call Graph Data Model

```rust
pub struct CallGraph {
    pub nodes: HashMap<String, CallNode>,     // Function name → node
    pub entries: Vec<String>,                 // Entry point names
    pub callers: HashMap<String, Vec<String>>,// Reverse index: function → callers
}

pub struct CallNode {
    pub qualified_name: String,       // "main::src/lib.rs::process"
    pub source_path: Option<PathBuf>, // Source file
    pub line: Option<usize>,          // Line number
    pub callees: Vec<String>,         // Functions this node calls
    pub is_entry: bool,               // Is this an entry point?
}
```

## Current Limitations

1. **Regex-based parsing**: Currently uses regex heuristics, not a full AST parser. This is fast but may miss complex patterns (e.g., dynamic dispatch, reflection).
2. **No cross-file resolution**: Function calls are matched by name, not by full module path resolution.
3. **No dynamic analysis**: Doesn't track runtime call patterns.
4. **Language coverage**: Rust, JS/TS, Python, Go supported. Java, Ruby, PHP parsing is planned.

## Future: Tree-Sitter Integration

Planned upgrade to use [tree-sitter](https://tree-sitter.github.io/) for accurate AST parsing:

```rust
// Planned: tree-sitter based parsing
let mut parser = Parser::new();
parser.set_language(tree_sitter_rust::language())?;
let tree = parser.parse(source_code, None)?;
// Walk AST for function definitions, calls, imports
```

Benefits:
- Accurate function boundary detection
- Proper scope resolution
- Support for macros, generics, dynamic dispatch patterns
- Language-specific semantic understanding

## PledgePack Integration

PledgeRecon is designed to integrate with PledgePack's `SerializableModuleGraph` for JS/TS projects. PledgePack already builds a module dependency graph with:
- Module IDs and paths
- Static and dynamic dependencies
- Reverse dependency map
- Content hashes for incremental updates

By reusing PledgePack's graph, PledgeRecon can:
1. Skip building its own call graph for JS/TS projects
2. Get accurate import resolution
3. Support incremental analysis (only re-scan changed modules)

## Configuration

```toml
# pledgerecon.toml
reachability = true  # Enable AST-based reachability (default: true)

# Disable for faster scans (version-only matching):
# reachability = false
```

## CLI Usage

```bash
# Default: reachability enabled
pledgerecon scan .

# Disable reachability for faster scan
pledgerecon scan . --no-reachability

# Reachability results in JSON output:
pledgerecon scan . --format json | jq '.findings[] | {advisory_id, reachability, call_chain}'
```

## Incremental Reachability (Goal 76)

PledgeRecon supports incremental scanning — only re-scanning manifests that changed since the last scan. The scan state (manifest hashes) is persisted to `.pledgerecon-cache/scan-state.json`:

```bash
# First scan — full scan, state saved
pledgerecon scan . --incremental

# Second scan — only changed manifests are re-parsed
pledgerecon scan . --incremental
```

## Memory-Mapped Source Scanning (Goal 79)

For large source files (>1 MB), PledgeRecon uses memory-mapped I/O (`memmap2`) to avoid copying file contents into memory. This improves performance when scanning large monorepos with many source files.

## Glob-Based Source Filtering (Goal 80)

Source files can be filtered using include/exclude glob patterns:

```toml
# pledgerecon.toml
[source_filter]
include = ["src/**/*.rs", "src/**/*.ts"]
exclude = ["node_modules/**", "target/**", "dist/**", "vendor/**"]
```
