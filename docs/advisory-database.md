# Advisory Database

PledgeRecon fetches vulnerability advisories from multiple public sources and caches them locally for offline use.

## Sources

### OSV.dev (Primary)
- **API**: `https://api.osv.dev/v1/query` (POST)
- **Coverage**: Multiple ecosystems (crates.io, npm, PyPI, Go, Maven, etc.)
- **Query**: By package name + version
- **Data**: CVE IDs, GHSA IDs, severity (CVSS), affected ranges, references, vulnerable functions
- **Rate limit**: None (open API)

### GitHub Security Advisories (GHSA)
- **API**: `https://api.github.com/advisories` (GET)
- **Auth**: Optional GitHub token (increases rate limit from 60 to 5000 req/hour)
- **Coverage**: npm, pip, RubyGems, Maven, Go, Rust, etc.
- **Query**: By package + ecosystem
- **Data**: GHSA IDs, CVE aliases, severity, affected ranges, references

### NVD (National Vulnerability Database) — Planned
- **API**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Coverage**: All CVEs
- **Auth**: Optional API key (increases rate limit)
- **Data**: CVE IDs, CVSS scores, CPE matching, descriptions

### Local Advisory Files
- User-provided JSON files containing custom advisories
- Useful for internal packages or air-gapped environments
- Format: Same as the cached database format

## Caching

Advisories are cached to `.pledgerecon-cache/advisories.json` using serde JSON serialization.

```
.pledgerecon-cache/
└── advisories.json    # All fetched advisories, keyed by AdvisoryId
```

### Cache Behavior
- **Offline mode** (`--offline`): Uses cache only, never fetches from network
- **Online mode**: Fetches from sources, updates cache
- **Cache key**: `AdvisoryId` (e.g. "CVE-2021-23337", "GHSA-35jh-r3h4-6jhm")
- **Deduplication**: Advisories with the same ID are merged (aliases consolidated)

## Version Range Matching

PledgeRecon uses semver-aware version range checking:

```rust
// Advisory specifies affected range:
VersionRange {
    introduced: Some("4.0.0"),  // Affected since 4.0.0
    fixed: Some("4.17.21"),     // Fixed in 4.17.21
}

// Dependency version: 4.17.11
// → MATCH (4.0.0 <= 4.17.11 < 4.17.21)
```

### Supported Range Formats
- **OSV**: `introduced` / `fixed` / `last_affected` fields
- **GHSA**: `<` / `>=` / `<=` / `=` semver expressions
- **NVD**: CPE version ranges (planned)

## Advisory Data Model

```rust
pub struct Advisory {
    pub id: AdvisoryId,              // "CVE-2021-23337"
    pub aliases: Vec<String>,        // ["GHSA-35jh-r3h4-6jhm"]
    pub summary: String,             // One-line description
    pub description: String,         // Full description
    pub severity: AdvisorySeverity,  // Critical/High/Medium/Low/None
    pub cvss_score: Option<f64>,     // 0.0 - 10.0
    pub affected_packages: Vec<String>, // ["npm:lodash"]
    pub ranges: Vec<VersionRange>,   // Affected version ranges
    pub references: Vec<AdvisoryReference>, // URLs
    pub vulnerable_functions: Vec<String>,  // ["template"] — for reachability
    pub cwes: Vec<String>,           // ["CWE-77"]
    pub published: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub fix_available: bool,
}
```

## Vulnerable Functions

Some advisories (especially from OSV) include `vulnerable_functions` — the specific functions that contain the vulnerability. PledgeRecon uses these for AST-based reachability analysis:

1. Advisory says `lodash.template` is vulnerable
2. PledgeRecon checks if `template()` is called in the project's source code
3. If not called → marked `[UNREACHABLE]` (lower priority)
4. If called → marked `[REACHABLE]` with call chain (high priority)

## Configuration

```toml
# pledgerecon.toml
[[advisory_sources]]
# Uses OSV and GHSA by default

# Add a local advisory database:
# [[advisory_sources]]
# type = "local"
# path = "./internal-advisories.json"

# Offline mode (cache only):
offline = true

# Cache directory:
cache_dir = ".pledgerecon-cache"

# Persistent advisory store (Goal 78):
# advisory_store_path = ".pledgerecon-cache/advisory-store.json"

# Parallel advisory fetching concurrency (Goal 77):
# advisory_fetch_concurrency = 8
```

## Persistent Advisory Store (Goal 78)

For large datasets, PledgeRecon provides a persistent on-disk advisory store (`AdvisoryStore`) that maintains a package-level index for efficient lookups. The store is flushed to disk as JSON and can be batch-loaded:

```rust
use pledgerecon_core::AdvisoryStore;

let mut store = AdvisoryStore::open(&Path::new(".pledgerecon-cache/advisory-store.json"))?;
store.batch_insert(advisories);
store.flush()?;
```

## Parallel Advisory Fetching (Goal 77)

Advisories for multiple packages can be fetched concurrently using a rayon thread pool with configurable concurrency:

```rust
use pledgerecon_core::fetch_advisories_parallel;

let results = fetch_advisories_parallel(&packages, fetch_fn, 8);
```

## Air-Gapped Mode (Goal 94)

For fully offline operation, PledgeRecon supports air-gapped mode with a pre-bundled advisory database. The advisory bundle is a JSON file containing all advisories needed for offline scans. Use `verify_air_gapped()` to validate that all prerequisites are met before running a scan.
