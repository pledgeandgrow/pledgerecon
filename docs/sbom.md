# SBOM Generation

PledgeRecon generates Software Bills of Materials (SBOMs) in SPDX and CycloneDX formats.

## What is an SBOM?

An SBOM is a formal record describing the components and dependencies that make up a software product. It's required for:
- US Executive Order 14028 (cybersecurity)
- NTIA minimum elements
- Enterprise security policies
- Supply chain risk management
- Compliance audits

## Supported Formats

### SPDX 2.3 (JSON)

SPDX is an open standard developed by the Linux Foundation.

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT-...",
  "name": "my-project-sbom",
  "documentNamespace": "https://pledgerecon.dev/spdx/...",
  "creationInfo": {
    "created": "2026-07-20T10:00:00+00:00",
    "creators": ["Tool: PledgeRecon", "Organization: PledgeLabs"],
    "licenseListVersion": "3.21"
  },
  "packages": [
    {
      "name": "my-project",
      "SPDXID": "SPDXRef-RootPackage",
      "versionInfo": "0.0.0",
      "downloadLocation": "NOASSERTION",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION"
    },
    {
      "name": "lodash",
      "SPDXID": "SPDXRef-pkg-npm-lodash-4-17-0",
      "versionInfo": "4.17.0",
      "externalRefs": [{
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "npm",
        "referenceLocator": "pkg:npm/lodash@4.17.0"
      }]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-RootPackage",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-pkg-npm-lodash-4-17-0"
    }
  ]
}
```

### CycloneDX 1.5 (JSON)

CycloneDX is an OWASP standard for SBOM.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2026-07-20T10:00:00+00:00",
    "component": {
      "type": "application",
      "bom-ref": "pkg:my-project@0.0.0",
      "name": "my-project",
      "version": "0.0.0"
    },
    "tools": [{
      "vendor": "PledgeLabs",
      "name": "PledgeRecon",
      "version": "0.1.0"
    }]
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/lodash@4.17.0",
      "name": "lodash",
      "version": "4.17.0",
      "purl": "pkg:npm/lodash@4.17.0",
      "scope": "required"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/express@4.18.0",
      "dependsOn": ["pkg:npm/body-parser"]
    }
  ]
}
```

## PURL Identifiers

Both formats use Package URL (PURL) identifiers:

| Ecosystem | PURL Format | Example |
|---|---|---|
| npm | `pkg:npm/{name}@{version}` | `pkg:npm/lodash@4.17.0` |
| crates.io | `pkg:crates/{name}@{version}` | `pkg:crates/serde@1.0` |
| PyPI | `pkg:pypi/{name}@{version}` | `pkg:pypi/django@4.0` |
| Go | `pkg:go/{name}@{version}` | `pkg:go/github.com/gorilla/mux@1.8` |

## CLI Usage

```bash
# Generate CycloneDX SBOM (default)
pledgerecon sbom . --output sbom.json

# Generate SPDX SBOM
pledgerecon sbom . --format spdx --output sbom.spdx.json

# Generate SBOM alongside a scan
pledgerecon scan . --generate-sbom --sbom-format cyclonedx --sbom-path sbom.json
```

## Configuration

```toml
# pledgerecon.toml
generate_sbom = true
sbom_format = "cyclonedx"  # or "spdx"
sbom_path = "sbom.json"
```

## Dependency Scope

PledgeRecon marks dependencies as:
- **required**: Direct dependencies (in the manifest's `dependencies` section)
- **optional**: Transitive dependencies (dependencies of dependencies)

## Integration with CI/CD

```yaml
# GitHub Actions
- name: Generate SBOM
  run: pledgerecon sbom . --format cyclonedx --output sbom.json

- uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.json
```

```yaml
# GitLab CI
pledgerecon:sbom:
  script:
    - pledgerecon sbom . --format cyclonedx --output sbom.json
  artifacts:
    paths:
      - sbom.json
```

## Validation

SBOMs can be validated with:
- **SPDX**: `spdx-sbom-generator --validate sbom.spdx.json`
- **CycloneDX**: `cyclonedx validate --input-file sbom.json --input-format json`

## SBOM Diff (Goal 90)

PledgeRecon can compare two SBOMs to show added, removed, and changed components. This is useful for tracking dependency changes between releases or PRs.

```rust
use pledgerecon_core::{diff_sboms, sbom_diff_to_text};

let diff = diff_sboms(&old_sbom_json, &new_sbom_json);
println!("{}", sbom_diff_to_text(&diff));
```

The `SbomDiff` result includes:
- **Added components**: New dependencies in the new SBOM
- **Removed components**: Dependencies no longer present
- **Changed components**: Dependencies with version changes
- **Summary**: Counts of each change type

## VEX Output (Goal 91)

PledgeRecon generates Vulnerability Exploitability eXchange (VEX) documents in CycloneDX VEX format. VEX statements communicate whether a vulnerability is exploitable in a specific product context.

```rust
use pledgerecon_core::{generate_vex, vex_to_json};

let vex = generate_vex(&scan_report);
let json = vex_to_json(&vex);
```

VEX statuses:
- **Affected**: Vulnerability is confirmed and exploitable
- **Not Affected**: Vulnerability is not exploitable (unreachable code or false positive)
- **Fixed**: Vulnerability has been patched in the current version
- **Under Investigation**: Triage is ongoing

Each VEX statement includes a justification (e.g., "Not reachable", "False positive") and an optional action statement (e.g., "Upgrade to 4.17.21").
