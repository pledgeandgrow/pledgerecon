//! SBOM (Software Bill of Materials) generation — SPDX and CycloneDX formats.
//!
//! An SBOM is a formal record describing the components and dependencies
//! that make up a software product. PledgeRecon generates SBOMs from the
//! dependency graph, enabling compliance with executive orders and
//! enterprise security policies.

use crate::dependency::DependencyGraph;
use chrono::Utc;
use std::io::Write;
use thiserror::Error;
use uuid::Uuid;

/// SBOM output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    /// SPDX 2.3 (JSON).
    Spdx,
    /// CycloneDX 1.5 (JSON).
    CycloneDx,
}

impl std::fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SbomFormat::Spdx => write!(f, "spdx"),
            SbomFormat::CycloneDx => write!(f, "cyclonedx"),
        }
    }
}

/// Errors during SBOM generation.
#[derive(Debug, Error)]
pub enum SbomError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("no dependencies found")]
    Empty,
}

/// The SBOM generator.
pub struct SbomGenerator {
    /// Project name (from the root manifest or directory name).
    project_name: String,
    /// Project version.
    project_version: String,
}

impl SbomGenerator {
    pub fn new(project_name: impl Into<String>, project_version: impl Into<String>) -> Self {
        Self {
            project_name: project_name.into(),
            project_version: project_version.into(),
        }
    }

    /// Create a generator from a dependency graph (extracts project name/version from manifests).
    pub fn from_graph(_graph: &DependencyGraph, root: &std::path::Path) -> Self {
        let project_name = root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        let project_version = "0.0.0".to_string();
        Self {
            project_name,
            project_version,
        }
    }

    /// Generate an SBOM in the specified format and write it to a file.
    pub fn generate(
        &self,
        graph: &DependencyGraph,
        format: SbomFormat,
        output: &std::path::Path,
    ) -> Result<(), SbomError> {
        let content = match format {
            SbomFormat::Spdx => self.generate_spdx(graph)?,
            SbomFormat::CycloneDx => self.generate_cyclonedx(graph)?,
        };

        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = std::fs::File::create(output)?;
        file.write_all(content.as_bytes())?;
        tracing::info!(
            "SBOM generated: {} format, {} bytes → {}",
            format,
            content.len(),
            output.display()
        );
        Ok(())
    }

    /// Generate SPDX 2.3 JSON.
    pub fn generate_spdx(&self, graph: &DependencyGraph) -> Result<String, SbomError> {
        let spdx_id = format!("SPDXRef-DOCUMENT-{}", Uuid::new_v4());

        let mut packages = Vec::new();
        let mut relationships = Vec::new();

        // Root package.
        let root_id = "SPDXRef-RootPackage".to_string();
        packages.push(serde_json::json!({
            "name": self.project_name,
            "SPDXID": root_id,
            "versionInfo": self.project_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
        }));

        // Dependency packages.
        for (key, dep) in &graph.dependencies {
            let dep_id = format!("SPDXRef-pkg-{}", sanitize_id(key));
            packages.push(serde_json::json!({
                "name": dep.name,
                "SPDXID": dep_id.clone(),
                "versionInfo": dep.version,
                "downloadLocation": dep.source_url.as_deref().unwrap_or("NOASSERTION"),
                "filesAnalyzed": false,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": dep.kind.ecosystem_prefix(),
                    "referenceLocator": format!("pkg:{}/{}@{}", dep.kind.ecosystem_prefix().to_lowercase(), dep.name, dep.version),
                }],
            }));

            if dep.is_direct {
                relationships.push(serde_json::json!({
                    "spdxElementId": root_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": dep_id,
                }));
            }
        }

        let doc = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": spdx_id,
            "name": format!("{}-sbom", self.project_name),
            "documentNamespace": format!("https://pledgerecon.dev/spdx/{}", Uuid::new_v4()),
            "creationInfo": {
                "created": Utc::now().format("%+").to_string(),
                "creators": ["Tool: PledgeRecon", "Organization: PledgeLabs"],
                "licenseListVersion": "3.21",
            },
            "packages": packages,
            "relationships": relationships,
        });

        Ok(serde_json::to_string_pretty(&doc)?)
    }

    /// Generate CycloneDX 1.5 JSON.
    pub fn generate_cyclonedx(&self, graph: &DependencyGraph) -> Result<String, SbomError> {
        let mut components = Vec::new();
        let mut dependencies = Vec::new();

        // Root component as metadata.
        let bom_ref = format!("pkg:{}@{}", self.project_name, self.project_version);

        // Dependency components.
        for dep in graph.dependencies.values() {
            let dep_ref = format!(
                "pkg:{}/{}@{}",
                dep.kind.ecosystem_prefix().to_lowercase(),
                dep.name,
                dep.version
            );

            let mut component = serde_json::json!({
                "type": "library",
                "bom-ref": dep_ref.clone(),
                "name": dep.name,
                "version": dep.version,
                "purl": dep_ref,
            });

            // Add scope (required vs optional).
            if !dep.is_direct {
                component["scope"] = serde_json::Value::String("optional".to_string());
            } else {
                component["scope"] = serde_json::Value::String("required".to_string());
            }

            // Add external references if available.
            if let Some(ref url) = dep.source_url {
                component["externalReferences"] = serde_json::json!([{
                    "type": "website",
                    "url": url,
                }]);
            }

            components.push(component);

            // Build dependency relationships.
            let mut deps_for_component = Vec::new();
            for sub_dep in &dep.dependencies {
                let sub_ref = format!(
                    "pkg:{}/{}",
                    dep.kind.ecosystem_prefix().to_lowercase(),
                    sub_dep
                );
                deps_for_component.push(sub_ref);
            }
            if !deps_for_component.is_empty() {
                dependencies.push(serde_json::json!({
                    "ref": dep_ref,
                    "dependsOn": deps_for_component,
                }));
            }
        }

        let doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": format!("urn:uuid:{}", Uuid::new_v4()),
            "version": 1,
            "metadata": {
                "timestamp": Utc::now().format("%+").to_string(),
                "component": {
                    "type": "application",
                    "bom-ref": bom_ref,
                    "name": self.project_name,
                    "version": self.project_version,
                },
                "tools": [{
                    "vendor": "PledgeLabs",
                    "name": "PledgeRecon",
                    "version": env!("CARGO_PKG_VERSION"),
                }],
            },
            "components": components,
            "dependencies": dependencies,
        });

        Ok(serde_json::to_string_pretty(&doc)?)
    }
}

/// Sanitize a dependency key into a valid SPDX identifier fragment.
fn sanitize_id(key: &str) -> String {
    key.replace(|c: char| !c.is_alphanumeric() && c != '-', "-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::{Dependency, DependencyKind};
    use std::path::PathBuf;

    fn make_test_graph() -> DependencyGraph {
        let mut graph = DependencyGraph::new();
        graph.add(Dependency {
            name: "lodash".to_string(),
            version: "4.17.0".to_string(),
            kind: DependencyKind::Npm,
            is_direct: true,
            manifest_path: PathBuf::from("package.json"),
            dependencies: vec![],
            source_url: None,
        });
        graph.add(Dependency {
            name: "express".to_string(),
            version: "4.18.0".to_string(),
            kind: DependencyKind::Npm,
            is_direct: true,
            manifest_path: PathBuf::from("package.json"),
            dependencies: vec!["body-parser".to_string()],
            source_url: None,
        });
        graph
    }

    #[test]
    fn test_generate_spdx() {
        let graph = make_test_graph();
        let generator = SbomGenerator::new("test-project", "1.0.0");
        let spdx = generator.generate_spdx(&graph).unwrap();
        assert!(spdx.contains("SPDX-2.3"));
        assert!(spdx.contains("lodash"));
        assert!(spdx.contains("express"));
        assert!(spdx.contains("DEPENDS_ON"));
    }

    #[test]
    fn test_generate_cyclonedx() {
        let graph = make_test_graph();
        let generator = SbomGenerator::new("test-project", "1.0.0");
        let cdx = generator.generate_cyclonedx(&graph).unwrap();
        assert!(cdx.contains("CycloneDX"));
        assert!(cdx.contains("1.5"));
        assert!(cdx.contains("lodash"));
        assert!(cdx.contains("express"));
        assert!(cdx.contains("PledgeRecon"));
    }

    #[test]
    fn test_generate_to_file() {
        let graph = make_test_graph();
        let generator = SbomGenerator::new("test-project", "1.0.0");
        let dir = std::env::temp_dir().join("pledgerecon_sbom_test");
        let path = dir.join("sbom.json");
        generator
            .generate(&graph, SbomFormat::CycloneDx, &path)
            .unwrap();
        assert!(path.exists());
    }
}
