use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;
use tracing_subscriber::EnvFilter;

use pledgerecon_core::{ci, config::ScanConfig, output, sbom::SbomFormat, scanner::Scanner};

/// PledgeRecon — Rust-native dependency vulnerability scanner.
///
/// AST-based reachability, WASM rules, LLM triage, SBOM generation.
#[derive(Parser)]
#[command(name = "pledgerecon")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Enable verbose logging.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a project for dependency vulnerabilities.
    Scan {
        /// Project root directory (default: current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format: text, json, sarif, markdown, html.
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Output file path (stdout if not specified).
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Minimum severity to report: low, medium, high, critical.
        #[arg(long, default_value = "low")]
        min_severity: String,

        /// Fail with non-zero exit code if vulnerabilities are found.
        #[arg(long)]
        fail_on_findings: bool,

        /// Disable AST-based reachability analysis.
        #[arg(long)]
        no_reachability: bool,

        /// Enable LLM-powered triage.
        #[arg(long)]
        triage: bool,

        /// Generate an SBOM alongside the scan.
        #[arg(long)]
        generate_sbom: bool,

        /// SBOM format: spdx or cyclonedx.
        #[arg(long, default_value = "cyclonedx")]
        sbom_format: String,

        /// SBOM output file path.
        #[arg(long, default_value = "sbom.json")]
        sbom_path: PathBuf,

        /// Enable WASM custom rules.
        #[arg(long)]
        wasm_rules: bool,

        /// Path(s) to WASM rule files.
        #[arg(long = "wasm-rule")]
        wasm_rule_paths: Vec<PathBuf>,

        /// Work offline (use cached advisory database only).
        #[arg(long)]
        offline: bool,

        /// GitHub API token for GHSA queries.
        #[arg(long)]
        github_token: Option<String>,
    },

    /// Generate an SBOM for a project.
    Sbom {
        /// Project root directory.
        #[arg(default_value = ".")]
        path: PathBuf,

        /// SBOM format: spdx or cyclonedx.
        #[arg(short, long, default_value = "cyclonedx")]
        format: String,

        /// Output file path.
        #[arg(short, long, default_value = "sbom.json")]
        output: PathBuf,
    },

    /// Initialize a pledgerecon.toml configuration file.
    Init {
        /// Project root directory.
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// List all dependencies in a project (without scanning for vulnerabilities).
    List {
        /// Project root directory.
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format: text, json.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Generate CI/CD pipeline templates.
    Ci {
        /// CI platform: github, gitlab.
        #[arg(short, long, default_value = "github")]
        platform: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match cli.command {
        Commands::Scan {
            path,
            format,
            output,
            min_severity,
            fail_on_findings,
            no_reachability,
            triage,
            generate_sbom,
            sbom_format,
            sbom_path,
            wasm_rules,
            wasm_rule_paths,
            offline,
            github_token,
        } => {
            let mut config = ScanConfig::from_root(&path).unwrap_or_default();
            config.min_severity = min_severity.clone();
            config.reachability = !no_reachability;
            config.triage = triage;
            config.generate_sbom = generate_sbom;
            config.sbom_format = sbom_format;
            config.sbom_path = sbom_path;
            config.wasm_rules = wasm_rules;
            config.wasm_rule_paths = wasm_rule_paths;
            config.offline = offline;
            config.fail_on_findings = fail_on_findings;
            if let Some(token) = github_token {
                config.github_token = Some(token);
            }

            let scanner = Scanner::new(config);
            let report = scanner.scan(&path).map_err(|e| anyhow::anyhow!("{}", e))?;

            let output_format =
                output::OutputFormat::from_str(&format).map_err(|e| anyhow::anyhow!("{}", e))?;

            let content = match output_format {
                output::OutputFormat::Json => output::to_json(&report),
                output::OutputFormat::Sarif => output::to_sarif(&report),
                output::OutputFormat::Text => output::to_text(&report),
                output::OutputFormat::Markdown => output::to_markdown(&report),
                output::OutputFormat::Html => output::to_html(&report),
                output::OutputFormat::Pdf => output::to_pdf(&report),
                output::OutputFormat::JunitXml => output::to_junit_xml(&report),
                output::OutputFormat::GitlabCodeQuality => output::to_gitlab_code_quality(&report),
                output::OutputFormat::SonarQube => output::to_sonarqube(&report),
            };

            if let Some(ref output_path) = output {
                std::fs::write(output_path, &content)?;
                tracing::info!("Report written to {}", output_path.display());
            } else {
                println!("{}", content);
            }

            if fail_on_findings && report.has_actionable() {
                let min_sev =
                    pledgerecon_core::finding::VulnerabilitySeverity::from_str(&min_severity)
                        .unwrap_or(pledgerecon_core::finding::VulnerabilitySeverity::Low);
                let exit = ci::exit_code(&report, min_sev, false);
                std::process::exit(exit);
            }
        }

        Commands::Sbom {
            path,
            format,
            output,
        } => {
            let graph = pledgerecon_core::dependency::build_dependency_graph(&path)
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            if graph.is_empty() {
                eprintln!("No dependencies found in {}", path.display());
                return Ok(());
            }

            let generator = pledgerecon_core::sbom::SbomGenerator::from_graph(&graph, &path);
            let sbom_format = match format.as_str() {
                "spdx" => SbomFormat::Spdx,
                _ => SbomFormat::CycloneDx,
            };

            generator
                .generate(&graph, sbom_format, &output)
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            eprintln!(
                "SBOM generated: {} ({} dependencies)",
                output.display(),
                graph.len()
            );
        }

        Commands::Init { path } => {
            let config_path = path.join("pledgerecon.toml");
            if config_path.exists() {
                eprintln!("Configuration already exists: {}", config_path.display());
                return Ok(());
            }

            let config = ScanConfig::default();
            config
                .save(&config_path)
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            eprintln!("Configuration created: {}", config_path.display());
        }

        Commands::List { path, format } => {
            let graph = pledgerecon_core::dependency::build_dependency_graph(&path)
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            if format == "json" {
                let json =
                    serde_json::to_string_pretty(&graph).map_err(|e| anyhow::anyhow!("{}", e))?;
                println!("{}", json);
            } else {
                eprintln!(
                    "Dependencies ({} total, {} direct):\n",
                    graph.len(),
                    graph.direct.len()
                );
                for dep in graph.dependencies.values() {
                    let kind = match dep.kind {
                        pledgerecon_core::dependency::DependencyKind::Rust => "🦀",
                        pledgerecon_core::dependency::DependencyKind::Npm => "📦",
                        pledgerecon_core::dependency::DependencyKind::Python => "🐍",
                        pledgerecon_core::dependency::DependencyKind::Go => "🐹",
                        _ => "📦",
                    };
                    let direct = if dep.is_direct {
                        "direct"
                    } else {
                        "transitive"
                    };
                    eprintln!("  {} {}@{} ({})", kind, dep.name, dep.version, direct);
                }
            }
        }

        Commands::Ci { platform } => {
            let template = match platform.as_str() {
                "github" => ci::github_actions_template(),
                "gitlab" => ci::gitlab_ci_template(),
                _ => {
                    eprintln!("Unknown platform: {}. Supported: github, gitlab", platform);
                    return Ok(());
                }
            };
            println!("{}", template);
        }
    }

    Ok(())
}
