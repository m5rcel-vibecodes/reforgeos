use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use reforge_core::{
    binary,
    config::Config,
    decompiler, image,
    project::{Project, Stage},
    util::hash_file,
};
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "reforge",
    version,
    about = "Local operating-system image analysis and experimental source recovery"
)]
struct Cli {
    #[arg(long, global = true, help = "Emit machine-readable JSON")]
    json: bool,
    #[arg(short, long, global = true, help = "Suppress progress messages")]
    quiet: bool,
    #[arg(
        short,
        long,
        global = true,
        help = "Print detailed operation diagnostics"
    )]
    verbose: bool,
    #[arg(long, global = true, help = "TOML resource limits")]
    config: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        help = "Ghidra installation root (or GHIDRA_INSTALL_DIR)"
    )]
    ghidra_home: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    Ghidra,
}
#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Recovery,
}

#[derive(Subcommand)]
enum Commands {
    /// Detect installed optional tools; does not download anything
    Doctor,
    /// Report implemented and unsupported capabilities
    Capabilities,
    /// Detect input format and inspect executable metadata
    Inspect { input: PathBuf },
    /// Extract to a new directory with bounded nested archive processing
    Extract {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Extract, inventory, analyze binaries, and generate reports
    Analyze {
        input: PathBuf,
        #[arg(short, long, default_value = "analysis.reforge")]
        output: PathBuf,
    },
    /// Export genuine Ghidra pseudocode into a persistent project
    Decompile {
        input: PathBuf,
        #[arg(short, long, default_value = "decompiled.reforge")]
        output: PathBuf,
        #[arg(long, value_enum, default_value = "ghidra")]
        backend: Backend,
    },
    /// Generate C-like source, inferred headers, provenance and CMake
    Reconstruct {
        input: PathBuf,
        #[arg(short, long, default_value = "reconstructed.reforge")]
        output: PathBuf,
        #[arg(long, value_enum, default_value = "recovery")]
        mode: Mode,
    },
    /// Attempt object compilation; never execute recovered code
    Build { project: PathBuf },
    /// Resume committed work and retry failed jobs, verifying input hashes
    Resume { project: PathBuf },
    /// Regenerate JSON, Markdown and dependency graph reports
    Report { project: PathBuf },
    /// Show persistent project progress
    Status { project: PathBuf },
}

fn execute(cli: &Cli) -> Result<Value> {
    let config = Config::load(cli.config.as_deref())?;
    match &cli.command {
        Commands::Doctor => Ok(decompiler::doctor(cli.ghidra_home.as_deref())),
        Commands::Capabilities => Ok(json!({
            "extraction": ["ISO9660 primary volume, 2048-byte sectors", "ZIP (stored/deflate)", "TAR regular files", "GZIP (nested)"],
            "binary_analysis": ["PE/COFF", "ELF", "thin Mach-O"], "native_disassembly": ["x86", "x86-64"],
            "decompilation": "optional Ghidra; architecture support depends on installed Ghidra language modules",
            "reconstruction": "experimental recovery mode: unmodified pseudocode, inferred prototypes, function provenance, object-compilation attempt",
            "persistence": "SQLite; hash/config/tool/backend/script-aware resume; one job at a time",
            "not_implemented": ["UDF", "Joliet/Rock Ridge metadata", "WIM/ESD/CAB", "XZ/Zstd/CPIO", "filesystem/disk adapters", "fat Mach-O slicing", "PDB/DWARF type recovery", "reference source matching", "rewrite/hybrid", "QEMU validation", "whole-OS rebuild", "cross-compilation"]
        })),
        Commands::Inspect { input } => {
            let format = image::detect(input)?;
            let b = if format.binary() {
                Some(binary::inspect(input, &config)?)
            } else {
                None
            };
            Ok(
                json!({"path": input, "sha256": hash_file(input)?, "format": format, "extraction_supported": format.extractable(), "binary": b}),
            )
        }
        Commands::Extract { input, output } => Ok(serde_json::to_value(image::extract(
            input, output, &config,
        )?)?),
        Commands::Analyze { input, output }
        | Commands::Decompile { input, output, .. }
        | Commands::Reconstruct { input, output, .. } => {
            let stage = match cli.command {
                Commands::Analyze { .. } => Stage::Analyze,
                Commands::Decompile { .. } => Stage::Decompile,
                _ => Stage::Reconstruct,
            };
            if !cli.quiet {
                eprintln!(
                    "ReforgeOS: {stage:?} {} -> {}",
                    input.display(),
                    output.display()
                );
            }
            let mut p = Project::create(input, output, &config, stage, cli.ghidra_home.as_deref())?;
            p.run(cli.ghidra_home.as_deref())
        }
        Commands::Build { project } => Project::open(project)?.build(),
        Commands::Resume { project } => Project::open(project)?.run(cli.ghidra_home.as_deref()),
        Commands::Report { project } => Project::open(project)?.report(),
        Commands::Status { project } => Project::open(project)?.status(),
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let start = std::time::Instant::now();
    match execute(&cli) {
        Ok(value) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
                );
            } else if value.get("analyzed_unique_binaries").is_some() {
                println!("Status: {}\nExtracted files: {}\nBinaries analyzed: {} / {}\nFunctions decompiled: {} / {}\nFunctional equivalence: unverified\nReports saved in the project's reports directory.", value["status"], value["extracted_files"], value["analyzed_unique_binaries"], value["recognized_unique_binaries"], value["decompilation_coverage"]["numerator"], value["decompilation_coverage"]["denominator"]);
                if let Some(failures) = value["failures"].as_array() {
                    for f in failures {
                        eprintln!("{}: {}", f["stage"], f["error"]);
                    }
                }
                if let Some(warnings) = value["warnings"].as_array() {
                    for w in warnings {
                        eprintln!("Warning: {w}");
                    }
                }
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
                );
            }
            if cli.verbose && !cli.quiet {
                eprintln!("Elapsed: {:.3}s", start.elapsed().as_secs_f64());
            }
            if value["status"] == "partial_with_blockers" {
                std::process::ExitCode::from(3)
            } else {
                std::process::ExitCode::SUCCESS
            }
        }
        Err(error) => {
            if cli.json {
                println!(
                    "{}",
                    json!({"status": "error", "error": format!("{error:#}")})
                );
            } else {
                eprintln!("Error: {error:#}");
            }
            std::process::ExitCode::from(1)
        }
    }
}
