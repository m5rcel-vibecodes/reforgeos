use crate::{
    binary::{self, Binary},
    config::Config,
    decompiler::{self, Decompilation, DecompilerBackend, Ghidra},
    image::{self, Extraction},
    util::{atomic_write, find_tool, hash_bytes, hash_file, safe_relative, tool_path},
    Fault,
};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Analyze,
    Decompile,
    Reconstruct,
}

pub struct Project {
    pub root: PathBuf,
    db: Connection,
    _lock: File,
}

impl Project {
    pub fn create(
        input: &Path,
        output: &Path,
        config: &Config,
        stage: Stage,
        ghidra_home: Option<&Path>,
    ) -> Result<Self> {
        config.validate()?;
        let input = input.canonicalize().context("open input")?;
        if !input.is_file() {
            anyhow::bail!("input must be a file");
        }
        fs::create_dir(output).with_context(|| {
            format!(
                "create new project {}; choose a new directory or use resume",
                output.display()
            )
        })?;
        let mut p = Self::open_internal(output, true)?;
        let tx = p.db.transaction()?;
        for (key, value) in [
            ("schema", json!(1)),
            ("version", json!(env!("CARGO_PKG_VERSION"))),
            ("input", json!(input)),
            ("input_sha256", json!(hash_file(&input)?)),
            ("config", json!(config)),
            ("stage", json!(stage)),
            (
                "ghidra_home",
                json!(ghidra_home.map(|p| p.canonicalize()).transpose()?),
            ),
        ] {
            tx.execute(
                "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                params![key, value.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(p)
    }

    pub fn open(root: &Path) -> Result<Self> {
        Self::open_internal(root, false)
    }

    fn open_internal(root: &Path, create: bool) -> Result<Self> {
        if !create && !root.join("project.sqlite").is_file() {
            anyhow::bail!("not a ReforgeOS project: {}", root.display());
        }
        let root = root.canonicalize()?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join("project.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock).context("project is locked by another process")?;
        let db = Connection::open(root.join("project.sqlite"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL, format TEXT NOT NULL, container TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs(sha256 TEXT NOT NULL, stage TEXT NOT NULL, cache_key TEXT NOT NULL, status TEXT NOT NULL, data TEXT, error TEXT, PRIMARY KEY(sha256,stage));")?;
        let p = Self {
            root,
            db,
            _lock: lock,
        };
        if !create {
            let schema: u32 = p.meta("schema")?;
            if schema != 1 {
                anyhow::bail!("unsupported project schema {schema}");
            }
            let version: String = p.meta("version")?;
            if version != env!("CARGO_PKG_VERSION") {
                anyhow::bail!("project created by {version}; migration required");
            }
        }
        Ok(p)
    }

    fn meta<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T> {
        let v: String = self
            .db
            .query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
                r.get(0)
            })
            .with_context(|| format!("read project metadata {key}"))?;
        Ok(serde_json::from_str(&v)?)
    }

    fn set_meta(&self, key: &str, value: &impl Serialize) -> Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO metadata VALUES(?1,?2)",
            params![key, serde_json::to_string(value)?],
        )?;
        Ok(())
    }

    fn cached<T: serde::de::DeserializeOwned>(
        &self,
        sha: &str,
        stage: &str,
        cache: &str,
    ) -> Result<Option<T>> {
        let value: Option<String> = self.db.query_row("SELECT data FROM jobs WHERE sha256=?1 AND stage=?2 AND cache_key=?3 AND status='complete'", params![sha, stage, cache], |r| r.get(0)).optional()?;
        value
            .map(|v| serde_json::from_str(&v).map_err(Into::into))
            .transpose()
    }

    fn job(&self, sha: &str, stage: &str, cache: &str, result: &Result<Value>) -> Result<()> {
        let (status, data, error) = match result {
            Ok(v) => ("complete", Some(v.to_string()), None),
            Err(e) => ("failed", None, Some(format!("{e:#}"))),
        };
        self.db.execute(
            "INSERT OR REPLACE INTO jobs VALUES(?1,?2,?3,?4,?5,?6)",
            params![sha, stage, cache, status, data, error],
        )?;
        Ok(())
    }

    pub fn run(&mut self, home_override: Option<&Path>) -> Result<Value> {
        let config: Config = self.meta("config")?;
        config.validate()?;
        let input: PathBuf = self.meta("input")?;
        let original_hash: String = self.meta("input_sha256")?;
        if hash_file(&input)? != original_hash {
            anyhow::bail!("input changed since project creation; start a new project");
        }
        let stage: Stage = self.meta("stage")?;
        let stored_home: Option<PathBuf> = self.meta("ghidra_home")?;
        if let Some(home) = home_override {
            self.set_meta("ghidra_home", &Some(home.canonicalize()?))?;
        }
        let backend = if stage >= Stage::Decompile {
            Some(Ghidra::discover(home_override.or(stored_home.as_deref())))
        } else {
            None
        };
        let extraction: Option<Extraction> = self
            .db
            .query_row(
                "SELECT value FROM metadata WHERE key='extraction'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(|s| serde_json::from_str(&s))
            .transpose()?;
        let extraction = match extraction {
            Some(e) => e,
            None => {
                let out = self.root.join("extracted");
                if out.exists() {
                    // Preserve an uncommitted extraction; never delete user files on resume.
                    let orphan = self.root.join(format!(
                        "uncommitted-{}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_nanos()
                    ));
                    fs::rename(&out, orphan)?;
                }
                let e = image::extract(&input, &out, &config)?;
                let tx = self.db.transaction()?;
                for f in &e.files {
                    tx.execute(
                        "INSERT INTO files VALUES(?1,?2,?3,?4,?5)",
                        params![
                            f.path,
                            f.sha256,
                            f.size,
                            format!("{:?}", f.format),
                            f.container
                        ],
                    )?;
                }
                tx.execute(
                    "INSERT INTO metadata VALUES('extraction',?1)",
                    [serde_json::to_string(&e)?],
                )?;
                tx.commit()?;
                e
            }
        };
        let cache = format!(
            "{}:{}",
            env!("CARGO_PKG_VERSION"),
            serde_json::to_string(&config)?
        );
        let mut analyzed = BTreeSet::new();
        for f in &extraction.files {
            let path = self.root.join("extracted").join(safe_relative(&f.path)?);
            let resolved = path.canonicalize().with_context(|| {
                format!(
                    "missing extracted file {}; restore it or create a new project",
                    f.path
                )
            })?;
            if !resolved.starts_with(self.root.join("extracted")) || hash_file(&path)? != f.sha256 {
                anyhow::bail!("extracted file changed or escaped project: {}", f.path);
            }
            if !f.format.binary() || !analyzed.insert(f.sha256.clone()) {
                continue;
            }
            let metadata = match self.cached::<Binary>(&f.sha256, "analysis", &cache)? {
                Some(b) => b,
                None => {
                    let result =
                        binary::inspect(&path, &config).and_then(|b| Ok(serde_json::to_value(b)?));
                    self.job(&f.sha256, "analysis", &cache, &result)?;
                    match result {
                        Ok(b) => serde_json::from_value(b)?,
                        Err(_) => continue,
                    }
                }
            };
            let dir = self.root.join("artifacts").join(&f.sha256);
            fs::create_dir_all(&dir)?;
            atomic_write(
                &dir.join("binary.json"),
                &serde_json::to_vec_pretty(&metadata)?,
            )?;
            if matches!(metadata.architecture.as_str(), "I386" | "X86_64")
                && !dir.join("assembly.txt").exists()
            {
                atomic_write(
                    &dir.join("assembly.txt"),
                    binary::disassemble(&path, &config)?.as_bytes(),
                )?;
            }
            if let Some(backend) = &backend {
                match backend {
                    Ok(g) => {
                        let key = format!(
                            "{cache}:ghidra:{}:{}",
                            g.version(),
                            crate::decompiler::EXPORT_SCRIPT
                        );
                        if self
                            .cached::<Decompilation>(&f.sha256, "decompile", &key)?
                            .is_none()
                        {
                            let result = g
                                .decompile(&path, &dir, &config)
                                .and_then(|d| Ok(serde_json::to_value(d)?));
                            self.job(&f.sha256, "decompile", &key, &result)?;
                        }
                    }
                    Err(e) => self.job(
                        &f.sha256,
                        "decompile",
                        "missing-backend",
                        &Err(anyhow::anyhow!("{e:#}")),
                    )?,
                }
            }
        }
        self.set_meta("os_evidence", &self.os_evidence(&extraction)?)?;
        if stage == Stage::Reconstruct {
            self.generate()?;
        }
        self.report()
    }

    fn os_evidence(&self, extraction: &Extraction) -> Result<Vec<Value>> {
        let mut facts = Vec::new();
        for f in &extraction.files {
            let lower = f.path.to_lowercase();
            if lower.ends_with("etc/os-release") && f.size < 65536 {
                let path = self.root.join("extracted").join(safe_relative(&f.path)?);
                let text = fs::read_to_string(path)?;
                let values: Vec<_> = text
                    .lines()
                    .filter(|l| {
                        l.starts_with("NAME=")
                            || l.starts_with("VERSION_ID=")
                            || l.starts_with("ID=")
                    })
                    .collect();
                facts.push(json!({"family": "Linux", "basis": "os-release metadata", "evidence": values, "path": f.path, "classification": "metadata_observation"}));
            }
            if lower.ends_with("install.wim") || lower.ends_with("boot.wim") {
                facts.push(json!({"family": "Windows", "basis": "installer filename", "path": f.path, "classification": "heuristic_not_verified"}));
            }
            if lower.contains("system/library/coreservices") {
                facts.push(json!({"family": "macOS", "basis": "directory layout", "path": f.path, "classification": "heuristic_not_verified"}));
            }
            if lower.ends_with(".efi") && f.format == image::Format::Pe {
                facts.push(json!({"boot_artifact": "possible UEFI executable", "path": f.path, "classification": "filename_and_format"}));
            }
        }
        Ok(facts)
    }

    fn results<T: serde::de::DeserializeOwned>(&self, stage: &str) -> Result<Vec<(String, T)>> {
        let mut stmt = self.db.prepare(
            "SELECT sha256,data FROM jobs WHERE stage=?1 AND status='complete' ORDER BY sha256",
        )?;
        let rows = stmt.query_map([stage], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (hash, text) = row?;
            Ok((hash, serde_json::from_str(&text)?))
        })
        .collect()
    }

    fn generate(&self) -> Result<()> {
        let results = self.results::<Decompilation>("decompile")?;
        let root = self.root.join("reconstructed");
        let generation_key = hash_bytes(&serde_json::to_vec(&(
            "generator-v2",
            &results,
            include_str!("../../../adapters/ghidra/primitives.h"),
        ))?);
        let previous: Option<String> = self.optional_meta("generation_key")?;
        if previous.is_some() {
            let files: BTreeMap<String, String> = self.meta("generated_files")?;
            for (name, expected) in files {
                let file = root.join(safe_relative(&name)?);
                if !file.is_file() || hash_file(&file)? != expected {
                    return Err(Fault::Blocked(format!("generated file changed: {}; preserve edits in a separate tree before regenerating", file.display())).into());
                }
            }
            if previous.as_deref() == Some(&generation_key) {
                return Ok(());
            }
        } else if root.exists() && fs::read_dir(&root)?.next().is_some() {
            return Err(Fault::Blocked(
                "untracked reconstructed directory exists; preserve/move it before regeneration"
                    .into(),
            )
            .into());
        }
        fs::create_dir_all(&root)?;
        let mut generated_paths = Vec::new();
        let extraction: Extraction = self.meta("extraction")?;
        let mut cmake = String::from("cmake_minimum_required(VERSION 3.20)\nproject(ReforgeRecovered C)\n# Object compilation only: linking and behavioral equivalence remain unverified.\n");
        let mut provenance = Vec::new();
        for (hash, d) in results {
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                anyhow::bail!("invalid binary hash in database");
            }
            let dir = root.join(&hash);
            let original_paths: Vec<_> = extraction
                .files
                .iter()
                .filter(|f| f.sha256 == hash)
                .map(|f| &f.path)
                .collect();
            fs::create_dir_all(&dir)?;
            let mut c = String::from("/* Genuine Ghidra C-like output. Behavior unverified. */\n#include \"recovered.h\"\n");
            let mut header = String::from("/* Prototypes reported by Ghidra; inferred types may require review. */\n#pragma once\n#include \"../ghidra_primitives.h\"\n");
            let mut recovered = 0;
            for f in d.functions {
                let recovered_code = f.code.as_ref().is_some_and(|c| !c.trim().is_empty());
                if recovered_code {
                    c.push_str(&format!("\n/* Function index {recovered}; see provenance.json for original address. */\n"));
                    c.push_str(f.code.as_deref().unwrap_or(""));
                    c.push('\n');
                    if let Some(signature) = &f.signature {
                        header.push_str(signature.trim_end_matches(';'));
                        header.push_str(";\n");
                    }
                    recovered += 1;
                }
                provenance.push(json!({"binary_sha256": hash, "original_binary_paths": original_paths, "symbol": f.name, "address": f.address, "backend": d.backend, "backend_version": d.version,
                    "language": d.language, "compiler_spec": d.compiler, "source": format!("{hash}/module.c"),
                    "classification": if recovered_code {"decompiler_output"} else {"unresolved"}, "warning": f.warning,
                    "transformations": ["concatenation", "generated header include", "Ghidra undefinedN storage-width support aliases; original signedness unknown"], "compilation": "not_tested", "validation": "unverified", "unresolved_dependencies": "not_resolved"}));
            }
            if recovered != 0 {
                atomic_write(&dir.join("module.c"), c.as_bytes())?;
                atomic_write(&dir.join("recovered.h"), header.as_bytes())?;
                generated_paths.push(format!("{hash}/module.c"));
                generated_paths.push(format!("{hash}/recovered.h"));
                cmake.push_str(&format!(
                    "add_library(module_{hash} OBJECT {hash}/module.c)\n"
                ));
            }
        }
        atomic_write(&root.join("CMakeLists.txt"), cmake.as_bytes())?;
        atomic_write(
            &root.join("ghidra_primitives.h"),
            include_bytes!("../../../adapters/ghidra/primitives.h"),
        )?;
        atomic_write(
            &root.join("provenance.json"),
            &serde_json::to_vec_pretty(&provenance)?,
        )?;
        atomic_write(&root.join("README.md"), b"# Recovered source\n\nGenuine Ghidra pseudocode, not original source. No missing behavior is stubbed. Prototypes are decompiler inferences. Globals, types, linker information and dependencies may remain unresolved. CMake attempts object compilation only. Linking, bootability and behavioral equivalence are unverified. See provenance.json and the parent project report.\n")?;
        self.set_meta(
            "generated_functions",
            &provenance
                .iter()
                .filter(|v| v["classification"] == "decompiler_output")
                .count(),
        )?;
        generated_paths.extend(
            [
                "CMakeLists.txt",
                "ghidra_primitives.h",
                "provenance.json",
                "README.md",
            ]
            .map(str::to_owned),
        );
        let files = generated_paths
            .into_iter()
            .map(|name| Ok((name.clone(), hash_file(&root.join(&name))?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        self.set_meta("generated_files", &files)?;
        self.set_meta("generation_key", &generation_key)?;
        self.set_meta(
            "build",
            &json!({"status": "not_performed", "reason": "source generated or changed"}),
        )?;
        Ok(())
    }

    pub fn build(&self) -> Result<Value> {
        let config: Config = self.meta("config")?;
        let run = || -> Result<Value> {
            let binaries = self.results::<Binary>("analysis")?;
            let decompiled = self.results::<Decompilation>("decompile")?;
            if decompiled.is_empty() {
                return Err(Fault::Blocked(
                    "no decompiled components; run reconstruct with Ghidra".into(),
                )
                .into());
            }
            for (hash, _) in &decompiled {
                let b = binaries
                    .iter()
                    .find(|(h, _)| h == hash)
                    .context("missing binary metadata")?;
                let host_matches = matches!(
                    (b.1.architecture.as_str(), std::env::consts::ARCH),
                    ("X86_64", "x86_64") | ("Aarch64", "aarch64") | ("I386", "x86")
                );
                if !host_matches {
                    return Err(Fault::Blocked(format!(
                        "cross-compilation requires a reviewed toolchain for {}",
                        b.1.architecture
                    ))
                    .into());
                }
            }
            self.generate()?;
            let cmake = find_tool("cmake")
                .ok_or_else(|| Fault::Dependency("install CMake and a C compiler".into()))?;
            let source = tool_path(&self.root.join("reconstructed"));
            let build = tool_path(&self.root.join("build"));
            let logs = self.root.join("build-logs");
            let configured = decompiler::run_process(
                Command::new(&cmake)
                    .arg("-S")
                    .arg(&source)
                    .arg("-B")
                    .arg(&build),
                &logs,
                "configure",
                config.timeout_seconds,
            )?;
            if configured != 0 {
                return Err(Fault::Blocked(format!(
                    "CMake configure exit {configured}; see build-logs"
                ))
                .into());
            }
            let status = decompiler::run_process(
                Command::new(&cmake)
                    .arg("--build")
                    .arg(&build)
                    .arg("--config")
                    .arg("Release")
                    .arg("--parallel")
                    .arg("1"),
                &logs,
                "compile",
                config.timeout_seconds,
            )?;
            if status != 0 {
                return Err(Fault::Blocked(format!("compiler exit {status}; unresolved types/globals/ABI require evidence-supported repair; see build-logs")).into());
            }
            Ok(
                json!({"status": "object_compilation_succeeded", "components": decompiled.len(), "linked": false, "runtime_validation": "not_performed", "functional_equivalence": "unverified", "attempts": 1}),
            )
        };
        let result = run();
        let record = match &result {
            Ok(v) => v.clone(),
            Err(e) => {
                json!({"status": "blocked_or_failed", "diagnostic": format!("{e:#}"), "attempts": 1, "functional_equivalence": "unverified"})
            }
        };
        self.set_meta("build", &record)?;
        if let Some(mut files) =
            self.optional_meta::<BTreeMap<String, String>>("generated_files")?
        {
            let provenance_path = self.root.join("reconstructed/provenance.json");
            // Do not overwrite an edited provenance file, even after a blocked build.
            if provenance_path.is_file()
                && files.get("provenance.json") == Some(&hash_file(&provenance_path)?)
            {
                let mut functions: Vec<Value> =
                    serde_json::from_slice(&fs::read(&provenance_path)?)?;
                for f in &mut functions {
                    f["compilation"] =
                        if result.is_ok() && f["classification"] == "decompiler_output" {
                            json!("containing_module_object_compiled")
                        } else {
                            json!("project_blocked_or_failed; individual_function_status_unknown")
                        };
                }
                atomic_write(&provenance_path, &serde_json::to_vec_pretty(&functions)?)?;
                files.insert("provenance.json".into(), hash_file(&provenance_path)?);
                self.set_meta("generated_files", &files)?;
            }
        }
        self.report()?;
        result
    }

    pub fn report(&self) -> Result<Value> {
        let extraction: Extraction = self.meta("extraction")?;
        let binaries = self.results::<Binary>("analysis")?;
        let decompilations = self.results::<Decompilation>("decompile")?;
        let recognized: BTreeSet<_> = extraction
            .files
            .iter()
            .filter(|f| f.format.binary())
            .map(|f| &f.sha256)
            .collect();
        let mut failures = Vec::new();
        let mut stmt = self.db.prepare(
            "SELECT sha256,stage,error FROM jobs WHERE status='failed' ORDER BY sha256,stage",
        )?;
        for row in stmt.query_map([], |r| Ok(json!({"binary_sha256": r.get::<_, String>(0)?, "stage": r.get::<_, String>(1)?, "error": r.get::<_, String>(2)?})))? { failures.push(row?); }
        let discovered: usize = decompilations.iter().map(|(_, d)| d.functions.len()).sum();
        let recovered: usize = decompilations
            .iter()
            .flat_map(|(_, d)| &d.functions)
            .filter(|f| f.code.as_ref().is_some_and(|c| !c.trim().is_empty()))
            .count();
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut dot = String::from("digraph dependencies {\n");
        for (hash, b) in &binaries {
            nodes.push(json!({"id": hash, "architecture": b.architecture, "format": b.format}));
            dot.push_str(&format!("  {} ;\n", serde_json::to_string(hash)?));
            let libraries: BTreeSet<_> = b
                .imports
                .iter()
                .filter(|i| !i.library.is_empty())
                .map(|i| &i.library)
                .collect();
            for library in libraries {
                edges.push(json!({"from": hash, "to": library, "basis": "binary_import_table", "resolved": false}));
                dot.push_str(&format!(
                    "  {} -> {};\n",
                    serde_json::to_string(hash)?,
                    serde_json::to_string(library)?
                ));
            }
        }
        dot.push_str("}\n");
        let stage: Stage = self.meta("stage")?;
        let generated: usize = self.optional_meta("generated_functions")?.unwrap_or(0);
        let build: Value = self
            .optional_meta("build")?
            .unwrap_or(json!({"status": "not_performed"}));
        let report = json!({
            "schema_version": 1, "tool_version": env!("CARGO_PKG_VERSION"), "input": self.meta::<Value>("input")?, "input_sha256": self.meta::<Value>("input_sha256")?,
            "status": if !failures.is_empty() || !extraction.warnings.is_empty() || build["status"] == "blocked_or_failed" {"partial_with_blockers"} else if stage == Stage::Analyze {"analysis_finished"} else {"partial_reconstruction"},
            "requested_stage": stage, "extracted_files": extraction.files.len(), "extracted_bytes": extraction.bytes, "duplicate_contents": extraction.duplicate_contents,
            "recognized_unique_binaries": recognized.len(), "analyzed_unique_binaries": binaries.len(),
            "extraction_coverage": {"numerator": extraction.files.len(), "denominator": null, "basis": "total input members unknown; not a percentage"},
            "analysis_coverage": {"numerator": binaries.len(), "denominator": recognized.len(), "basis": "unique contents with recognized executable signatures"},
            "decompilation_coverage": {"numerator": recovered, "denominator": discovered, "basis": "functions discovered in successful Ghidra exports only; failed binaries and undiscovered functions are unknown"},
            "source_generation_coverage": {"numerator": generated, "denominator": recovered, "basis": "exported decompiled functions"},
            "symbol_functions": binaries.iter().map(|(_, b)| b.discovered_symbol_functions).sum::<usize>(),
            "os_evidence": self.optional_meta::<Value>("os_evidence")?.unwrap_or(json!([])),
            "backend_versions": decompilations.iter().map(|(_, d)| &d.version).collect::<BTreeSet<_>>(),
            "build": build, "runtime_validation": "not_performed", "functional_equivalence": "unverified",
            "failures": failures, "warnings": extraction.warnings,
            "limitations": ["No whole-OS reconstruction or equivalence claim", "Types, globals, linkage and debug type recovery remain unresolved", "Extraction does not preserve ownership, timestamps, permissions, links or empty directories", "Native disassembly is x86/x86-64 linear sweep only"]
        });
        let reports = self.root.join("reports");
        atomic_write(
            &reports.join("report.json"),
            &serde_json::to_vec_pretty(&report)?,
        )?;
        atomic_write(
            &reports.join("graph.json"),
            &serde_json::to_vec_pretty(&json!({"nodes": nodes, "edges": edges}))?,
        )?;
        atomic_write(&reports.join("graph.dot"), dot.as_bytes())?;
        let markdown = format!("# ReforgeOS report\n\nStatus: {}\n\nExtracted files: {}\n\nUnique binaries analyzed: {} / {}\n\nFunctions decompiled: {} / {} discovered in successful exports (unknown elsewhere)\n\nFunctions written to source: {}\n\nBuild: {}\n\nRuntime validation: not performed. Functional equivalence: unverified.\n\n## Diagnostics\n\n```json\n{}\n```\n\nSee report.json for evidence, warnings, and metric definitions.\n", report["status"], extraction.files.len(), binaries.len(), recognized.len(), recovered, discovered, generated, report["build"]["status"], serde_json::to_string_pretty(&json!({"failures": report["failures"], "warnings": report["warnings"]}))?);
        atomic_write(&reports.join("report.md"), markdown.as_bytes())?;
        Ok(report)
    }

    fn optional_meta<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let text: Option<String> = self
            .db
            .query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
                r.get(0)
            })
            .optional()?;
        text.map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }

    pub fn status(&self) -> Result<Value> {
        let count: usize = self
            .db
            .query_row("SELECT count(*) FROM files", [], |r| r.get(0))?;
        let complete: usize = self.db.query_row(
            "SELECT count(*) FROM jobs WHERE status='complete'",
            [],
            |r| r.get(0),
        )?;
        let failed: usize =
            self.db
                .query_row("SELECT count(*) FROM jobs WHERE status='failed'", [], |r| {
                    r.get(0)
                })?;
        Ok(
            json!({"input": self.meta::<Value>("input")?, "requested_stage": self.meta::<Stage>("stage")?, "inventoried_files": count, "completed_jobs": complete, "failed_jobs": failed, "extraction_committed": self.optional_meta::<Value>("extraction")?.is_some()}),
        )
    }
}
