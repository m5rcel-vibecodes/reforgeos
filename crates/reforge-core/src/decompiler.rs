//! Optional Ghidra integration. Never executes an analyzed program.
use crate::{
    config::Config,
    util::{atomic_write, find_tool, tool_path},
    Fault,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub const EXPORT_SCRIPT: &str = include_str!("../../../adapters/ghidra/ReforgeExport.java");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub address: String,
    pub signature: Option<String>,
    pub code: Option<String>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decompilation {
    pub backend: String,
    pub version: String,
    pub language: String,
    pub compiler: String,
    pub functions: Vec<Function>,
}

pub trait DecompilerBackend {
    fn version(&self) -> &str;
    fn decompile(&self, input: &Path, work: &Path, config: &Config) -> Result<Decompilation>;
}

pub struct Ghidra {
    pub home: PathBuf,
    pub java: PathBuf,
    pub version: String,
}

impl Ghidra {
    pub fn discover(home: Option<&Path>) -> Result<Self> {
        let home = home.map(Path::to_owned).or_else(|| std::env::var_os("GHIDRA_INSTALL_DIR").map(PathBuf::from))
            .context("MISSING_DEPENDENCY: set GHIDRA_INSTALL_DIR or pass --ghidra-home; see docs/guide.md")?;
        let home = home
            .canonicalize()
            .context("Ghidra installation directory")?;
        let properties = fs::read_to_string(home.join("Ghidra/application.properties"))
            .context("read Ghidra application.properties")?;
        let version = properties
            .lines()
            .find_map(|l| l.strip_prefix("application.version="))
            .context("missing Ghidra version")?
            .trim()
            .to_owned();
        if !home
            .join("Ghidra/Framework/Utility/lib/Utility.jar")
            .is_file()
        {
            return Err(Fault::Dependency("Ghidra Utility.jar missing".into()).into());
        }
        let java = std::env::var_os("JAVA_HOME")
            .map(PathBuf::from)
            .map(|p| {
                p.join(if cfg!(windows) {
                    "bin/java.exe"
                } else {
                    "bin/java"
                })
            })
            .filter(|p| p.is_file())
            .or_else(|| find_tool("java"))
            .ok_or_else(|| Fault::Dependency("Java required for Ghidra; set JAVA_HOME".into()))?;
        Ok(Self {
            home,
            java,
            version,
        })
    }
}

impl DecompilerBackend for Ghidra {
    fn version(&self) -> &str {
        &self.version
    }
    fn decompile(&self, input: &Path, work: &Path, config: &Config) -> Result<Decompilation> {
        fs::create_dir_all(work)?;
        let temp = tempfile::tempdir_in(work)?;
        let root = tool_path(&temp.path().canonicalize()?);
        let script_dir = root.join("scripts");
        fs::create_dir(&script_dir)?;
        atomic_write(
            &script_dir.join("ReforgeExport.java"),
            EXPORT_SCRIPT.as_bytes(),
        )?;
        let output = root.join("functions.json");
        let runtime = tool_path(&work.canonicalize()?).join("runtime");
        for name in ["settings", "cache", "temp"] {
            fs::create_dir_all(runtime.join(name))?;
        }
        // Direct Java invocation avoids cmd.exe/.bat shell argument interpolation on Windows.
        let mut command = Command::new(&self.java);
        command
            .arg("-Xmx2G")
            .arg("-Xshare:off")
            .arg("-Djava.awt.headless=true")
            .arg("-Dfile.encoding=UTF8")
            .arg(format!("-Duser.home={}", root.display()))
            .arg(format!(
                "-Dapplication.settingsdir={}",
                runtime.join("settings").display()
            ))
            .arg(format!(
                "-Dapplication.cachedir={}",
                runtime.join("cache").display()
            ))
            .arg(format!(
                "-Dapplication.tempdir={}",
                runtime.join("temp").display()
            ))
            .arg("-Djava.system.class.loader=ghidra.GhidraClassLoader")
            .arg("-cp")
            .arg(tool_path(
                &self.home.join("Ghidra/Framework/Utility/lib/Utility.jar"),
            ))
            .arg("ghidra.Ghidra")
            .arg("ghidra.app.util.headless.AnalyzeHeadless")
            .arg(&root)
            .arg("reforge")
            .arg("-import")
            .arg(tool_path(&input.canonicalize()?))
            .arg("-scriptPath")
            .arg(&script_dir)
            .arg("-postScript")
            .arg("ReforgeExport.java")
            .arg(&output)
            .arg(config.function_timeout_seconds.to_string())
            .arg("-analysisTimeoutPerFile")
            .arg(config.timeout_seconds.to_string())
            .arg("-max-cpu")
            .arg("1")
            .arg("-deleteProject");
        let status = run_process(&mut command, work, "ghidra", config.timeout_seconds)?;
        if status != 0 {
            return Err(Fault::Backend(format!(
                "Ghidra exit {status}; see {}",
                work.join("ghidra.stdout.log").display()
            ))
            .into());
        }
        if fs::metadata(&output).map(|m| m.len()).unwrap_or(0) > config.max_binary_bytes {
            return Err(Fault::Limit("Ghidra output too large".into()).into());
        }
        let result: Decompilation = serde_json::from_slice(
            &fs::read(&output).context("Ghidra did not export functions; inspect backend logs")?,
        )?;
        if result.backend != "ghidra"
            || result.version != self.version
            || result.functions.is_empty()
        {
            return Err(Fault::Backend("invalid/empty Ghidra export".into()).into());
        }
        if result
            .functions
            .iter()
            .all(|f| f.code.as_ref().is_none_or(|c| c.trim().is_empty()))
        {
            return Err(Fault::Backend("no function successfully decompiled".into()).into());
        }
        Ok(result)
    }
}

/// Bounded process lifetime; logs go to files so pipe buffering cannot deadlock.
/// No hostile input is interpreted as shell text.
pub fn run_process(
    command: &mut Command,
    directory: &Path,
    label: &str,
    seconds: u64,
) -> Result<i32> {
    fs::create_dir_all(directory)?;
    let stdout_path = directory.join(format!("{label}.stdout.log"));
    let stderr_path = directory.join(format!("{label}.stderr.log"));
    command
        .stdin(Stdio::null())
        .stdout(File::create(&stdout_path)?)
        .stderr(File::create(&stderr_path)?);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("launch {label}; verify dependencies with reforge doctor"))?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.code().unwrap_or(-1));
        }
        let logs_exceeded = [&stdout_path, &stderr_path]
            .iter()
            .any(|p| fs::metadata(p).is_ok_and(|m| m.len() > 64 * 1024 * 1024));
        if start.elapsed() > Duration::from_secs(seconds) || logs_exceeded {
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                if let Some(root) = std::env::var_os("SystemRoot") {
                    let _ = Command::new(PathBuf::from(root).join("System32/taskkill.exe"))
                        .args(["/PID", &child.id().to_string(), "/T", "/F"])
                        .creation_flags(0x08000000)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            }
            let _ = child.kill();
            child.wait()?;
            if logs_exceeded {
                return Err(Fault::Limit(format!("{label} log size exceeded 64 MiB")).into());
            }
            return Err(Fault::Timeout(format!(
                "{label} exceeded {seconds}s; see {}",
                directory.display()
            ))
            .into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn doctor(home: Option<&Path>) -> serde_json::Value {
    let ghidra = match Ghidra::discover(home) {
        Ok(g) => {
            serde_json::json!({"available": true, "version": g.version, "path": g.home, "java": g.java, "execution_verified": false})
        }
        Err(e) => serde_json::json!({"available": false, "diagnostic": format!("{e:#}")}),
    };
    serde_json::json!({"version": env!("CARGO_PKG_VERSION"), "host": std::env::consts::OS, "architecture": std::env::consts::ARCH,
        "ghidra_optional": ghidra, "cmake_optional": find_tool("cmake"), "c_compiler_optional": find_tool("cl").or_else(||find_tool("cc")).or_else(||find_tool("clang")),
        "qemu_optional_not_integrated": find_tool("qemu-system-x86_64"), "revng_optional_not_integrated": find_tool("revng"),
        "free_disk_bytes": fs2::available_space(".").ok(), "native_core_ready": true})
}
