use crate::Fault;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub fn hash_file(path: &Path) -> Result<String> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().context("output has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .with_context(|| format!("commit {}", path.display()))?;
    Ok(())
}

/// Restrict archive names to a portable subset, including on Unix hosts.
pub fn safe_relative(name: &str) -> Result<PathBuf> {
    let bad = || Fault::UnsafePath(name.to_owned());
    if name.is_empty() || name.contains(['\\', ':', '\0']) || name.len() > 4096 {
        return Err(bad().into());
    }
    let path = Path::new(name);
    for c in path.components() {
        let Component::Normal(p) = c else {
            return Err(bad().into());
        };
        let s = p.to_str().ok_or_else(bad)?;
        let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
        if s.ends_with(['.', ' '])
            || s.chars().any(|c| c.is_control() || "<>\"|?*".contains(c))
            || ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(bad().into());
        }
    }
    if name
        .split('/')
        .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(bad().into());
    }
    Ok(path.to_owned())
}

pub fn find_tool(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|v| {
        std::env::split_paths(&v).find_map(|dir| {
            let p = dir.join(name);
            if p.is_file() {
                return Some(p);
            }
            #[cfg(windows)]
            for ext in ["exe", "bat", "cmd"] {
                let p = dir.join(format!("{name}.{ext}"));
                if p.is_file() {
                    return Some(p);
                }
            }
            None
        })
    })
}

/// Java/CMake do not consistently accept Rust's verbatim Windows canonical paths.
/// Convert only the Win32 namespace prefix; retain the absolute path and arguments.
pub fn tool_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    if let Some(text) = path.to_str() {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }
    }
    path.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_nonportable_and_traversal_paths() {
        for p in [
            "../evil", "/root", "C:/evil", "a\\..\\b", "CON.txt", "a/./b", "a//b", "a/../b",
            "bad.", "NUL", "a:stream",
        ] {
            assert!(safe_relative(p).is_err(), "{p}");
        }
        assert_eq!(
            safe_relative("usr/bin/tool").unwrap(),
            PathBuf::from("usr/bin/tool")
        );
    }
    #[test]
    fn sha256_known_vector() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("abc");
        fs::write(&p, b"abc").unwrap();
        assert_eq!(
            hash_file(&p).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
