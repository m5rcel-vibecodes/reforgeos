//! Signature recognition and bounded, read-only extraction into a fresh directory.
use crate::{
    config::Config,
    util::{hash_file, safe_relative},
    Fault,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashSet, VecDeque},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Format {
    Iso9660,
    Zip,
    Tar,
    Gzip,
    Pe,
    Elf,
    MachO,
    FatMachO,
    Wim,
    Cab,
    Xz,
    Zstd,
    SquashFs,
    Cpio,
    Xar,
    Vhdx,
    Unknown,
}

impl Format {
    pub fn binary(self) -> bool {
        matches!(self, Self::Pe | Self::Elf | Self::MachO | Self::FatMachO)
    }
    pub fn extractable(self) -> bool {
        matches!(self, Self::Iso9660 | Self::Zip | Self::Tar | Self::Gzip)
    }
}

pub fn detect(path: &Path) -> Result<Format> {
    let mut bytes = vec![0; 65536];
    let mut file = File::open(path).with_context(|| format!("detect {}", path.display()))?;
    let mut used = 0;
    while used < bytes.len() {
        let n = file.read(&mut bytes[used..])?;
        if n == 0 {
            break;
        }
        used += n;
    }
    bytes.truncate(used);
    Ok(detect_bytes(&bytes))
}

pub fn detect_bytes(b: &[u8]) -> Format {
    if b.get(32769..32774) == Some(b"CD001") {
        return Format::Iso9660;
    }
    if b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06") {
        return Format::Zip;
    }
    if b.starts_with(b"\x1f\x8b") {
        return Format::Gzip;
    }
    if b.get(257..262) == Some(b"ustar") {
        return Format::Tar;
    }
    if b.starts_with(b"MZ") {
        return Format::Pe;
    }
    if b.starts_with(b"\x7fELF") {
        return Format::Elf;
    }
    if let Some(m) = b.get(..4) {
        if [
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
        ]
        .iter()
        .any(|magic| magic.as_slice() == m)
        {
            return Format::MachO;
        }
        if [
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        ]
        .iter()
        .any(|magic| magic.as_slice() == m)
        {
            return Format::FatMachO;
        }
    }
    if b.starts_with(b"MSWIM\0\0\0") {
        return Format::Wim;
    }
    if b.starts_with(b"MSCF") {
        return Format::Cab;
    }
    if b.starts_with(b"\xfd7zXZ\0") {
        return Format::Xz;
    }
    if b.starts_with(b"\x28\xb5\x2f\xfd") {
        return Format::Zstd;
    }
    if b.starts_with(b"hsqs") {
        return Format::SquashFs;
    }
    if b.starts_with(b"070701") || b.starts_with(b"070702") || b.starts_with(b"070707") {
        return Format::Cpio;
    }
    if b.starts_with(b"xar!") {
        return Format::Xar;
    }
    if b.starts_with(b"vhdxfile") {
        return Format::Vhdx;
    }
    Format::Unknown
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub format: Format,
    pub container: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Extraction {
    pub files: Vec<ExtractedFile>,
    pub warnings: Vec<String>,
    pub bytes: u64,
    pub duplicate_contents: usize,
}

struct Sink<'a> {
    root: PathBuf,
    config: &'a Config,
    report: Extraction,
    names: HashSet<String>,
}

impl Sink<'_> {
    fn put(&mut self, name: &str, reader: &mut impl Read, container: &str) -> Result<()> {
        let relative = safe_relative(name)?;
        if !self.names.insert(name.to_lowercase()) {
            return Err(
                Fault::UnsafePath(format!("duplicate or case-colliding path: {name}")).into(),
            );
        }
        if self.report.files.len() >= self.config.max_files {
            return Err(Fault::Limit("file count".into()).into());
        }
        let dest = self.root.join(relative);
        fs::create_dir_all(dest.parent().context("missing parent")?)?;
        let mut out = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&dest)?;
        let mut size = 0_u64;
        let mut buf = [0; 65536];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            size += n as u64;
            if size > self.config.max_file_bytes
                || self.report.bytes + n as u64 > self.config.max_extracted_bytes
            {
                return Err(Fault::Limit(format!("extraction byte budget at {name}")).into());
            }
            if fs2::available_space(&self.root)? < self.config.min_free_bytes + n as u64 {
                return Err(Fault::Limit("insufficient disk space".into()).into());
            }
            out.write_all(&buf[..n])?;
            self.report.bytes += n as u64;
        }
        out.sync_all()?;
        drop(out);
        self.report.files.push(ExtractedFile {
            path: name.to_owned(),
            sha256: hash_file(&dest)?,
            size,
            format: detect(&dest)?,
            container: container.to_owned(),
        });
        Ok(())
    }

    fn archive(
        &mut self,
        path: &Path,
        format: Format,
        prefix: &str,
        container: &str,
    ) -> Result<()> {
        match format {
            Format::Zip => {
                let mut zip = zip::ZipArchive::new(File::open(path)?)?;
                if zip.len() > self.config.max_files {
                    return Err(Fault::Limit("ZIP entry count".into()).into());
                }
                for i in 0..zip.len() {
                    let mut entry = zip
                        .by_index(i)
                        .context("open ZIP entry (encrypted entries are unsupported)")?;
                    let name = entry.name().trim_end_matches('/');
                    safe_relative(name)?;
                    let name = format!("{prefix}{name}");
                    if entry.is_dir() {
                        continue;
                    }
                    if entry
                        .unix_mode()
                        .is_some_and(|m| (m & 0o170000) != 0 && (m & 0o170000) != 0o100000)
                    {
                        self.report
                            .warnings
                            .push(format!("Skipped ZIP link/special file: {name}"));
                        continue;
                    }
                    if entry.size() > self.config.max_file_bytes {
                        return Err(Fault::Limit(name).into());
                    }
                    self.put(&name, &mut entry, container)?;
                }
            }
            Format::Tar => {
                let mut archive = tar::Archive::new(File::open(path)?);
                for (i, item) in archive.entries()?.enumerate() {
                    if i >= self.config.max_files {
                        return Err(Fault::Limit("TAR entry count".into()).into());
                    }
                    let mut entry = item?;
                    let name = entry
                        .path()?
                        .to_str()
                        .context("non-UTF8 TAR path")?
                        .trim_end_matches('/')
                        .to_owned();
                    // A leading ./ is a common harmless TAR convention.
                    let name = name.strip_prefix("./").unwrap_or(&name);
                    if name.is_empty() && entry.header().entry_type().is_dir() {
                        continue;
                    }
                    safe_relative(name)?;
                    let name = format!("{prefix}{name}");
                    if entry.header().entry_type().is_dir() {
                        continue;
                    }
                    if !entry.header().entry_type().is_file() {
                        self.report
                            .warnings
                            .push(format!("Skipped TAR link/special file: {name}"));
                        continue;
                    }
                    self.put(&name, &mut entry, container)?;
                }
            }
            Format::Gzip => {
                let mut decoder = flate2::read::MultiGzDecoder::new(File::open(path)?);
                self.put(&format!("{prefix}payload"), &mut decoder, container)?;
            }
            Format::Iso9660 => self.iso(path, prefix, container)?,
            _ => return Err(Fault::Unsupported(format!("{format:?}")).into()),
        }
        Ok(())
    }

    fn iso(&mut self, path: &Path, prefix: &str, container: &str) -> Result<()> {
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        let mut pvd = None;
        for sector in 16..80_u64 {
            let mut block = [0; 2048];
            file.seek(SeekFrom::Start(sector * 2048))?;
            file.read_exact(&mut block)
                .context("truncated ISO volume descriptor")?;
            if &block[1..6] != b"CD001" || block[6] != 1 {
                return Err(Fault::Corrupt("invalid ISO descriptor".into()).into());
            }
            if block[0] == 1 {
                pvd = Some(block);
            }
            if block[0] == 2 {
                self.report.warnings.push("ISO supplementary names (including Joliet) are not used; extracting ISO9660 primary names".into());
            }
            if block[0] == 255 {
                break;
            }
        }
        let pvd = pvd.context("ISO primary volume descriptor missing")?;
        if pvd[128..132] != [0, 8, 8, 0] {
            return Err(Fault::Unsupported("ISO logical block size must be 2048".into()).into());
        }
        let volume_size = both32(&pvd[80..88])? as u64 * 2048;
        if volume_size > length {
            return Err(Fault::Corrupt("ISO volume exceeds input".into()).into());
        }
        let root = iso_record(&pvd[156..190])?;
        let mut queue = VecDeque::from([(root.0, root.1, prefix.to_owned(), 0_usize)]);
        let mut visited = HashSet::new();
        let mut entries = 0;
        while let Some((extent, size, base, depth)) = queue.pop_front() {
            if depth > 64 {
                return Err(Fault::Limit("ISO directory depth".into()).into());
            }
            if !visited.insert(extent) {
                return Err(Fault::Corrupt("cyclic/shared ISO directory extent".into()).into());
            }
            let offset = extent as u64 * 2048;
            if offset + size as u64 > volume_size {
                return Err(Fault::Corrupt("ISO directory outside volume".into()).into());
            }
            let mut pos = 0_u64;
            while pos < size as u64 {
                file.seek(SeekFrom::Start(offset + pos))?;
                let mut first = [0];
                file.read_exact(&mut first)?;
                if first[0] == 0 {
                    pos = (pos / 2048 + 1) * 2048;
                    continue;
                }
                let record_len = first[0] as usize;
                if pos + record_len as u64 > size as u64 || pos % 2048 + record_len as u64 > 2048 {
                    return Err(Fault::Corrupt("ISO record crosses boundary".into()).into());
                }
                let mut rec = vec![0; record_len];
                rec[0] = first[0];
                file.read_exact(&mut rec[1..])?;
                pos += record_len as u64;
                let (start, size, flags, id) = iso_record(&rec)?;
                if id == [0] || id == [1] {
                    continue;
                }
                entries += 1;
                if entries > self.config.max_files {
                    return Err(Fault::Limit("ISO entry count".into()).into());
                }
                let name = std::str::from_utf8(id).context("non-ASCII primary ISO identifier")?;
                let name = name.split(';').next().unwrap_or(name).trim_end_matches('.');
                safe_relative(name)?;
                let name = format!("{base}{name}");
                if flags & (0x80 | 0x04) != 0 || rec[1] != 0 || rec[26] != 0 || rec[27] != 0 {
                    self.report.warnings.push(format!(
                        "Unsupported multi-extent/interleaved/extended ISO entry: {name}"
                    ));
                    continue;
                }
                // Rock Ridge attributes are not applied. Never materialize its links/devices.
                let su = 33 + id.len() + usize::from(id.len() % 2 == 0);
                if rec.get(su..).is_some_and(|s| !s.is_empty()) {
                    self.report
                        .warnings
                        .push(format!("ISO system-use metadata not applied: {name}"));
                }
                if flags & 2 != 0 {
                    queue.push_back((start, size, format!("{name}/"), depth + 1));
                } else {
                    let start = start as u64 * 2048;
                    if start + size as u64 > volume_size {
                        return Err(
                            Fault::Corrupt(format!("ISO extent outside volume: {name}")).into()
                        );
                    }
                    file.seek(SeekFrom::Start(start))?;
                    self.put(&name, &mut (&mut file).take(size as u64), container)?;
                }
            }
        }
        Ok(())
    }
}

fn both32(b: &[u8]) -> Result<u32> {
    let a = u32::from_le_bytes(b[..4].try_into()?);
    let c = u32::from_be_bytes(b[4..8].try_into()?);
    if a != c {
        return Err(Fault::Corrupt("ISO endian fields disagree".into()).into());
    }
    Ok(a)
}

fn iso_record(rec: &[u8]) -> Result<(u32, u32, u8, &[u8])> {
    if rec.len() < 34 || rec[0] as usize != rec.len() || 33 + rec[32] as usize > rec.len() {
        return Err(Fault::Corrupt("invalid ISO directory record".into()).into());
    }
    Ok((
        both32(&rec[2..10])?,
        both32(&rec[10..18])?,
        rec[25],
        &rec[33..33 + rec[32] as usize],
    ))
}

pub fn extract(input: &Path, output: &Path, config: &Config) -> Result<Extraction> {
    config.validate()?;
    if output.exists() {
        anyhow::bail!(
            "output already exists: {}; use a new directory",
            output.display()
        );
    }
    let format = detect(input)?;
    if !format.extractable() && !format.binary() {
        return Err(
            Fault::Unsupported(format!("{format:?}: cannot extract {}", input.display())).into(),
        );
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let mut sink = Sink {
        root: staging.path().to_owned(),
        config,
        report: Extraction::default(),
        names: HashSet::new(),
    };
    let input_hash = hash_file(input)?;
    if format.binary() {
        sink.put("input.bin", &mut File::open(input)?, &input_hash)?;
    } else {
        sink.archive(input, format, "", &input_hash)?;
    }
    let mut seen_archives = HashSet::from([input_hash]);
    let mut seen_files = HashSet::new();
    let mut cursor = 0;
    let mut depths = std::collections::HashMap::new();
    while cursor < sink.report.files.len() {
        let item = sink.report.files[cursor].clone();
        cursor += 1;
        if !seen_files.insert(item.sha256.clone()) {
            sink.report.duplicate_contents += 1;
        }
        if item.format.extractable() && seen_archives.insert(item.sha256.clone()) {
            let depth = depths.get(&item.container).copied().unwrap_or(0) + 1;
            depths.insert(item.sha256.clone(), depth);
            if depth > config.max_depth {
                sink.report
                    .warnings
                    .push(format!("Nested depth limit: {}", item.path));
                continue;
            }
            sink.archive(
                &sink.root.join(&item.path),
                item.format,
                &format!("__nested/{}/", item.sha256),
                &item.sha256,
            )?;
        } else if !item.format.extractable()
            && !item.format.binary()
            && item.format != Format::Unknown
        {
            sink.report.warnings.push(format!(
                "Recognized but unsupported nested format {:?}: {}",
                item.format, item.path
            ));
        }
    }
    fs::rename(staging.path(), output).context("commit extraction directory")?;
    Ok(sink.report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_and_truncations() {
        assert_eq!(detect_bytes(b"\x7fELF"), Format::Elf);
        assert_eq!(detect_bytes(b"MZ"), Format::Pe);
        for n in 0..4 {
            assert_eq!(detect_bytes(&b"\x7fELF"[..n]), Format::Unknown);
        }
        assert_eq!(detect_bytes(b"MSWIM\0\0\0"), Format::Wim);
    }
    #[test]
    fn zip_traversal_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("bad.zip");
        let mut zip = zip::ZipWriter::new(File::create(&input).unwrap());
        zip.start_file("../escaped", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"no").unwrap();
        zip.finish().unwrap();
        let output = dir.path().join("out");
        assert!(extract(&input, &output, &Config::default()).is_err());
        assert!(!output.exists());
        assert!(!dir.path().join("escaped").exists());
    }
    #[test]
    fn byte_limit_and_duplicate_names() {
        for duplicate in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let input = dir.path().join("input.zip");
            let mut zip = zip::ZipWriter::new(File::create(&input).unwrap());
            for name in if duplicate {
                vec!["A", "a"]
            } else {
                vec!["file"]
            } {
                zip.start_file(name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                zip.write_all(b"12345").unwrap();
            }
            zip.finish().unwrap();
            let config = Config {
                max_file_bytes: if duplicate { 100 } else { 4 },
                ..Config::default()
            };
            assert!(extract(&input, &dir.path().join("out"), &config).is_err());
        }
    }
}
