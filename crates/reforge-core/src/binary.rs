use crate::{config::Config, util::hash_file, Fault};
use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: String,
    pub flags: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: String,
    pub undefined: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub name: String,
    pub library: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub address: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relocation {
    pub section: String,
    pub offset: u64,
    pub kind: String,
    pub target: String,
    pub addend: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binary {
    pub sha256: String,
    pub format: String,
    pub architecture: String,
    pub little_endian: bool,
    pub bits: u8,
    pub entry: u64,
    pub flags: String,
    pub debug_information_present: bool,
    pub sections: Vec<Section>,
    pub segments: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocations: Vec<Relocation>,
    pub strings: Vec<String>,
    pub discovered_symbol_functions: usize,
    pub warnings: Vec<String>,
}

fn bytes(path: &Path, config: &Config) -> Result<Vec<u8>> {
    if fs::metadata(path)?.len() > config.max_binary_bytes {
        return Err(Fault::Limit(format!(
            "binary exceeds memory input limit: {}",
            path.display()
        ))
        .into());
    }
    // Bounded read also handles a file growing after metadata was checked.
    use std::io::Read;
    let mut result = Vec::new();
    fs::File::open(path)?
        .take(config.max_binary_bytes + 1)
        .read_to_end(&mut result)?;
    if result.len() as u64 > config.max_binary_bytes {
        return Err(Fault::Limit("binary grew during read".into()).into());
    }
    Ok(result)
}

pub fn inspect(path: &Path, config: &Config) -> Result<Binary> {
    let data = bytes(path, config)?;
    let file = object::File::parse(data.as_slice()).with_context(|| {
        format!(
            "parse executable {} (fat Mach-O requires selecting a slice externally)",
            path.display()
        )
    })?;
    let mut sections = Vec::new();
    let mut relocations = Vec::new();
    for s in file.sections() {
        let name = s.name()?.to_owned();
        // Validate every section's extent even if the caller only needs metadata.
        s.data().with_context(|| format!("read section {name}"))?;
        for (offset, r) in s.relocations() {
            if relocations.len() >= 1_000_000 {
                return Err(Fault::Limit("relocation count".into()).into());
            }
            relocations.push(Relocation {
                section: name.clone(),
                offset,
                kind: format!("{:?}", r.kind()),
                target: format!("{:?}", r.target()),
                addend: r.addend(),
            });
        }
        sections.push(Section {
            name,
            address: s.address(),
            size: s.size(),
            kind: format!("{:?}", s.kind()),
            flags: format!("{:?}", s.flags()),
        });
    }
    let segments = file
        .segments()
        .map(|s| {
            Ok(Section {
                name: s.name()?.unwrap_or("").to_owned(),
                address: s.address(),
                size: s.size(),
                kind: "segment".into(),
                flags: format!("{:?}", s.flags()),
            })
        })
        .collect::<Result<_>>()?;
    let mut symbols = Vec::new();
    let mut unique = std::collections::HashSet::new();
    for s in file.symbols().chain(file.dynamic_symbols()) {
        if symbols.len() >= 1_000_000 {
            return Err(Fault::Limit("symbol count".into()).into());
        }
        let name = s.name()?.to_owned();
        if unique.insert((name.clone(), s.address(), s.is_undefined())) {
            symbols.push(Symbol {
                name,
                address: s.address(),
                size: s.size(),
                kind: format!("{:?}", s.kind()),
                undefined: s.is_undefined(),
            });
        }
    }
    let imports = file
        .imports()?
        .into_iter()
        .map(|i| Import {
            name: String::from_utf8_lossy(i.name()).into_owned(),
            library: String::from_utf8_lossy(i.library()).into_owned(),
        })
        .collect();
    let exports = file
        .exports()?
        .into_iter()
        .map(|e| Export {
            name: String::from_utf8_lossy(e.name()).into_owned(),
            address: e.address(),
        })
        .collect();
    let discovered_symbol_functions = symbols
        .iter()
        .filter(|s| s.kind == "Text" && !s.undefined)
        .count();
    let mut strings = Vec::new();
    let mut run = Vec::new();
    for &b in data.iter().chain(std::iter::once(&0)) {
        if b.is_ascii_graphic() || b == b' ' {
            if run.len() < 4096 {
                run.push(b);
            }
        } else {
            if run.len() >= 4 {
                strings.push(String::from_utf8_lossy(&run).into_owned());
            }
            run.clear();
            if strings.len() >= config.max_strings {
                break;
            }
        }
    }
    if config.max_strings == 0 {
        strings.clear();
    }
    Ok(Binary {
        sha256: hash_file(path)?, format: format!("{:?}", file.format()), architecture: format!("{:?}", file.architecture()),
        little_endian: file.is_little_endian(), bits: if file.is_64() { 64 } else { 32 }, entry: file.entry(),
        flags: format!("{:?}", file.flags()), debug_information_present: file.has_debug_symbols(), sections, segments,
        symbols, imports, exports, relocations, strings, discovered_symbol_functions,
        warnings: vec!["Function count includes defined text symbols only; stripped/undiscovered functions are unknown. Debug presence does not imply types were recovered. Import library names may be unavailable (especially ELF). Security flags are raw header facts, not a security assessment.".into()],
    })
}

pub fn disassemble(path: &Path, config: &Config) -> Result<String> {
    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
    let data = bytes(path, config)?;
    let file = object::File::parse(data.as_slice())?;
    let bits = match file.architecture() {
        object::Architecture::I386 => 32,
        object::Architecture::X86_64 => 64,
        a => {
            return Err(Fault::Unsupported(format!("native disassembly architecture {a:?}")).into())
        }
    };
    let mut result = String::from(
        "; Linear-sweep disassembly, not decompiled source. Data may be decoded as instructions.\n",
    );
    let mut formatter = IntelFormatter::new();
    let mut count = 0;
    for section in file
        .sections()
        .filter(|s| s.kind() == object::SectionKind::Text)
    {
        result.push_str(&format!("; section {:?}\n", section.name()?));
        let mut decoder = Decoder::with_ip(
            bits,
            section.data()?,
            section.address(),
            DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            if count >= 100_000 {
                result.push_str("; TRUNCATED at 100000 instructions\n");
                return Ok(result);
            }
            let instruction = decoder.decode();
            let mut line = String::new();
            formatter.format(&instruction, &mut line);
            result.push_str(&format!("{:016x}: {line}\n", instruction.ip()));
            count += 1;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspect_three_real_object_formats() {
        for format in [
            object::BinaryFormat::Coff,
            object::BinaryFormat::Elf,
            object::BinaryFormat::MachO,
        ] {
            let mut obj = object::write::Object::new(
                format,
                object::Architecture::X86_64,
                object::Endianness::Little,
            );
            let section = obj.section_id(object::write::StandardSection::Text);
            obj.append_section_data(section, &[0xb8, 42, 0, 0, 0, 0xc3], 1);
            obj.add_symbol(object::write::Symbol {
                name: b"answer".to_vec(),
                value: 0,
                size: 6,
                kind: object::SymbolKind::Text,
                scope: object::SymbolScope::Linkage,
                weak: false,
                section: object::write::SymbolSection::Section(section),
                flags: object::SymbolFlags::None,
            });
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("fixture.o");
            fs::write(&path, obj.write().unwrap()).unwrap();
            let report = inspect(&path, &Config::default()).unwrap();
            assert_eq!(report.architecture, "X86_64");
            let expected = if format == object::BinaryFormat::MachO {
                "_answer"
            } else {
                "answer"
            };
            assert!(
                report.symbols.iter().any(|s| s.name == expected),
                "{format:?}: {:?}",
                report.symbols
            );
            assert!(disassemble(&path, &Config::default())
                .unwrap()
                .contains("ret"));
        }
    }
    #[test]
    fn malformed_and_oversized_binaries() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.exe");
        fs::write(&p, b"MZbad").unwrap();
        assert!(inspect(&p, &Config::default()).is_err());
        assert!(inspect(
            &p,
            &Config {
                max_binary_bytes: 1,
                ..Config::default()
            }
        )
        .is_err());
    }
}
