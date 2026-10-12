# ReforgeOS

A local Rust command-line tool for extracting installation images, analyzing binaries,
and experimentally exporting real Ghidra decompiler output into traceable C projects.
The executable is `reforge`.

**This is an initial working implementation, not universal OS source recovery.**
Compiled programs lose source information. Decompiled pseudocode is not original
source. The [specification review](docs/spec-review.md) separates implemented scope
from the larger research roadmap in [PROMPT.md](PROMPT.md).

## Build on Windows

Install stable Rust and Visual Studio C++ Build Tools with a Windows SDK. Core
analysis requires no Java, Python, Node, cloud account, WSL, or database service.

```powershell
cargo build --release --locked
.\target\release\reforge.exe --help
.\target\release\reforge.exe doctor
```

Only Windows x86-64 is validated in this iteration. The core uses portable Rust APIs;
Linux, macOS and Windows ARM64 remain unvalidated.

## Use

```powershell
reforge capabilities
reforge inspect system.iso --json
reforge extract system.iso --output extracted
reforge analyze system.iso --output analysis.reforge
reforge status analysis.reforge
reforge resume analysis.reforge
reforge report analysis.reforge --json
```

Output directories must be new. Resume verifies original and extracted file hashes
and reuses successful jobs. Inputs are opened read-only. Extracted programs are
never launched. A project is locked against concurrent ReforgeOS writers.

### Ghidra recovery

Install official Ghidra and its required JDK. The optional integration test targets
Ghidra 11.4.2 with Java 21. Open a fresh shell after installing tools:

```powershell
$env:GHIDRA_INSTALL_DIR = 'C:\tools\ghidra_11.4.2_PUBLIC'
$env:JAVA_HOME = 'C:\Program Files\Eclipse Adoptium\your-jdk-directory'
reforge doctor
reforge reconstruct answer.exe --output recovered.reforge --mode recovery
reforge build recovered.reforge
```

`--ghidra-home PATH` overrides the environment variable. `decompile` stores function
results without generating source; `reconstruct` also creates C, inferred prototypes,
function provenance and CMake. `build` requires CMake and a C compiler.

Ghidra's `undefinedN` primitives receive unsigned storage-width aliases; their original
signedness remains unknown. Missing structures, globals, linker information and
dependencies are not invented. Compilation
may fail, in which case diagnostics are persisted. Build success means **object
compilation only**, not linking, bootability or behavioral equivalence.

## Supported scope

| Area | Implemented |
| --- | --- |
| Extraction | ISO9660 primary names with 2048-byte sectors; ZIP stored/deflate; TAR regular files; GZIP; nested recognized containers |
| Inspection | PE/COFF, ELF, thin Mach-O; headers, sections, segments, symbols, imports/exports, section relocations, bounded ASCII strings, SHA-256 |
| Disassembly | x86/x86-64 text-section linear sweep, capped at 100,000 instructions |
| OS evidence | Linux os-release metadata; Windows installer, macOS layout and possible EFI clues |
| Recovery | Actual Ghidra headless pseudocode, inferred prototypes, addresses and failures |
| Persistence | SQLite transactions, exclusive project locks, content-based analysis reuse, resume |
| Reports | JSON, Markdown, import dependency graphs in DOT/JSON, defined coverage denominators |

WIM/ESD, UDF, SquashFS, disk filesystems, Apple installer formats and fat Mach-O
slicing are not implemented. A Windows ISO's WIM contents will **not** be analyzed.
Recognized unsupported nested formats are retained and reported. Joliet/Rock Ridge
names, ownership, permissions, timestamps, links and empty directories are not
preserved. ELF library attribution is incomplete. Debug data is detected, not decoded
into source types. Rewrite/hybrid modes, QEMU validation, parallel jobs and whole-OS
rebuilding are not advertised as implemented features.

## Output

```text
analysis.reforge/
  project.sqlite          Configuration, inventory, cached jobs and function results
  extracted/              Regular files; nested archives use hash directories
  artifacts/<sha256>/     Binary metadata, assembly and backend logs
  reconstructed/          C, headers, provenance and CMake (recovery only)
  build/                  CMake object output (after build)
  build-logs/             Compiler diagnostics
  reports/                report.json, report.md, graph.json, graph.dot
```

Use `--config examples/reforge.toml` for resource limits. Unknown keys are rejected.
`--json` selects machine output; `--quiet` suppresses progress; `--verbose` adds timing.
Exit codes: 0 processing finished, 1 fatal error, 2 CLI usage error, 3 partial processing
with recorded warnings/blockers. Exit 0 never means an entire OS was recovered.

## Development

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --locked
```

See [the engineering guide](docs/guide.md) for architecture, testing, schema and
troubleshooting, and [SECURITY.md](SECURITY.md) for security boundaries. You are
responsible for authorization to analyze supplied material. No proprietary OS code
is bundled. Licensed MIT OR Apache-2.0.

Executed checks and their limits are recorded in [docs/validation.md](docs/validation.md).
