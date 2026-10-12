# Engineering guide

## Modules and pipeline

`image` recognizes signatures and extracts into a private staging directory, renamed
into place only after success. Portable paths reject traversal, device names, ADS,
case collisions and backslashes. Links/special files are skipped with warnings.
Byte limits apply to actual decompressed bytes. Free space is checked before writes.
ISO bounds and both-endian fields are validated, and directory cycles rejected.
Unsupported multi-extent/interleaved/extended-attribute entries are reported.

Nested archives expand once per SHA-256 under `__nested/<hash>/`, preserving their
container relationship in the inventory. Identical ordinary files retain their paths;
binary analysis is deduplicated by hash. Empty directories and file metadata are not
preserved. Corrupt containers abort extraction without committing the staging tree.

`binary` uses object 0.36 for metadata and iced-x86 for disassembly. Format recognition
does not imply architecture-specific decompilation support. Fat Mach-O requires
external slice selection. COFF is inspectable through the library API; automatic
image scanning relies on PE/ELF/Mach-O signatures. Strings and assembly are bounded.

`decompiler` provides a typed `DecompilerBackend` interface. Ghidra is launched via
Java with structured arguments, avoiding shell interpolation. The Java script calls
DecompInterface and exports real C-like output, signatures, addresses and per-function
warnings. A successful exit alone is insufficient: the export must be valid and
contain recovered functions. Logs, per-function timeouts, a process timeout, one
analysis CPU and a 2 GiB Java heap cap bound backend activity.

API references: [object](https://docs.rs/object/0.36.7/object/read/index.html),
[DecompInterface](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html),
[DecompiledFunction](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompiledFunction.html).
Installed Ghidra includes `support/analyzeHeadlessREADME.html` documenting its flags.

`project` coordinates jobs, reconstruction and reports. OS evidence distinguishes
metadata observations from filename/layout heuristics. Dependency graph edges come
from observed import-library names. Unattributed imports remain in binary.json.
Generated C contains unmodified function output and inferred header declarations.
Globals, types, linkage and ABI issues remain explicit blockers. CMake attempts one
object target per binary. Cross-architecture compilation is blocked.

The only built-in type support is Ghidra's undefined/undefined1/2/4/8 mapped to
unsigned integer storage of the stated width. This is explicitly listed as a
transformation, not original type recovery; signedness remains unknown. Generated
files are fingerprinted. Resume/build refuse to overwrite user edits; copy edited
experiments to a separate tree. Compilation status is recorded in function provenance.

## SQLite schema and resume

| Table | Stored data |
| --- | --- |
| metadata | Key/value JSON: schema, version, input path/hash, configuration, requested stage, backend path, extraction, OS evidence and build result |
| files | Path primary key; hash, size, format and container hash |
| jobs | Primary key (hash, stage); cache key, complete/failed state, result JSON and error |

Schema version is 1. SQLite WAL and transactions preserve committed jobs. An OS file
lock prevents concurrent writers. Cache identity includes file hash, configuration,
tool version, backend version and exporter script. Failed jobs are retried. Resume
verifies original/extracted hashes. Extraction commits as a whole, so interruption
requires repeating that stage. An uncommitted extracted directory is preserved as
`uncommitted-<timestamp>`. No automatic general cleanup command deletes ambiguous files.

Function provenance records source hash, symbol/address, backend/version, language,
compiler spec, transformations, warning, compilation and validation status. Ghidra
prototypes are inferences, not exact original declarations.

## Configuration and limits

See `examples/reforge.toml`; the flat schema accepts only implemented fields. Extraction
and binary input bounds are enforced. They are not a hard total RSS quota: parser
metadata, external native memory and filesystem overhead add to those limits. Log
caps are periodically checked and may overshoot. Use a disposable environment for
adversarial inputs; this tool is not a malware sandbox.

## Tests and fixtures

The normal test suite generates small redistributable ISO, PE, ELF and Mach-O fixtures.
Tests exercise parsing, symbols, malformed inputs, traversal, collisions, limits,
nested archives, persistence, locks, reports, resume and tamper detection.

```powershell
New-Item -ItemType Directory -Force scratch
cargo run -p reforge-core --example make_fixture -- scratch/answer.iso
cargo run -p reforge-cli -- reconstruct scratch/answer.iso --output scratch/answer.reforge
cargo run -p reforge-cli -- build scratch/answer.reforge
```

For the optional test, configure GHIDRA_INSTALL_DIR, JAVA_HOME, CMake and the C compiler:

```powershell
cargo test -p reforge-core --test pipeline real_ghidra_recovery_and_object_compilation -- --ignored --nocapture
```

This test is explicitly ignored by the normal suite because the tools are optional.
Run it before claiming Ghidra was validated. It checks object compilation, not execution.
`fixtures/answer.c` documents the tiny PE fixture's semantics. The generator accepts
an independently compiled PE file as its optional second argument.

## Troubleshooting

| Diagnostic | Resolution |
| --- | --- |
| UNSUPPORTED_FORMAT | Extract externally with a trusted read-only tool or add an adapter |
| CORRUPTED_INPUT | Verify input integrity and reported extent/header |
| RESOURCE_LIMIT | Inspect input before increasing the documented configuration limit |
| UNSAFE_PATH | Correct the archive's unsafe or colliding entry |
| MISSING_DEPENDENCY | Install/configure optional tools; run doctor |
| BACKEND_FAILURE | Check artifacts/<hash>/ghidra.*.log and backend version |
| ANALYSIS_TIMEOUT | Inspect logs; adjust timeout_seconds if justified |
| RECONSTRUCTION_BLOCKED | Inspect build-logs and unresolved types/globals/ABI; never stub behavior |
| INVALID_CONFIGURATION | Correct TOML fields/limits |

I/O/parser errors retain their causes. JSON results use stdout and progress uses stderr.
Partial processing saves reports before exit 3. `doctor` checks availability; it does
not claim tools have executed successfully. Use Visual Studio Developer PowerShell
if CMake cannot find the C compiler. Open a new shell after installation to refresh PATH.

On the development machine, the optional Ghidra download lives in `.tools/` and is
excluded from Git. `scripts/dev-shell.ps1` discovers it and installed Rust, CMake and
Temurin for the current shell. If local PowerShell scripts are disabled, open a
session with a process-only policy (no machine policy change):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -NoExit -File scripts/dev-shell.ps1
```

## Releases

Windows CI runs formatting, Clippy, tests and a locked release build. The manual
packaging workflow creates ZIP/checksum artifacts without publishing a release.
`scripts/package-windows.ps1` packages locally. Rust and Cargo.lock pin tool/dependency
resolution; bitwise reproducibility across machines has not been demonstrated.
