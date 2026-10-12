# ReforgeOS — Universal Operating System Decompiler & Source Reconstruction Framework

## ROLE AND OBJECTIVE

You are a senior systems programmer, reverse-engineering researcher, compiler engineer, operating system developer, and production software architect.

Your task is to **design and implement ReforgeOS**, a powerful, lightweight, cross-platform, open-source command-line application capable of analyzing operating system installation images, extracting their contents, decompiling executable components, reconstructing source code, and attempting to produce a buildable operating system source tree.

This must be an actual working software project, not a concept, mockup, proof-of-concept-only script, or collection of placeholders.

ReforgeOS must run on Windows, macOS, and Linux and support analyzing operating systems from all three families, regardless of which host platform is running the tool, subject to documented format and architecture limitations.

The project's ultimate research goal is to reconstruct as much of an operating system's original implementation as technically possible, including the kernel, drivers, system libraries, startup components, services, applications, and configuration.

It must be possible for a user to supply an installation ISO and initiate an automated reconstruction pipeline.

### Critical scientific limitations

Compiled binaries do not contain all the information present in their original source code.

Consequently:

- Never promise exact original source recovery where information has been irreversibly lost.
- Never fabricate supposedly original source files, comments, names, or implementations.
- Attempt source recovery using available symbols, debug information, metadata, structure analysis, and user-supplied reference sources.
- When exact recovery is impossible, generate a clearly identified reconstructed implementation where sufficient information exists.
- Distinguish genuine decompiler output from manually or automatically rewritten code.
- Preserve provenance and traceability from every generated function to its source binary.
- Clearly identify unsupported, unresolved, and unverified components.
- Never claim an operating system is functionally equivalent based solely on compilation or successful booting.

The tool must maximize actual recoverability rather than merely generate source code that looks believable.

---

# 1. PROJECT IDENTITY

**Project name:** ReforgeOS

**Executable:** `reforge`

**Primary language:** Rust

**Project type:** Open-source, cross-platform command-line application

**Primary license:** Apache-2.0 OR MIT, subject to dependency compatibility.

**Development priorities:**

1. Correctness and reliability
2. Genuine reverse-engineering capabilities
3. Cross-platform compatibility
4. Source reconstruction quality
5. Low resource consumption
6. Reproducible builds
7. Security
8. Extensibility
9. Maintainability
10. Ease of installation

The application must not require a graphical desktop environment.

It should work inside terminals, automated pipelines, remote servers, and CI environments.

It must not require any online AI service, API key, paid subscription, or cloud account.

All fundamental functionality must operate locally.

---

# 2. HOST PLATFORM SUPPORT

Support these host environments:

### Windows

- Windows 10 and newer
- Windows 11
- x86-64
- ARM64 where feasible
- PowerShell and Command Prompt
- Native Windows builds without requiring WSL

### Linux

- Major glibc-based distributions
- Alpine Linux where compatible
- x86-64
- ARM64
- Headless and desktop environments
- Docker-compatible workflows

### macOS

- Intel-based Macs
- Apple Silicon Macs
- Native arm64 and x86-64 builds
- Terminal operation without mandatory GUI components

Host platform support and target operating system support must be implemented independently.

For example, a user running ReforgeOS on Linux must be able to analyze Windows PE binaries and macOS Mach-O binaries.

Architecture support must be reported explicitly; never silently assume that an architecture is supported merely because the file was recognized.

Use conditional compilation and portable Rust APIs wherever possible.

Avoid unnecessary platform-specific code.

---

# 3. INPUT FORMAT SUPPORT

The tool must recognize supported installation images automatically using their actual format signatures, not merely their filename extensions.

Implement a modular format-handling system.

### Generic formats

- ISO9660
- UDF where supported
- Raw disk images
- ZIP
- TAR
- GZIP
- XZ
- Zstandard
- CPIO
- Nested archives

### Windows formats

- Windows installation ISOs
- WIM
- ESD, where compatible extraction is available
- CAB
- PE executables
- DLL files
- SYS drivers
- EFI executables
- VHD and VHDX through supported adapters
- PDB debugging information when available

### Linux formats

- Linux installation ISOs
- ELF binaries
- SquashFS
- initramfs images
- CPIO archives
- ext-family filesystems through appropriate readers
- Kernel images where their packaging is recognized
- Shared libraries
- Kernel modules
- Bootloader files

### macOS formats

- Mach-O executables
- Universal/Fat Mach-O binaries
- DMG where supported
- PKG and XAR archives
- APFS through compatible read-only adapters
- HFS+ through compatible adapters
- Apple installer packages
- dyld shared caches where supported

macOS installers do not necessarily use ISO images. Users must be able to submit supported macOS installer and disk-image formats directly.

Do not assume that encrypted, compressed, signed, or proprietary formats can always be extracted.

Report unsupported features explicitly.

Never attempt to bypass encryption, platform security, or access controls.

### Intelligent extraction

The extractor must:

- Determine the actual file format.
- Detect nested images and archives.
- Extract recognized files recursively where appropriate.
- Preserve original directory structure.
- Retain file metadata when technically possible.
- Hash extracted contents.
- Detect duplicate files.
- Avoid repeated extraction of identical content.
- Prevent path traversal attacks.
- Detect archive bombs.
- Respect disk space and resource limits.
- Handle corrupted inputs safely.
- Allow partial extraction when noncritical files fail.
- Produce a complete extraction report.

Extraction must always operate on a copy or read-only view of the input.

Never modify the original ISO or disk image.

---

# 4. OPERATING SYSTEM DETECTION

After opening an image, ReforgeOS must attempt to determine:

- OS family
- OS name
- Version
- Build identifier
- CPU architecture
- Boot method
- Filesystem layout
- Package structure
- Kernel type
- Executable formats
- Installed components
- Whether the input contains an installed OS or only installation utilities

Use evidence-based identification.

Examples include Windows installation metadata, Linux release metadata, and macOS installer metadata.

Do not fabricate missing version information.

Each detected property must have an evidence source and confidence indicator.

Example output:

    ReforgeOS
    Image: system.iso

    Detected family: Linux
    Architecture: x86_64
    Boot mode: UEFI
    Primary executable format: ELF

    Extraction: Supported
    Binary analysis: Supported
    Decompiler: Available
    Reconstruction: Partial support

The tool should display warnings when detection is uncertain.

---

# 5. BINARY ANALYSIS ENGINE

Implement a reusable binary analysis subsystem.

The native core should inspect executable metadata without requiring a heavyweight reverse-engineering suite.

### Required functionality

- Detect executable format.
- Detect target architecture.
- Parse headers.
- Enumerate sections and segments.
- Inspect imports and exports.
- Extract symbols when available.
- Read relocation tables.
- Identify entry points.
- Inspect known debug formats.
- Recover strings.
- Locate referenced libraries.
- Generate dependency information.
- Calculate hashes.
- Collect binary security characteristics.

### Primary binary types

- PE/COFF
- ELF
- Mach-O
- Raw binaries where configuration provides sufficient interpretation context

Use a well-maintained Rust binary parsing library where practical.

LIEF may be supported as an optional backend if its build and licensing requirements are compatible with the project.

Separate format parsing from decompilation.

The analysis database should retain the discovered information even if later decompilation fails.

---

# 6. AUTOMATED DECOMPILATION

This is one of the project's most important features.

ReforgeOS must provide a real decompilation workflow rather than renaming binary files to source extensions or generating empty function definitions.

### Supported output

Prioritize C-like decompiler output.

Additional languages may be supported in later implementations, but the initial application should focus on C and architecture-specific assembly.

Do not generate Rust implementations merely by syntactically translating C unless semantic correctness can be meaningfully checked.

### Backend architecture

Define a common interface for decompiler backends.

Possible backends:

**Ghidra**

- Support automatic headless analysis.
- Detect an existing Ghidra installation.
- Integrate through documented command-line and scripting interfaces.
- Export functions, prototypes, symbols, and pseudocode.
- Capture warnings and analysis errors.

**rev.ng**

- Support its documented interfaces where available.
- Use its recompilable C generation capabilities when appropriate.
- Keep it optional rather than a mandatory dependency.

**Native analysis backend**

- Provide lightweight binary inspection and architecture-supported disassembly.
- Preserve assembly output when decompilation is unavailable.
- Do not mislabel disassembly as high-level source reconstruction.

Use a backend interface such as:

    DecompilerBackend
      - identify()
      - capabilities()
      - analyze()
      - decompile()
      - export()
      - diagnostics()

The actual Rust design may differ if a better typed abstraction is appropriate.

### Backend management

Implement:

- Backend discovery
- Version detection
- Dependency validation
- Supported architecture reporting
- Timeout handling
- Process exit-code checks
- Backend-specific diagnostics
- Resource limits
- Capability negotiation
- Reproducible configuration
- Fallback handling

A backend failure must not corrupt the analysis database or destroy previously recovered results.

Never claim a successful decompilation if the backend only produced an error, assembly listing, or incomplete intermediate output.

---

# 7. SOURCE CODE RECOVERY

Implement a source recovery subsystem focused on maximizing accurate information recovered from compiled binaries.

The system should analyze:

- Available symbol names
- Function entry points
- Function signatures
- Imported APIs
- Exported APIs
- Calling conventions
- Debug information
- Stack layouts
- Data structures
- Global variables
- Memory accesses
- String references
- Cross-references
- Indirect calls
- Control flow
- Shared data layouts
- Object-oriented metadata where available

Attempt to infer:

- Function parameters
- Return types
- Structure fields
- Structure sizes
- Enumeration values
- Pointer relationships
- Function boundaries
- Module relationships
- Header dependencies
- Calling conventions

Distinguish exact recovered facts from heuristic guesses.

### Original source identification

When the user supplies a reference source tree, symbols, map files, or debugging data:

- Index the reference information.
- Compare it against analyzed binaries.
- Identify possible source-to-binary relationships.
- Match functions using appropriate metadata and fingerprints.
- Report strong and weak matches separately.
- Preserve the relationship between matched source and binary addresses.

Do not automatically download arbitrary copyrighted source repositories.

Do not present a source match as exact unless it is supported by sufficient evidence.

---

# 8. AUTOMATED SOURCE RECONSTRUCTION

Create a reconstruction engine that assembles recovered functions and data structures into a coherent source tree.

### Reconstruction modes

Implement three modes.

**Recovery mode**

Prioritize fidelity to the analyzed binary.

Preserve low-level control flow and unusual constructs when necessary.

Avoid stylistic changes that could alter behavior.

**Rewrite mode**

Generate a clearer implementation where enough behavioral evidence exists.

Allow cleaner variable names, modular organization, and more maintainable code.

Require rewritten functions to retain references to their original binaries and addresses.

**Hybrid mode**

Use verified recovered source where available, minimally transformed decompiler output where viable, and clearly identified rewritten implementations for selected components.

Never silently merge incompatible functions or structures.

### Important reconstruction features

- Normalize source identifiers where necessary.
- Generate explicit source files.
- Recover or generate header declarations.
- Build a module dependency graph.
- Reconstruct library interfaces.
- Identify cross-module relationships.
- Separate user-space and kernel-space code.
- Recover initialization order where possible.
- Preserve binary addresses and symbol mappings.
- Track uncertainty at function level.
- Identify missing functions.
- Represent unresolved behavior without inventing implementations.
- Produce diagnostics explaining reconstruction blockers.

### Confidence and provenance

Every reconstructed function must have metadata containing:

- Source binary
- Original address or symbol
- Backend used
- Recovered information
- Transformations applied
- Analysis warnings
- Compilation status
- Validation status
- Unresolved dependencies

Do not assign arbitrary numerical confidence scores without defining how they are calculated.

Use evidence classifications and measurable validation results wherever possible.

---

# 9. OPERATING SYSTEM COMPONENT MAPPING

The engine must attempt to identify and classify operating system components.

### Kernel

Attempt to locate:

- Kernel entry points
- Boot initialization routines
- Interrupt handling
- Memory management
- Process and thread scheduling
- Synchronization primitives
- System call interfaces
- Device management
- Filesystem interfaces
- Kernel modules

### Drivers

Identify:

- Storage drivers
- Network drivers
- Display drivers
- Input drivers
- Bus drivers
- Filesystem drivers
- Platform-specific drivers

Infer relevant interfaces and dependencies.

### User-space components

Identify:

- Init systems
- Service managers
- Background services
- System utilities
- Authentication components
- User interface components
- System libraries
- Runtime libraries
- Command interpreters

### Dependency graph

Create a graph representing discovered relationships between executables, libraries, drivers, and services.

Support exported Graphviz DOT and JSON graph formats.

A dependency relationship must have a recorded basis, such as an import, symbol reference, metadata entry, or observed runtime interaction.

---

# 10. BUILD SYSTEM RECONSTRUCTION

The tool must attempt to produce a buildable project from reconstructed source code.

However, decompiled programs may rely on details that are not preserved in the original binary.

Do not assume the original compiler, linker scripts, or build flags can always be recovered.

### Required behavior

- Detect target architecture.
- Determine likely ABI requirements.
- Detect calling conventions.
- Identify required libraries.
- Recover linkage relationships when possible.
- Generate compiler configuration.
- Generate header dependencies.
- Report missing toolchains.
- Preserve architecture-specific assembly.
- Create linker scripts only when sufficient information is available.
- Produce a reproducible build manifest.

Prioritize CMake for generated C projects.

Use Cargo for generated Rust components.

Support GNU Make or other build systems through additional adapters.

### Generated project

An example output structure:

    reconstructed/
    ├── README.md
    ├── reconstruction.json
    ├── provenance.json
    ├── CMakeLists.txt
    ├── boot/
    ├── kernel/
    ├── drivers/
    ├── libraries/
    ├── services/
    ├── userspace/
    ├── headers/
    ├── assembly/
    ├── resources/
    ├── unresolved/
    ├── tests/
    ├── reports/
    └── build/

Only create components that are present, recovered, or meaningfully reconstructed.

Preserve the original binary organization in metadata, even if the generated tree uses a different layout.

### Compilation feedback

Implement a bounded reconstruction loop:

1. Generate the source project.
2. Run the relevant compiler.
3. Collect compiler diagnostics.
4. Identify recoverable generation problems.
5. Apply narrowly scoped, evidence-supported corrections.
6. Recompile.
7. Stop when successful, blocked, or the configured attempt limit is reached.

Never remove required functionality merely to silence compilation errors.

Never replace important functions with empty stubs and report success.

---

# 11. RUNTIME VALIDATION

Support optional validation in an isolated virtual machine.

QEMU should be the preferred initial runtime validation backend.

It must be an optional dependency.

### Validation capabilities

- Boot a supported original image when feasible and authorized.
- Capture serial output.
- Capture boot-stage diagnostics.
- Observe selected runtime behavior.
- Execute controlled test workloads.
- Attempt to boot reconstructed images.
- Compare observable behavior.
- Generate validation reports.

### Differential testing

Where technically possible:

- Run identical test inputs against the reference and reconstructed systems.
- Compare system call results.
- Compare selected filesystem operations.
- Compare process creation and termination behavior.
- Compare application output.
- Compare defined device interactions.
- Record failures and differences.

Do not compare nondeterministic outputs without appropriate normalization.

A successful boot is not sufficient evidence of complete operating system reconstruction.

Explicitly distinguish:

- Compiles successfully
- Links successfully
- Produces a bootable image
- Reaches kernel initialization
- Reaches user space
- Passes functional tests
- Matches tested reference behavior

A validated result must not claim properties that have not been tested.

---

# 12. LIGHTWEIGHT ARCHITECTURE

The main executable must be written in Rust.

Avoid introducing unnecessary runtimes.

### Core requirements

- Build using stable Rust.
- Use Cargo.
- Avoid mandatory Python.
- Avoid mandatory Java.
- Avoid mandatory Node.js.
- Avoid mandatory Docker.
- Avoid mandatory databases running as services.
- Avoid an Electron interface.
- Avoid unnecessary HTTP services.
- Avoid cloud dependencies.

Ghidra's Java runtime may be required when the optional Ghidra backend is enabled, but it must not be required for basic image extraction or binary inspection.

### Modular internal organization

Use a Cargo workspace or similarly maintainable structure.

Suggested modules:

    crates/
      reforge-cli/
      reforge-core/
      reforge-image/
      reforge-formats/
      reforge-binary/
      reforge-analysis/
      reforge-decompiler/
      reforge-reconstruction/
      reforge-build/
      reforge-validation/
      reforge-storage/
      reforge-report/

Avoid overengineering.

Combine crates where separation adds no useful architectural value.

### Memory efficiency

Implement:

- Streaming file processing
- Bounded job queues
- Configurable parallelism
- Lazy loading
- Incremental analysis
- Content-addressed caching
- Database transactions
- Memory-conscious graph processing
- Explicit process limits
- Temporary file cleanup

A small analysis job should not require a multi-gigabyte runtime.

Large OS images must be handled without loading the entire image into RAM.

Do not impose an unrealistic fixed RAM target on large-scale decompilation.

### Persistent storage

Use SQLite for:

- Project metadata
- File inventories
- Binary metadata
- Analysis jobs
- Symbol relationships
- Reconstruction provenance
- Recovery progress
- Validation results

Use ordinary filesystem storage for large source files and binary artifacts.

Avoid storing extremely large blobs directly inside SQLite unless justified.

---

# 13. COMMAND-LINE INTERFACE

Develop a clean, professional CLI.

Use familiar UNIX-style conventions and clear help messages.

The executable must be named `reforge`.

### Required commands

**General**

- `reforge --help`
- `reforge --version`
- `reforge doctor`
- `reforge capabilities`

**Image inspection**

- `reforge inspect system.iso`
- `reforge extract system.iso --output extracted`
- `reforge analyze system.iso`

**Decompilation**

- `reforge decompile system.iso --output project`
- `reforge decompile system.iso --backend ghidra`
- `reforge decompile system.iso --jobs 4`

**Reconstruction**

- `reforge reconstruct system.iso --mode recovery`
- `reforge reconstruct system.iso --mode rewrite`
- `reforge reconstruct system.iso --mode hybrid`

**Building and testing**

- `reforge build project`
- `reforge test project --backend qemu`
- `reforge report project`

**Project management**

- `reforge status project`
- `reforge resume project`
- `reforge clean project --temporary`

The actual command parser must reject unsupported options with helpful diagnostics.

Do not advertise features that are not implemented.

### Example usage

A user should be able to run:

    reforge reconstruct operating-system.iso \
      --mode hybrid \
      --output reconstructed-os \
      --jobs 4

The CLI should provide:

- Progress indicators
- Current operation
- File counts
- Completed analysis jobs
- Skipped components
- Warnings
- Errors
- Elapsed time
- Resource usage where available

Support:

- Human-readable output
- JSON output
- Quiet mode
- Verbose mode
- Debug logging
- Noninteractive operation
- Deterministic exit codes

### Resume support

Large operating system images may require extensive analysis.

Support interruption and resuming without repeating completed work.

Use input hashes, tool versions, analysis configuration, and backend versions to determine whether cached results remain valid.

Resume functionality must work across application restarts.

---

# 14. USER CONFIGURATION

Provide an optional TOML configuration file.

Example:

    [general]
    jobs = 4
    cache = true
    offline = true

    [analysis]
    extract_nested = true
    preserve_assembly = true
    recover_symbols = true

    [decompiler]
    backend = "auto"
    timeout_seconds = 600

    [reconstruction]
    mode = "hybrid"
    language = "c"

    [resources]
    max_memory_mb = 2048
    max_disk_gb = 50

    [validation]
    enabled = false
    backend = "qemu"

Actual keys must match the implemented configuration schema.

Use sensible defaults.

Provide configuration validation.

Document all options.

Resource limits must be enforced wherever the host operating system and backend allow them; report when a limit cannot be guaranteed.

---

# 15. BACKEND DEPENDENCIES

ReforgeOS must be usable without manually installing every analysis tool.

### Dependency discovery

Implement the `reforge doctor` command to detect:

- Rust build information
- C compiler availability
- CMake
- Ghidra
- rev.ng
- QEMU
- Image extraction utilities
- Available disk space
- Architecture support

Optional components should be marked as optional.

Do not report the entire installation as broken because QEMU or Ghidra is missing.

### Dependency handling

Provide platform-specific setup instructions.

Prefer package-manager integration and existing installations over bundling massive binaries.

Do not silently download or execute programs.

Any dependency download must be explicitly authorized and verified.

Use version compatibility checks.

If a backend is unavailable, explain which capabilities are affected and how to enable them.

---

# 16. SECURITY REQUIREMENTS

Treat every input ISO, executable, archive, or disk image as untrusted.

Operating system images may contain malicious binaries or malformed filesystem structures.

### Mandatory protections

- Validate input sizes and offsets.
- Prevent integer overflow.
- Prevent path traversal during extraction.
- Prevent uncontrolled symlink traversal.
- Limit recursive extraction depth.
- Limit total extracted data.
- Limit subprocess runtime.
- Avoid shell-string command construction.
- Pass subprocess arguments safely.
- Avoid unsafe temporary file handling.
- Do not execute extracted binaries automatically.
- Keep original images read-only.
- Use unique isolated workspaces.
- Validate external tool results.
- Record relevant operations in logs.
- Clean up interrupted jobs safely.

### Dynamic analysis

Running recovered binaries or operating system images must require explicit user authorization.

Prefer isolated virtual machines.

Disable network connectivity by default.

Do not mount sensitive host directories.

Use disposable writable overlays instead of modifying source images.

Make the limitations of sandboxing on each supported host clear.

### Legal and provenance concerns

The application may be used to analyze proprietary operating systems.

Provide a clear notice that users are responsible for having the necessary rights or authorization for their activities.

Do not bundle proprietary OS binaries or distribute reconstructed proprietary code with the project.

Preserve license metadata and source provenance when known.

Do not attempt to defeat DRM, disk encryption, secure boot protections, or licensing mechanisms.

---

# 17. ERROR HANDLING

This must be suitable for production environments.

Do not rely on panic-based error handling for ordinary input failures.

Use structured Rust errors with meaningful context.

### Required error categories

- Unsupported format
- Corrupted image
- Encrypted image
- Missing dependency
- Unsupported architecture
- Insufficient storage
- Insufficient memory
- Backend failure
- Analysis timeout
- Compilation failure
- Reconstruction blocked
- Filesystem permission failure
- Interrupted operation
- Invalid configuration
- Internal invariant violation

Errors must identify:

- The failed operation
- The relevant file or component
- The underlying cause when known
- Whether retrying is reasonable
- How the user may resolve the problem

Example:

    Error: DECOMPILER_UNAVAILABLE

    The selected Ghidra backend was not found.

    Binary extraction completed successfully.
    Decompilation was not started.

    Run:
      reforge doctor

Never silently ignore failures.

Avoid presenting partial success as full success.

Use atomic writes where appropriate and database transactions to prevent inconsistent project state.

---

# 18. REPORTING SYSTEM

Every project must produce comprehensive machine-readable and human-readable reports.

### Required report formats

- JSON
- Markdown
- Optional HTML

### Required information

- Source image information
- Input hashes
- Detected OS family
- Architecture
- Extracted file count
- Recognized executable count
- Unsupported file count
- Decompiler coverage
- Recovered functions
- Unresolved functions
- Successfully compiled components
- Failed builds
- Validation results
- Missing dependencies
- Backend versions
- Warnings and blockers

### Recovery metrics

Provide separate metrics for:

1. Image extraction coverage
2. Binary analysis coverage
3. Function decompilation coverage
4. Source reconstruction coverage
5. Compilation success
6. Runtime validation coverage

Define denominators precisely.

For example, function recovery coverage must specify whether the denominator includes only discovered functions or an estimated total.

An unidentified function cannot simply be omitted to inflate the result.

### Example report

    ReforgeOS Reconstruction Report

    Extracted files: 1,240
    Recognized binaries: 312
    Binaries analyzed: 290
    Binaries unsupported: 22

    Discovered functions: 18,420
    Decompiled functions: 15,870
    Functions requiring review: 2,550

    Compiled components: 41
    Failed components: 13

    Boot validation: Not performed
    Functional equivalence: Unverified

    Status: PARTIAL_RECONSTRUCTION

These are illustrative report values only, not expected benchmark results.

Never label a reconstruction complete without sufficient evidence.

---

# 19. PROJECT STRUCTURE

Create a complete, properly organized Rust repository.

Suggested structure:

    reforgeos/
    ├── Cargo.toml
    ├── Cargo.lock
    ├── rust-toolchain.toml
    ├── README.md
    ├── LICENSE
    ├── CHANGELOG.md
    ├── SECURITY.md
    ├── CONTRIBUTING.md
    ├── .gitignore
    ├── .github/
    │   └── workflows/
    │       ├── ci.yml
    │       └── release.yml
    ├── crates/
    │   ├── reforge-cli/
    │   ├── reforge-core/
    │   ├── reforge-image/
    │   ├── reforge-binary/
    │   ├── reforge-analysis/
    │   ├── reforge-decompiler/
    │   ├── reforge-reconstruction/
    │   ├── reforge-build/
    │   ├── reforge-validation/
    │   ├── reforge-storage/
    │   └── reforge-report/
    ├── adapters/
    ├── tests/
    ├── fixtures/
    ├── examples/
    ├── docs/
    └── scripts/

This is a suggested structure, not an instruction to create unnecessary empty crates.

Every module should have a clear responsibility.

Prefer simple interfaces and maintainable code over elaborate abstractions.

---

# 20. BUILD AND DISTRIBUTION

The project must be easy to compile from a clean checkout.

### Basic installation

A developer should be able to run:

    git clone <repository-url>
    cd reforgeos
    cargo build --release

After successful compilation, the executable should be available in Cargo's release output directory.

### Required build characteristics

- Stable Rust toolchain
- Explicit dependency versions
- Reproducible dependency resolution
- Minimal default feature set
- Optional native integrations
- Release optimizations
- No mandatory paid dependencies
- No mandatory internet connection at runtime

### Distribution targets

Prepare build configurations for:

- Windows x86-64
- Windows ARM64 where supported
- Linux x86-64
- Linux ARM64
- macOS Intel
- macOS Apple Silicon

Produce platform-appropriate release archives.

Optional package-manager distribution may include:

- Homebrew
- WinGet
- Scoop
- Cargo install
- Linux package repositories

Do not claim package availability before packages have actually been published.

### Automated releases

Use GitHub Actions or an equivalent CI platform.

Build and test all supported release targets.

Use checksums for artifacts.

Generate release notes.

Do not publish packages that fail required validation.

---

# 21. TESTING REQUIREMENTS

The application must have comprehensive automated testing.

### Unit tests

Cover:

- Format detection
- Header parsing
- Symbol extraction
- Hash calculation
- Configuration
- Path normalization
- Resource limits
- Dependency graphs
- Reconstruction metadata
- Error handling

### Integration tests

Cover:

- ISO extraction
- Nested archive handling
- PE analysis
- ELF analysis
- Mach-O analysis
- Backend execution
- Source generation
- Project persistence
- Resume behavior
- Reporting

### End-to-end tests

Use legally redistributable, intentionally small test images and programs.

Suitable candidates include:

- A purpose-built minimal x86 operating system
- A tiny Linux initramfs-based environment
- Open-source educational kernels
- Small test executables compiled for PE, ELF, and Mach-O

Include source code for test fixtures wherever licensing permits.

Compare reconstructed output with the original reference sources and observable behavior.

Do not depend on proprietary Windows or macOS installation images for ordinary CI tests.

### Robustness tests

Test:

- Empty files
- Truncated images
- Invalid headers
- Corrupt archives
- Malformed executable sections
- Excessive nesting
- Very large metadata values
- Duplicate filenames
- Interrupted processes
- Backend timeouts
- Missing disk space
- Unavailable dependencies

Use fuzz testing for parsers and extraction logic.

### Quality checks

Required commands:

    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo build --release

Configure CI to run the appropriate checks on every supported platform.

Do not state that these checks passed unless they have actually been executed successfully.

---

# 22. PERFORMANCE REQUIREMENTS

The application must remain responsive during large analysis jobs.

### Requirements

- Stream image extraction.
- Avoid unnecessary file copies.
- Deduplicate analysis using file hashes.
- Reuse unchanged results.
- Limit concurrent backend processes.
- Avoid keeping entire binary collections in memory.
- Batch database operations.
- Make progress resumable.
- Provide configurable cache locations.
- Clean obsolete temporary data.

Benchmark common workloads.

Measure:

- Startup time
- Image detection time
- Extraction throughput
- Peak RAM usage
- Binary analysis throughput
- Cache effectiveness
- Report generation time

Include benchmark methodology and real measurements.

Do not invent performance results.

Do not compromise correctness solely to obtain smaller benchmarks.

---

# 23. DOCUMENTATION

The repository must include complete documentation.

### README.md

Explain:

- What ReforgeOS does
- What it cannot do
- Supported platforms
- Supported file formats
- Installation
- Basic usage
- Decompiler setup
- Example commands
- Output structure
- Limitations
- Security considerations
- Contribution instructions

### Technical documentation

Provide:

- Architecture overview
- Module responsibilities
- Processing pipeline
- Backend interfaces
- Database schema
- Reconstruction algorithms
- Error code reference
- Supported capability matrix
- Build instructions
- Troubleshooting guide
- Testing guide
- Release process

### Accuracy requirements

Never claim universal source recovery is solved.

Document exactly which analysis and reconstruction capabilities have been implemented and tested.

Differentiate production-ready implemented functionality from experimental research features.

---

# 24. DEVELOPMENT STRATEGY

Implement the project incrementally, but deliver working vertical slices rather than an empty framework.

## Milestone 1 — Functional core

Implement:

- Rust workspace
- CLI
- Configuration
- Logging
- Structured errors
- Project database
- ISO recognition
- Safe extraction
- PE/ELF/Mach-O inspection
- Analysis reports
- Tests

This milestone must build and work independently.

## Milestone 2 — Real decompilation

Implement:

- Ghidra headless integration
- Backend discovery
- Binary import
- Function extraction
- C-like pseudocode export
- Symbol metadata
- Resume support
- Decompilation reports

Validate using small executable fixtures.

## Milestone 3 — Source reconstruction

Implement:

- Function provenance
- Recovered headers
- Symbol relationships
- Source tree generation
- CMake generation
- Compilation attempts
- Build diagnostics
- Unresolved-component reporting

Provide an end-to-end example that generates and compiles source from a small supported binary.

## Milestone 4 — OS-focused analysis

Implement:

- Kernel identification
- Driver classification
- Boot artifact analysis
- Library dependency mapping
- Init and service detection
- OS component graphs
- Windows-specific adapters
- Linux-specific adapters
- macOS-specific adapters

Maintain explicit capability and support statuses.

## Milestone 5 — Runtime validation

Implement:

- QEMU integration
- Controlled runtime execution
- Boot diagnostics
- Test harness
- Differential observations
- Validation reports

Demonstrate the workflow against a small open-source OS.

## Milestone 6 — Production hardening

Complete:

- Windows builds
- macOS builds
- Linux builds
- Comprehensive tests
- Fuzzing coverage
- Resource limits
- Security review
- Reproducible builds
- Release packaging
- Documentation
- Performance optimization

Never skip the earlier functional stages merely to make the project appear complete.

---

# 25. IMPLEMENTATION RULES

Follow these rules throughout development.

1. Write real, compilable Rust code.
2. Do not create placeholder implementations and describe them as complete.
3. Do not introduce unused dependencies.
4. Do not add unnecessary complexity.
5. Do not create fake analysis results.
6. Do not suppress errors without justification.
7. Do not leave accidental panic paths in normal error handling.
8. Do not assume the presence of platform-specific utilities.
9. Do not hardcode development machine paths.
10. Do not invent APIs or crate methods.
11. Check actual dependency APIs and compatibility.
12. Prefer stable, maintained libraries.
13. Keep the native core separate from heavyweight optional backends.
14. Preserve the original inputs.
15. Make every analysis step reproducible.
16. Document unsupported capabilities.
17. Keep generated source traceable to the original binary.
18. Ensure tests exercise real behavior.
19. Keep source code organized and readable.
20. Do not claim zero defects or complete compatibility without evidence.

### Zero-known-error objective

The target is a clean, production-quality implementation with:

- No known build failures on supported targets.
- No failing required tests.
- No unresolved high-severity security findings.
- No known data-loss defects.
- No intentionally ignored compiler warnings.
- No misleading success states.
- No fake or decorative reconstruction functionality.

Absolute freedom from software defects cannot be guaranteed.

Use verification and transparent defect reporting rather than making impossible assurances.

---

# 26. MINIMUM ACCEPTANCE CRITERIA

The first release must demonstrate the following real workflow:

1. Build ReforgeOS from source using Cargo.
2. Run the CLI on Windows, macOS, and Linux CI environments.
3. Open a valid ISO.
4. Identify its format.
5. Extract its supported contents.
6. Locate executable files.
7. Analyze at least one PE, one ELF, and one Mach-O fixture.
8. Invoke an installed Ghidra backend on a supported binary.
9. Export real decompiler output.
10. Generate source files with provenance metadata.
11. Attempt compilation of a supported fixture.
12. Record compilation success or failure accurately.
13. Produce a reconstruction report.
14. Resume an interrupted project.
15. Reject malformed inputs safely.
16. Pass the required automated tests.

In addition, demonstrate a small open-source OS reconstruction exercise.

The demonstration must identify:

- Which components were actually reconstructed.
- Which components compiled.
- Whether the resulting image booted.
- Which runtime tests passed.
- What functionality remains unresolved.

Do not substitute screenshots, fictional terminal logs, or static example files for working functionality.

If a capability cannot be finished, report it honestly and keep it out of the supported feature list.

---

# 27. EXPECTED FINAL DELIVERABLE

Deliver a complete software repository containing:

- Full Rust source code
- Cargo manifests
- Dependency lockfile
- All required internal modules
- Functional command-line interface
- Image parsing and extraction
- Binary analysis
- At least one working decompiler integration
- Source reconstruction pipeline
- Reconstructed project generator
- SQLite project persistence
- Resume capability
- Reporting subsystem
- Automated tests
- CI workflows
- Installation documentation
- Usage examples
- Security documentation
- Build instructions
- License and notices

Do not deliver only a project outline.

Do not create empty files to satisfy a directory structure requirement.

Do not provide pseudocode in place of implementation.

Do not finish after merely constructing an application skeleton.

The final project must build, and its implemented workflows must be testable.

---

# 28. FINAL INSTRUCTIONS TO THE CODING AGENT

You are responsible for turning this specification into real working software.

First, design the smallest coherent architecture that can satisfy the requirements without unnecessary complexity.

Then implement the real project.

Prioritize the following sequence:

**Correct binary handling → accurate analysis → genuine decompilation → traceable source reconstruction → successful compilation → behavioral validation.**

Do not attempt to solve every operating system reverse-engineering problem with a single speculative algorithm.

Use existing mature reverse-engineering technology where beneficial.

Build ReforgeOS as the orchestration, reconstruction, and validation framework that connects these components into a consistent workflow.

Maintain a lightweight native core, with optional advanced backends.

Before considering any implementation complete:

- Compile it.
- Run its tests.
- Review its errors.
- Verify that claimed functionality actually works.
- Document its limitations.
- Ensure it does not fabricate recovered source.
- Confirm that the release builds are reproducible.

When encountering an unexpected technical limitation, implement the strongest correct supported behavior and report the limitation.

Never fabricate success to satisfy a requirement.

The ultimate goal is to create a serious, extensible, universal operating system reverse-engineering and reconstruction framework that researchers and developers can use to inspect compiled operating systems, recover meaningful source code, understand system architecture, and experimentally rebuild compatible implementations.

**Build ReforgeOS as a real, maintainable, production-quality systems engineering project — not as a demonstration that only appears to work.**