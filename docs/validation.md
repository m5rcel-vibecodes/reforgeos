# Local validation — 2026-10-12

Host: Windows x86-64. Compiler: rustc 1.99.0, native MSVC target. Optional backend:
Ghidra 11.4.2 with Temurin Java 21.0.12.1; CMake 4.4.4 and Visual Studio Build Tools
2026 (MSVC 14.51). Ghidra's official release ZIP was verified against the release
asset SHA-256: `795a02076af16257bd6f3f4736c4fc152ce9ff1f95df35cd47e2adc086e037a6`.

Executed successfully:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`
- `cargo test --workspace --offline`: 17 passed; one optional integration test ignored
- `cargo test -p reforge-core --test pipeline real_ghidra_recovery_and_object_compilation --offline -- --ignored --nocapture`: one passed
- `cargo build --release --locked --offline`
- Release executable version, JSON analysis of the generated ISO, resume and doctor

The optional test extracted a synthetic AMD64 PE from ISO9660, recovered one function
through Ghidra, wrote C/prototypes/provenance, and compiled its containing module to a
Windows object. It also verified persisted compilation status, cached resume, and
refusal to overwrite edited source. Ghidra inferred an undefined8 return type; a
documented unsigned 64-bit storage alias enabled compilation. This is not recovery
of the fixture's original C type or proof of equivalent behavior.

The fixture was not executed or linked into a bootable image. No proprietary OS
images, complete OS reconstruction, QEMU validation, non-Windows builds or cross-host
reproducibility were tested. No performance measurements are claimed.

Environment issues encountered and resolved: Java classpaths required ordinary Win32
paths rather than Rust's verbatim path prefix; Ghidra settings were scoped to the
project. This session's filesystem sandbox restricted Ghidra's script compiler and
MSBuild FileTracker. The real optional integration test ran with authorized sandbox
escalation. Core tests and the Rust Windows release build ran in the normal sandbox.
