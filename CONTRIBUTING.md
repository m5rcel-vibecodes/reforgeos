# Contributing

Deliver working vertical slices with honest capability reporting and optional backends.
Never fabricate source, suppress errors, or stub missing behavior to force compilation.

Run cargo fmt, Clippy with -D warnings, cargo test and cargo build --release. Use
--locked for release verification. Ghidra changes require the optional integration
test in docs/guide.md. Do not claim unexecuted checks passed.

Use small generated fixtures. Document architecture support, security bounds and
provenance. Do not commit proprietary images, downloaded tools or unauthorized
recovered source. Contributions are MIT OR Apache-2.0.
