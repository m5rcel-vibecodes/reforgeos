# Security

Treat images, binaries, decompiler output and externally supplied project directories
as untrusted. Use an isolated disposable environment for adversarial samples. This
tool is not a malware sandbox; Ghidra invokes native parsers and subprocesses.

Extracted binaries are never executed. Inputs are read-only. Extraction uses a new
private directory, validates paths/ISO extents, rejects collisions, skips links and
special files, and limits files, bytes, depth and available storage. Failed extraction
is not committed. Subprocess arguments are passed without shell-string construction.

Bounds do not provide a hard RSS/disk quota for all third-party libraries or tools.
The Java heap limit does not cover native memory. Polled log caps can overshoot.
Windows timeout handling attempts to terminate the process tree; other platforms
currently kill the direct child only. Concurrent malicious modification of local
project directories is outside the trust model. Do not open untrusted SQLite projects
or backend extensions on sensitive hosts. Inspect recovered source before compilation.

Only analyze authorized material. The tool does not bypass encryption, access controls,
licensing, DRM or secure boot. No proprietary OS code is distributed.

Report vulnerabilities privately through the repository's available security reporting
channel. If none is configured, request a private contact without posting exploit
details publicly. Include a minimized synthetic fixture, version and observed effects.
