# Review of PROMPT.md

The specification is a multi-milestone research program. Its central constraints are
correct binary handling, real decompilation, truthful uncertainty, read-only inputs,
and traceable source. Exact original-source recovery and whole-OS rebuilding cannot
be guaranteed from arbitrary compiled installers.

Two crates provide a useful first vertical slice without empty framework modules:
`reforge-core` implements processing/persistence, and `reforge-cli` handles user input.
The sequence is extraction, hashing/inventory, binary inspection, optional Ghidra
analysis, source generation, object-compilation attempt, reporting and resume.

No arbitrary confidence scores, guessed source matching, or dummy function bodies
are used. Compiler failures stop after one attempt; automatic semantic repair is not
implemented. Sources remain genuine decompiler text with explicit provenance.

This implementation does **not** fulfill every first-release acceptance criterion in
PROMPT.md. Outstanding work includes OS-specific image/filesystem adapters, metadata
preservation, PDB/DWARF type recovery, richer OS component mapping, reference source
matching, global/data reconstruction, cross-compilers, rewrite/hybrid modes, parallel
scheduling, QEMU differential validation, an educational OS reconstruction exercise,
fuzzing campaigns, performance measurements and validated non-Windows builds.

CI and packaging target Windows x86-64 only, as requested. No untested performance,
boot, equivalence or production-readiness claim is made.
