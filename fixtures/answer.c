/* SPDX-License-Identifier: MIT OR Apache-2.0
 * Fixture semantics used by tests/support/mod.rs: mov eax, 42; ret.
 * Compile with MSVC /GS- /Od and link /ENTRY:answer /SUBSYSTEM:CONSOLE /NODEFAULTLIB.
 * Never automatically execute this analysis fixture.
 */
int answer(void) { return 42; }
