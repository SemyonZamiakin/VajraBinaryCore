# Changelog

## 0.1.0 (2026-11-13)

First version.

- **Transactions** combining inline hooks, import redirection and type migrations, applied atomically with respect to all other threads; all-or-nothing commit with rollback of partial writes; revert of committed patches (migrations with an inverse plan).
- **Inline hooks** on x86-64: table-driven instruction length decoder (legacy, REX, VEX, EVEX, 0F/0F38/0F3A), prologue relocation (RIP-relative operands, short branches, calls) with explicit refusal rules, function body scan for branches into the patched bytes, trampolines placed within ±2 GiB, CET-compatible (`endbr64`), chaining.
- **Import redirection:** ELF GOT/PLT (`JUMP_SLOT`, `GLOB_DAT`, lazy binding and full RELRO) on Linux, PE IAT on Windows.
- **Stopping threads:** real-time signal + futex on Linux, `NtGetNextThread` + `SuspendThread` on Windows; threads inside the bytes to be rewritten make the patch retry, then fail with `Busy`. Cooperative safe points for mutator threads.
- **Type migration:** runtime type descriptions from `offsetof`, migration plans with rename / fill / drop / transforms, strict or saturating numeric conversions, a tracking heap with stale-version allocation checks, pointer fix-ups in references, roots, interior pointers and cross-type references, quarantine mode.
- **W^X:** code written through `/proc/self/mem` or with temporarily non-executable pages; `MprotectRWX` only on request.
- **Agent and `vajractl`:** Unix socket (Linux) or named pipe (Windows) with same-user access control, patch modules loaded with ownership and TOCTOU checks.
- **Demo:** `arena`, a game-like server patched from Entity v1 to v2 and back while it runs.
- Tests: decoder table and objdump cross-check, relocation, hooks, transactions with fault injection, stop-the-world, migration, GOT/IAT, stress, agent, demo. Linux: GCC, Clang, Debug, ASan+UBSan, TSan (cooperative parts). Windows: MinGW-w64 GCC (MINGW64, UCRT64).
