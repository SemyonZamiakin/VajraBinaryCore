# Vajra Binary Core: design

This document explains how Vajra changes code and data in a running process, what each step relies on, and where the limits are. Source references are to `src/`.

## 1. Scope and attach model

Vajra is an **in-process** library. The program links `libvajra` (a shared library on both platforms) and decides how patches arrive: through its own calls to the API, or through the bundled agent (section 9), which loads patch modules sent by the `vajractl` tool.

There is deliberately no external injector (no `ptrace` attach on Linux, no `CreateRemoteThread` on Windows):

- Type migration needs the program's cooperation anyway: only the program knows where its threads hold no raw pointers into the objects being migrated (section 4), and only the program can register its objects in a `vajra::Heap`.
- An injector is a powerful attack tool and hard to make safe. An opt-in library leaves the trust decision with the program's author.

Platforms: x86-64 Linux (GCC, Clang) and x86-64 Windows (MinGW-w64 GCC). Everything in `x86.cpp`, `relocate.cpp`, `types.cpp`, `migrate.cpp`, `safepoint.cpp` and `patch.cpp` is shared; the platform layer is `sys_linux.cpp` / `sys_windows.cpp` and `stop_linux.cpp` / `stop_windows.cpp` behind `sys.hpp` and `stop.hpp`.

## 2. The transaction

Every change goes through a `Transaction` (`patch.cpp`). `commit()` runs in two phases.

**Prepare (everything that can fail, while the program runs normally):**

1. Read the address space map; record Vajra's own code ranges (they may never be patched).
2. For each hook: find the function's bounds, scan its body, decode and analyse the prologue, allocate a code block near the target, write the relay and the relocated trampoline into it (section 5).
3. Switch all new code blocks from RW to RX.
4. For each import redirect: find every GOT/IAT slot of the symbol (section 6).
5. Compile and validate every migration plan (section 7).
6. Publish the `original` pointers (trampolines, previous import targets) to the caller's variables, so a detour that runs right after the commit already has them. Their previous values are kept for rollback.

**Execute (`execute()` in `patch.cpp`):**

1. If the transaction contains migrations: cooperative stop (section 4) and lock the affected heaps.
2. Prepare the migrations: allocate and fill all new objects, plan all pointer fix-ups. May fail; nothing visible has changed yet.
3. If the transaction contains code or import changes: stop the world (section 3).
4. Check every stopped thread's program counter against the bytes to be rewritten. If one is strictly inside `(entry, entry+5)` for some hook, resume, sleep `busy_retry_delay_us`, retry (up to `busy_retries` times), then fail with `Busy`.
5. Verify that memory still holds exactly the expected bytes / pointer values (detects concurrent patching by someone else). Mismatch: fail with `Mismatch`.
6. Write the code bytes, then the import slots, in order. If a write fails, undo the writes already made in reverse order, then fail with `WriteFailed` (or `Internal` if an undo also failed, which is reported as such).
7. Commit the migrations. This step cannot fail and does not allocate (section 7).
8. Resume the world; unlock the heaps; resume the cooperative stop; free (or quarantine) the old objects.

Steps 3 to 8 run while other threads may be stopped in the middle of anything, including `malloc` or the dynamic loader. Code between `world_stop()` and `world_resume()` therefore performs no allocation, takes no lock other threads could hold, and builds no error strings; error messages are assembled after the resume. On Linux the writes use raw system calls (`syscall` instruction), on Windows `VirtualProtect` / `WriteProcessMemory` / `FlushInstructionCache` (direct kernel calls that do not touch the user-mode heap).

If the commit fails at any step, the prepared code blocks are unmapped (no thread can have reached them), prepared objects are freed, and the caller's `original` pointers are restored. Either every operation takes effect or none does.

A `Patch` records what was done. `revert()` builds the inverse operations (original bytes back, previous slot values back, inverse migrations) and runs them through the same `execute()`. A code revert is refused with `Mismatch` if the bytes no longer hold what Vajra wrote, e.g. because another hook was stacked on top; revert in reverse order. A migration reverts only if an inverse plan was supplied (`NotRevertible` otherwise).

All transactions and reverts in the process are serialized by one mutex.

## 3. Stopping the world

`stop_linux.cpp`:

- A real-time signal (default `SIGRTMIN+7`, configurable, must have no other handler) is sent with `rt_tgsigqueueinfo` to every thread listed in `/proc/self/task`, carrying a generation number. The handler records the interrupted `RIP`/`RSP` from the `ucontext`, increments an arrival counter and waits on a futex until the stopper releases that generation, then executes `CPUID` (a serializing instruction, required after cross-modifying code) and leaves.
- After all signalled threads arrived, the task list is read again; threads created in the meantime (by threads that had not stopped yet) are signalled too. The stop is complete when a full rescan finds no new thread. A stopped thread cannot create threads, so this terminates.
- A thread that exits before handling its signal is detected through `/proc/self/task/<tid>/stat` (gone, or zombie) and no longer waited for. A thread that blocks the signal makes the stop time out: everyone is resumed and the patch fails with `Timeout`, naming the thread.
- Stale signals (from an earlier, timed-out stop) are recognized by their generation and ignored. The handler, the release and the in-flight counter are ordered so that no handler can still be inside a finished stop when the next one begins.
- All of this uses raw system calls and static buffers; nothing allocates.

`stop_windows.cpp`:

- Threads are enumerated with `NtGetNextThread` (no user-mode heap, no loader lock), suspended with `SuspendThread`, and their context read with `GetThreadContext`, which also waits until the suspension has actually happened. Enumeration repeats until a pass finds no new thread. Resume is `ResumeThread`, which on return to user mode implies the instruction fetch sees the new bytes after `FlushInstructionCache`.

**Why recording the PC is enough.** A hook overwrites only bytes `[entry, entry+5)` with one `jmp rel32`. A thread stopped exactly at `entry` will execute the new jump. A thread stopped at an instruction boundary at or after `entry+5` continues in untouched original code. Only a PC strictly inside `(entry, entry+5)` is unsafe, and that is what the check rejects. Return addresses on stacks are handled by the relocation rules: a `call` whose return address would land inside the overwritten bytes is refused (section 5).

**Under ThreadSanitizer** asynchronous signals are deferred until a thread calls into the TSan runtime, so the Linux world stop cannot work there; the TSan configuration only runs tests that do not need it.

## 4. Cooperative safe points

`safepoint.cpp`. A thread that touches migratable objects calls `Safepoints::attach()` once and `Safepoints::poll()` regularly; `poll()` is one acquire load when nothing is pending. A thread that blocks for a long time wraps the blocking call in a `BlockingRegion`.

`coop_stop()` sets the request flag and waits (with a timeout) until every attached thread other than the caller is parked in `poll()` or inside a region. Parked threads wait on a condition variable; a thread leaving a region during a stop waits at the exit. A thread attaching during a stop parks before `attach()` returns. Everything is mutex/condvar based, so the memory effects of the migration are visible to the threads when they resume (and ThreadSanitizer can verify it).

**The application's contract:** at a `poll()` call (and inside a region) a mutator holds no raw pointers into migratable objects except through registered roots. In practice: poll at the top of the work loop and re-read pointers from roots after it. A mutator that never polls makes every migration time out (`Timeout`), it never makes it unsafe.

## 5. Inline hooks

**Bounds and body scan** (`prepare_hook` in `patch.cpp`). The target must be in executable memory, outside Vajra's own code, and at a function entry. Bounds come from the module file's `.symtab` / `.dynsym` on Linux (read from disk; the main program via `/proc/self/exe`) and from the `.pdata` unwind table on Windows (chained entries are followed to the primary function, so a cold fragment is never mistaken for a function start). The whole function body is decoded linearly and every relative branch is checked: one that targets `(entry, entry+5)` makes the hook fail. A function without bounds is refused unless `allow_unknown_bounds` is set; a function shorter than 5 bytes is accepted only if the remaining bytes are padding (int3 / nop, checked by decoding) and no other function symbol starts there.

**Decoder** (`x86.cpp`). A table-driven length decoder for 64-bit mode: legacy prefixes, REX (only when directly before the opcode), VEX 2/3-byte, EVEX (maps 1, 2, 3, 5, 6), the 0F, 0F38 and 0F3A maps, ModRM/SIB/displacement, every immediate form (including `66`-dependent sizes, `moffs`, `enter`, group 3 `test`, `extrq`/`insertq`, 3DNow! suffixes, `mov cr/dr` ignoring `mod`), RIP-relative detection and relative branches. It refuses rather than guesses: invalid opcodes in 64-bit mode, AMD XOP, Intel APX (REX2, EVEX map 4), and relative branches with a `66` prefix (whose operand size differs between Intel and AMD). It is checked against GNU objdump on millions of instructions from real binaries on every test run.

**Relocation** (`relocate.cpp`). The instructions covering the first 5 bytes are re-encoded at the trampoline address:

| Instruction in the prologue | In the trampoline |
|---|---|
| no relative operand | copied |
| RIP-relative memory operand | copied with a new `disp32`; refused if the target is out of ±2 GiB |
| `jmp` rel8/rel32 | `jmp rel32`, or `jmp [rip+0]; .quad target` when out of range |
| `jcc` rel8/rel32 | `jcc rel32`, or inverted short `jcc` over an absolute jump |
| `call rel32` | `call rel32`, or `call [rip+2]; jmp +8; .quad target` |
| `loop`/`jrcxz`, `xbegin`, EIP-relative (`67`) operands | refused |
| any `call` ending inside the first 5 bytes | refused (its return address would point into rewritten code) |
| any branch into `[entry, entry+5)`, or into the middle of an instruction | refused |
| `ret`/`jmp` before byte 5 | accepted only if the rest is padding |

The trampoline starts with `endbr64` (unless the original did) so it is a valid indirect-branch target under CET/IBT, and ends with a jump back to `entry + stolen`. The hook site gets `jmp rel32` to a 14-byte relay (`jmp [rip+0]; .quad detour`) placed next to the trampoline, so the detour itself may be anywhere in the address space.

**Code memory near the target** (`map_near`). The trampoline must be within ±2 GiB of the target and of every RIP-relative operand it carries. Vajra intersects those windows (minus a 64 KiB margin), lists free regions from `/proc/self/maps` or `VirtualQuery`, sorts candidates by distance to the middle of the window and maps an RW block there (`MAP_FIXED_NOREPLACE` / `VirtualAlloc` at an explicit address), avoiding the stack's guard gap on Linux. Blocks are per transaction, switched to RX before the patch goes live, and never freed after a successful commit.

**Chaining.** Hooking an already hooked function relocates the existing `jmp rel32`, so the new trampoline leads to the previous detour. Reverts must happen in reverse order (enforced by the byte check).

## 6. Import redirection

**Linux** (`find_import_slots` in `sys_linux.cpp`). For every loaded module (except Vajra itself) matching the filter, the dynamic section gives `DT_JMPREL`, `DT_RELA`, the symbol and string tables. Every `R_X86_64_JUMP_SLOT` and `R_X86_64_GLOB_DAT` relocation for the symbol yields a slot address. A lazy `JUMP_SLOT` that is not bound yet is recognized precisely: it points at the PLT stub `[endbr64] push <its relocation index>`. For such slots the value the dynamic linker would write (`dlsym(RTLD_DEFAULT, ...)`) is also accepted at commit time.

**Windows** (`sys_windows.cpp`). The import directory of every module gives, per imported DLL, the name table and the IAT; every named import matching the symbol yields a slot. The IAT is bound at load, so slots are never lazy. Delay-load imports are not handled.

Slots are written with an aligned 8-byte atomic store. A read-only page (full RELRO, protected IAT) is made writable (never executable) for the store and restored. On Linux a thread that was stopped inside the lazy-binding resolver could write the resolved address after the resume; Vajra re-checks every writable slot after the resume and restores the redirect with a compare-and-swap if that happened.

Import redirection only affects calls that go through those slots. Function pointers taken earlier and direct calls inside the defining module are not redirected; use an inline hook for those. A replacement must call the original through the returned `original` pointer: calling the symbol by name from a redirected module goes through the redirected slot again.

## 7. Type migration

**Descriptions** (`types.hpp`). `describe<T>()` records a type's name, version, size, alignment and fields. Fields are declared with `offsetof` through `VAJRA_FIELD` / `VAJRA_REF`, so the description cannot drift from the compiled struct; kinds are derived from the member types. Types must be trivially copyable and standard-layout. `validate()` checks names, bounds, overlaps, kind sizes and alignment.

**Plans** (`MigrationPlan`). Fields map by name; `rename()` maps differently named fields, `fill_*()` sets new fields, unmapped new fields are zeroed. Every old field must have a destination or be dropped explicitly with `drop()`: data loss is never silent. Compilation rejects ambiguous mappings, incompatible kinds (number ↔ pointer, reference type changes) and fill values that do not fit. Conversions between numeric kinds follow the plan's policy:

- `Strict` (default): a value that would change fails the migration: out-of-range integers, non-integral or out-of-range floats into integers, NaN into integers, integers not exactly representable in the float type, non-0/1 into bool, truncating non-zero bytes, f64 → f32 overflow. Rounding f64 → f32 is allowed.
- `Saturate`: clamp; float → int truncates toward zero; NaN → 0.

Custom code runs after the field mapping through `transform()`, with typed name-based access (`ObjectView`) and `MigrationContext::fail()`.

**The heap** (`Heap`). Objects of migratable types are allocated through `Heap::allocate(type, version)`, which returns `nullptr` if `version` is not the current one: stale code that would build old-layout objects after a migration is caught instead of corrupting memory. Objects are tracked in an ordered map, which also resolves interior pointers. Root slots (`add_root`, `add_root_range`) are pointer variables outside the heap that the migration may rewrite.

**Running a migration** (`MigrationJob` in `migrate.cpp`), with all mutators parked and the heap locked:

- `prepare()`: check that the heap's current layout is exactly the plan's source layout; allocate a zeroed object of the new layout for every old object; convert each one (field mapping, then transforms); remap `Ref` fields inside the new objects (start pointers, and interior pointers to fields that have a destination); validate that every other `Ref` points to a live object of the declared type; plan the writes to root slots and to `Ref` fields of other types' objects. Any failure frees everything prepared and changes nothing.
- `commit()`: apply the planned pointer writes, re-key each object in the heap map by moving the map node (no allocation), and swap the type's current description with a prepared copy (no allocation). It cannot fail, so it is safe while other threads are stopped by signal.
- After resume: free the old objects, or with quarantine mode fill them with `0xDD` and keep them, so a stale pointer reads garbage instead of reused memory.

A pointer to offset 0 of an object is treated as a pointer to the object (not to its first field). Pointers to old objects held anywhere else (locals across a safe point, containers not registered as roots) are not updated; that is the application's contract from section 4.

## 8. W^X and instruction-cache coherence

Writes to code (`MemoryWriter` in `sys_*.cpp`), by `WriteMethod`:

| Method | Linux | Windows |
|---|---|---|
| `Auto` (default) | `ProcMem`, falling back to `MprotectRW` | `MprotectRW`; for the system DLLs on the `VirtualProtect` path (ntdll, kernelbase, kernel32) `WriteProcessMemory` |
| `ProcMem` | `pwrite` to `/proc/self/mem`: the kernel writes through the read-only private mapping (copy-on-write); the protection never changes | `WriteProcessMemory` on the own process |
| `MprotectRW` | `mprotect` RW without X, write, restore | `VirtualProtect` `PAGE_READWRITE`, write, restore |
| `MprotectRWX` | RWX briefly (opt-in) | `PAGE_EXECUTE_READWRITE` briefly (opt-in) |

`MprotectRW` makes the page non-executable while it is written. That is safe because every other thread is stopped, and the writer refuses it for pages that share an executable segment with code that must keep running meanwhile (Vajra itself; on Windows also the system DLLs it calls). Note that `WriteProcessMemory` may itself change page protection internally. Every write is verified by reading the bytes back.

After writing, the writer calls `__builtin___clear_cache` / `FlushInstructionCache` and executes `CPUID`. Threads stopped by signal execute `CPUID` before leaving the handler; threads parked at safe points do so after waking. Windows threads resume through the kernel.

## 9. The agent and the security model

The agent (`agent.cpp`) runs a listener thread:

- **Linux:** a Unix domain socket created with `umask 077`, `chmod 0600`; an existing path is replaced only if it is a socket owned by the same user. Every connection's peer uid (`SO_PEERCRED`) must equal the process's effective uid.
- **Windows:** a named pipe created with `FILE_FLAG_FIRST_PIPE_INSTANCE` (fails if someone else owns the name), `PIPE_REJECT_REMOTE_CLIENTS`, and a protected DACL granting access to the current user's SID only.

One command per connection, one line, 4 KiB maximum, 5 s read timeout. `apply` loads a module only if the file is owned by the current user (or root; on Windows also Administrators, SYSTEM, TrustedInstaller); on Linux it must not be writable by group or others, is opened with `O_NOFOLLOW` and loaded through `/proc/self/fd/N`, so the file that was checked is the file that is loaded; on Windows the file is held open without write sharing while `LoadLibrary` maps it, reparse points are refused, and the PE signature is checked first. The module's `vajra_patch_entry` builds a transaction, which the agent commits.

What this protects against, and what it does not:

| Threat | Status |
|---|---|
| Another local user applying patches | Blocked by socket permissions + peer uid check / pipe DACL |
| Remote clients | Unix sockets are local; the pipe rejects remote clients |
| Swapping the module file between check and load | Blocked (descriptor-based load / no write sharing) |
| A module planted in a world-writable location | Refused on Linux (permissions); on Windows only ownership is checked |
| A process of the **same user** applying patches | **Allowed by design**: same-user processes can already debug or modify each other. Do not run the agent in a process that is more privileged than its user, or do not start the agent there |
| A malicious module | Out of scope: a module is native code running in the process. Applying a module is equivalent to running it |
| Bugs in a patch (wrong layout description, detour with the wrong signature) | Not detectable in general. Layout descriptions are checked for consistency and against the heap's current version; signatures are not checked |

Patching is an inherently privileged operation. Ship the agent only in builds where live patching is wanted, keep the socket in a private directory, and treat patch modules like executables.

## 10. Testing approach

See the README for the suite list. Points worth noting about how correctness is checked:

- The decoder is compared against an independent implementation (GNU objdump) on every instruction of several large binaries, on both platforms.
- Rollback is tested with fault injection (`sys::set_write_fault_countdown`) at every write position of multi-operation transactions, for both commit and revert.
- The stop-the-world guarantee is tested directly: counters incremented by spinning threads must not move while the world is stopped, including threads created during the stop.
- Stress tests patch and migrate while threads continuously use the patched code and data, checking every result and global invariants afterwards, under ASan/UBSan on Linux.
