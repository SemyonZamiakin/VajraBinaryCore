// Vajra Binary Core - patch options.
// SPDX-License-Identifier: MIT
#pragma once

namespace vajra {

// How code bytes are written.
enum class WriteMethod {
    // ProcMem, falling back to MprotectRW. Never makes a page writable and
    // executable at the same time.
    Auto,
    // pwrite() to /proc/self/mem. The kernel writes through a read-only
    // private mapping (copy-on-write); page protections never change.
    ProcMem,
    // mprotect(RW) without exec, write, restore. Refused for pages that share an
    // executable segment with Vajra itself (the patcher must keep running).
    MprotectRW,
    // mprotect(RWX), write, restore. Briefly violates W^X; opt-in only.
    MprotectRWX,
};

struct PatchOptions {
    // Time allowed for all threads to reach a safe point (cooperative and
    // signal-based stop each get this budget).
    int stop_timeout_ms = 2000;
    // When a stopped thread sits inside bytes that must be rewritten, the
    // world is resumed and the stop is retried this many times.
    int busy_retries = 200;
    int busy_retry_delay_us = 500;
    // Inline hooks normally require the function size (from .symtab/.dynsym)
    // to check that no branch in the function targets the overwritten bytes.
    // Setting this allows hooking functions whose size cannot be determined.
    bool allow_unknown_bounds = false;
    WriteMethod write_method = WriteMethod::Auto;
};

}  // namespace vajra
