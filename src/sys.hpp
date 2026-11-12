// Vajra Binary Core - internal system layer (Linux and Windows, x86-64).
//
// One interface, two implementations: sys_linux.cpp and sys_windows.cpp.
// Everything marked "stop-safe" may be called while other threads are stopped
// (possibly holding the heap lock, the loader lock or libc locks): it does not
// allocate, takes no user-mode locks and goes straight to the kernel.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "vajra/options.hpp"
#include "vajra/status.hpp"

// Byte accesses to code pages must not be instrumented by ThreadSanitizer: it
// has no shadow memory for them.
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define VAJRA_NO_TSAN __attribute__((no_sanitize("thread")))
#endif
#endif
#if !defined(VAJRA_NO_TSAN) && defined(__SANITIZE_THREAD__)
#define VAJRA_NO_TSAN __attribute__((no_sanitize_thread))
#endif
#ifndef VAJRA_NO_TSAN
#define VAJRA_NO_TSAN
#endif

namespace vajra::sys {

using tid_t = long;

// Protection bits used throughout (same values as PROT_* on Linux).
constexpr int kProtRead = 1;
constexpr int kProtWrite = 2;
constexpr int kProtExec = 4;

// ---- threads and time ----
tid_t current_tid() noexcept;                // stop-safe
std::uint64_t monotonic_ns() noexcept;       // stop-safe
void cpu_serialize() noexcept;               // CPUID: serializing instruction for cross-modified code
void sleep_us(long us) noexcept;             // stop-safe

#if defined(__linux__)
// ---- Linux raw system calls (stop-safe); return -errno on failure ----
long raw_syscall(long n, long a1 = 0, long a2 = 0, long a3 = 0, long a4 = 0, long a5 = 0, long a6 = 0) noexcept;
long raw_getpid() noexcept;
long raw_futex_wait(const volatile std::uint32_t* addr, std::uint32_t expected, long timeout_ns) noexcept;
long raw_futex_wake(const volatile std::uint32_t* addr, int count) noexcept;
long raw_mprotect(std::uintptr_t addr, std::size_t len, int prot) noexcept;
#endif

std::size_t page_size() noexcept;
inline std::uintptr_t page_floor(std::uintptr_t a) { return a & ~(static_cast<std::uintptr_t>(page_size()) - 1); }
inline std::uintptr_t page_ceil(std::uintptr_t a) { return page_floor(a + page_size() - 1); }

// ---- address space ----
struct MapEntry {
    std::uintptr_t start = 0;
    std::uintptr_t end = 0;
    int prot = 0;  // kProt* bits
    std::string path;
};
Result read_maps(std::vector<MapEntry>& out);
// Protection of all pages in [addr, addr+len); fails if not uniformly mapped.
Result range_protection(const std::vector<MapEntry>& maps, std::uintptr_t addr, std::size_t len, int* prot);

// Copies up to n bytes; stops at the first unreadable byte. Returns bytes read.
std::size_t safe_read(std::uintptr_t addr, void* out, std::size_t n) noexcept;

// ---- code memory writes ----
// Writes bytes into mapped code or data without leaving any page writable and
// executable at the same time (unless MprotectRWX is chosen explicitly).
class MemoryWriter {
public:
    MemoryWriter() = default;
    ~MemoryWriter();
    MemoryWriter(const MemoryWriter&) = delete;
    MemoryWriter& operator=(const MemoryWriter&) = delete;

    // Not stop-safe: opens what it needs and records the code that must keep
    // running while a page is temporarily non-executable (Vajra itself, and on
    // Windows the system DLLs that implement VirtualProtect).
    Result prepare(WriteMethod method);
    // Stop-safe. `prot` is the current protection of the pages. Returns 0 or a
    // negative errno-style code.
    int write_code(std::uintptr_t addr, const std::uint8_t* data, std::size_t len, int prot) noexcept;
    // Stop-safe. Atomically stores a pointer into a (possibly read-only) data page.
    int write_pointer(std::uintptr_t* slot, std::uintptr_t value, int prot) noexcept;

private:
    bool overlaps_forbidden(std::uintptr_t lo, std::uintptr_t hi) const noexcept;
    int write_direct(std::uintptr_t addr, const std::uint8_t* data, std::size_t len) noexcept;
    int write_reprotect(std::uintptr_t addr, const std::uint8_t* data, std::size_t len, int prot, bool rwx) noexcept;

    int mem_fd_ = -1;  // Linux: /proc/self/mem
    WriteMethod method_ = WriteMethod::Auto;
    struct Range { std::uintptr_t lo, hi; };
    Range forbidden_[32] = {};
    int forbidden_count_ = 0;
};

// ---- executable memory near an address ----
// A block mapped close to code so rel32 displacements reach it.
struct NearBlock {
    std::uintptr_t base = 0;
    std::size_t size = 0;
};
// Maps an anonymous RW block entirely inside [lo, hi).
Result map_near(std::uintptr_t lo, std::uintptr_t hi, std::size_t size, NearBlock& out);
Result protect_exec(const NearBlock& b);  // RW -> RX
void unmap(const NearBlock& b) noexcept;

// ---- loaded modules ----
struct Module {
    std::string name;            // path ("" for the main program on Linux)
    std::uintptr_t bias = 0;     // load bias (Linux) / image base (Windows)
    std::uintptr_t dynamic = 0;  // Linux: runtime address of PT_DYNAMIC
    struct Segment { std::uintptr_t lo, hi; bool exec; };
    std::vector<Segment> segments;
    bool contains(std::uintptr_t a) const {
        for (const auto& s : segments)
            if (a >= s.lo && a < s.hi) return true;
        return false;
    }
    std::string file_path() const;  // usable path of the module file
};
std::vector<Module> list_modules();

// ---- functions in loaded modules ----
struct FunctionInfo {
    std::uintptr_t start = 0;
    std::size_t size = 0;
    std::string name;
    std::string module;
};
// Finds the function containing `addr`. Linux: .symtab / .dynsym of the module
// file. Windows: the x64 unwind table (.pdata). NotFound if there is none.
Result find_function(std::uintptr_t addr, FunctionInfo& out);
// Looks up a function by name (Linux: symbol tables, Windows: export tables).
// module_filter: substring of the module path, empty = any module.
Result find_function_by_name(const std::string& name, const std::string& module_filter, FunctionInfo& out);
// Executable ranges of the module that contains `addr`.
Result module_exec_ranges(std::uintptr_t addr, std::vector<std::pair<std::uintptr_t, std::uintptr_t>>& out);

// ---- import slots (ELF GOT / PE IAT) ----
struct ImportSlot {
    std::uintptr_t* slot = nullptr;
    std::uintptr_t current = 0;   // value now
    std::uintptr_t resolved = 0;  // value once bound (differs from current only for lazy ELF slots)
    bool lazy = false;            // not bound yet
    std::string module;
};
// Every slot through which modules matching `module_filter` (empty = all)
// import `symbol`, except slots of Vajra's own module.
Result find_import_slots(const std::string& symbol, const std::string& module_filter, std::vector<ImportSlot>& out);

// ---- testing hook ----
// When > 0, the n-th following write_code/write_pointer call fails with -EIO.
void set_write_fault_countdown(int n) noexcept;
bool take_write_fault() noexcept;  // used by the implementations

}  // namespace vajra::sys
