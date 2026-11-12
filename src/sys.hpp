// Vajra Binary Core - internal Linux/x86-64 system layer.
//
// Everything marked "signal-safe" may be called while other threads are
// stopped (possibly holding malloc or libc locks): it does not allocate, takes
// no locks and issues system calls directly.
// SPDX-License-Identifier: MIT
#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "vajra/options.hpp"
#include "vajra/status.hpp"

namespace vajra::sys {

// ---- raw system calls (signal-safe); return -errno on failure ----
long raw_syscall(long n, long a1 = 0, long a2 = 0, long a3 = 0, long a4 = 0, long a5 = 0, long a6 = 0) noexcept;
pid_t raw_gettid() noexcept;
pid_t raw_getpid() noexcept;
long raw_futex_wait(const volatile std::uint32_t* addr, std::uint32_t expected, long timeout_ns) noexcept;
long raw_futex_wake(const volatile std::uint32_t* addr, int count) noexcept;
long raw_mprotect(std::uintptr_t addr, std::size_t len, int prot) noexcept;
std::uint64_t monotonic_ns() noexcept;
void cpu_serialize() noexcept;   // CPUID: serializing instruction for cross-modified code
void cpu_relax() noexcept;       // PAUSE
void raw_sleep_us(long us) noexcept;

std::size_t page_size() noexcept;
inline std::uintptr_t page_floor(std::uintptr_t a) { return a & ~(static_cast<std::uintptr_t>(page_size()) - 1); }
inline std::uintptr_t page_ceil(std::uintptr_t a) { return page_floor(a + page_size() - 1); }

// ---- address space ----
struct MapEntry {
    std::uintptr_t start = 0;
    std::uintptr_t end = 0;
    int prot = 0;            // PROT_* bits
    bool is_private = false;
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

    // Not signal-safe: opens /proc/self/mem and records the library's own code
    // segments, which MprotectRW must never make non-executable.
    Result prepare(WriteMethod method);
    // Signal-safe. `prot` is the current protection of the pages. Returns 0 or -errno.
    int write_code(std::uintptr_t addr, const std::uint8_t* data, std::size_t len, int prot) noexcept;
    // Signal-safe. Atomically stores a pointer into a (possibly read-only) data page.
    int write_pointer(std::uintptr_t* slot, std::uintptr_t value, int prot) noexcept;

private:
    bool overlaps_forbidden(std::uintptr_t lo, std::uintptr_t hi) const noexcept;
    int write_procmem(std::uintptr_t addr, const std::uint8_t* data, std::size_t len) noexcept;
    int write_mprotect(std::uintptr_t addr, const std::uint8_t* data, std::size_t len, int prot, bool rwx) noexcept;

    int mem_fd_ = -1;
    WriteMethod method_ = WriteMethod::Auto;
    struct Range { std::uintptr_t lo, hi; };
    Range forbidden_[8] = {};
    int forbidden_count_ = 0;
};

// ---- executable memory near an address ----
// A page-granular block mapped close to code so rel32 displacements reach it.
struct NearBlock {
    std::uintptr_t base = 0;
    std::size_t size = 0;
};
// Maps an anonymous RW block entirely inside [lo, hi).
Result map_near(std::uintptr_t lo, std::uintptr_t hi, std::size_t size, NearBlock& out);
Result protect_exec(const NearBlock& b);   // RW -> RX
void unmap(const NearBlock& b) noexcept;

// ---- loaded modules ----
struct Module {
    std::string name;            // path; "" for the main program
    std::uintptr_t bias = 0;     // load bias (dlpi_addr)
    std::uintptr_t dynamic = 0;  // runtime address of PT_DYNAMIC, 0 if none
    struct Segment { std::uintptr_t lo, hi; int flags; };  // PT_LOAD, runtime addresses, PF_* flags
    std::vector<Segment> segments;
    bool contains(std::uintptr_t a) const {
        for (const auto& s : segments)
            if (a >= s.lo && a < s.hi) return true;
        return false;
    }
    std::string file_path() const;  // name, or /proc/self/exe for the main program
};
std::vector<Module> list_modules();

// ---- ELF symbols of loaded modules ----
struct FunctionInfo {
    std::uintptr_t start = 0;
    std::size_t size = 0;
    std::string name;
    std::string module;
};
// Finds the function symbol containing `addr` in the module's .symtab or
// .dynsym (read from the file on disk). Returns NotFound if there is none.
Result find_function(std::uintptr_t addr, FunctionInfo& out);
// Looks up a function symbol by name in loaded modules (module_filter: substring
// of the module path, empty = any; the main program is "" in dl_iterate_phdr and
// matched as its /proc/self/exe path).
Result find_function_by_name(const std::string& name, const std::string& module_filter, FunctionInfo& out);

// Executable PT_LOAD ranges of the module that contains `addr`.
Result module_exec_ranges(std::uintptr_t addr, std::vector<std::pair<std::uintptr_t, std::uintptr_t>>& out);

// ---- testing hook ----
// When > 0, the n-th following write_code/write_pointer call fails with -EIO.
void set_write_fault_countdown(int n) noexcept;

}  // namespace vajra::sys
