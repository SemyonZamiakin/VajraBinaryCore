// Vajra Binary Core - system layer, Linux implementation.
// SPDX-License-Identifier: MIT
#include "sys.hpp"

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cstring>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static_assert(PROT_READ == 1 && PROT_WRITE == 2 && PROT_EXEC == 4, "kProt* mirror PROT_*");

namespace vajra::sys {

namespace {
const std::size_t g_page_size = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));

// Byte copy that the compiler cannot turn into a libc memcpy call.
VAJRA_NO_TSAN void volatile_copy(std::uintptr_t dst, const std::uint8_t* src, std::size_t n) noexcept {
    volatile std::uint8_t* d = reinterpret_cast<volatile std::uint8_t*>(dst);
    for (std::size_t i = 0; i < n; ++i) d[i] = src[i];
}

VAJRA_NO_TSAN bool volatile_equal(std::uintptr_t a, const std::uint8_t* b, std::size_t n) noexcept {
    const volatile std::uint8_t* p = reinterpret_cast<const volatile std::uint8_t*>(a);
    for (std::size_t i = 0; i < n; ++i)
        if (p[i] != b[i]) return false;
    return true;
}

}  // namespace

// ---------------------------------------------------------------- syscalls

long raw_syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) noexcept {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}

tid_t current_tid() noexcept { return raw_syscall(SYS_gettid); }
long raw_getpid() noexcept { return raw_syscall(SYS_getpid); }

long raw_futex_wait(const volatile std::uint32_t* addr, std::uint32_t expected, long timeout_ns) noexcept {
    struct timespec ts;
    struct timespec* pts = nullptr;
    if (timeout_ns >= 0) {
        ts.tv_sec = timeout_ns / 1000000000L;
        ts.tv_nsec = timeout_ns % 1000000000L;
        pts = &ts;
    }
    constexpr long kFutexWaitPrivate = 0 | 128;  // FUTEX_WAIT | FUTEX_PRIVATE_FLAG
    return raw_syscall(SYS_futex, reinterpret_cast<long>(addr), kFutexWaitPrivate, static_cast<long>(expected),
                       reinterpret_cast<long>(pts));
}

long raw_futex_wake(const volatile std::uint32_t* addr, int count) noexcept {
    constexpr long kFutexWakePrivate = 1 | 128;  // FUTEX_WAKE | FUTEX_PRIVATE_FLAG
    return raw_syscall(SYS_futex, reinterpret_cast<long>(addr), kFutexWakePrivate, count);
}

long raw_mprotect(std::uintptr_t addr, std::size_t len, int prot) noexcept {
    return raw_syscall(SYS_mprotect, static_cast<long>(addr), static_cast<long>(len), prot);
}

std::uint64_t monotonic_ns() noexcept {
    struct timespec ts;
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<std::uint64_t>(ts.tv_nsec);
}

void cpu_serialize() noexcept {
    unsigned a = 0, b, c = 0, d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d) : : "memory");
    (void)b;
    (void)d;
}

void sleep_us(long us) noexcept {
    struct timespec ts;
    ts.tv_sec = us / 1000000L;
    ts.tv_nsec = (us % 1000000L) * 1000L;
    raw_syscall(SYS_nanosleep, reinterpret_cast<long>(&ts), 0);
}

std::size_t page_size() noexcept { return g_page_size; }

// ---------------------------------------------------------------- maps

namespace {
bool read_whole_file(const char* path, std::string& out) {
    out.clear();
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[8192];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        if (n == 0) break;
        out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return true;
}
}  // namespace

Result read_maps(std::vector<MapEntry>& out) {
    out.clear();
    std::string text;
    if (!read_whole_file("/proc/self/maps", text)) return {Status::IoError, "cannot read /proc/self/maps"};
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        const std::string line = text.substr(pos, eol - pos);
        pos = eol + 1;
        if (line.empty()) continue;
        MapEntry e;
        const char* s = line.c_str();
        char* end = nullptr;
        e.start = std::strtoull(s, &end, 16);
        if (*end != '-') continue;
        e.end = std::strtoull(end + 1, &end, 16);
        if (*end != ' ' || std::strlen(end) < 5) continue;
        const char* perms = end + 1;
        if (perms[0] == 'r') e.prot |= kProtRead;
        if (perms[1] == 'w') e.prot |= kProtWrite;
        if (perms[2] == 'x') e.prot |= kProtExec;
        // path: the 6th field, which may contain spaces
        int field = 0;
        const char* p = perms;
        while (*p && field < 4) {  // skip perms, offset, dev, inode
            while (*p && *p != ' ') ++p;
            while (*p == ' ') ++p;
            ++field;
        }
        e.path = p;
        out.push_back(std::move(e));
    }
    std::sort(out.begin(), out.end(), [](const MapEntry& a, const MapEntry& b) { return a.start < b.start; });
    return Result::ok();
}

std::size_t safe_read(std::uintptr_t addr, void* out, std::size_t n) noexcept {
    struct iovec local{out, n};
    struct iovec remote{reinterpret_cast<void*>(addr), n};
    const long r = raw_syscall(SYS_process_vm_readv, raw_getpid(), reinterpret_cast<long>(&local), 1,
                               reinterpret_cast<long>(&remote), 1, 0);
    if (r >= 0) return static_cast<std::size_t>(r);
    // Fallback (e.g. process_vm_readv filtered by seccomp): /proc/self/mem, page by page.
    const int fd = ::open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    std::size_t done = 0;
    while (done < n) {
        const std::uintptr_t a = addr + done;
        const std::size_t chunk = std::min(n - done, static_cast<std::size_t>(page_ceil(a + 1) - a));
        const ssize_t got = ::pread(fd, static_cast<char*>(out) + done, chunk, static_cast<off_t>(a));
        if (got <= 0) break;
        done += static_cast<std::size_t>(got);
        if (static_cast<std::size_t>(got) < chunk) break;
    }
    ::close(fd);
    return done;
}

// ---------------------------------------------------------------- writer

MemoryWriter::~MemoryWriter() {
    if (mem_fd_ >= 0) ::close(mem_fd_);
}

Result MemoryWriter::prepare(WriteMethod method) {
    method_ = method;
    if (method == WriteMethod::Auto || method == WriteMethod::ProcMem) {
        if (mem_fd_ < 0) mem_fd_ = ::open("/proc/self/mem", O_RDWR | O_CLOEXEC);
        if (mem_fd_ < 0 && method == WriteMethod::ProcMem)
            return {Status::PermissionDenied, std::string("cannot open /proc/self/mem: ") + std::strerror(errno)};
    }
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> ranges;
    Result r = module_exec_ranges(reinterpret_cast<std::uintptr_t>(&raw_syscall), ranges);
    if (!r) return r;
    forbidden_count_ = 0;
    for (const auto& rg : ranges) {
        if (forbidden_count_ == static_cast<int>(sizeof forbidden_ / sizeof forbidden_[0])) break;
        forbidden_[forbidden_count_++] = {rg.first, rg.second};
    }
    return Result::ok();
}

bool MemoryWriter::overlaps_forbidden(std::uintptr_t lo, std::uintptr_t hi) const noexcept {
    for (int i = 0; i < forbidden_count_; ++i)
        if (lo < forbidden_[i].hi && forbidden_[i].lo < hi) return true;
    return false;
}

int MemoryWriter::write_direct(std::uintptr_t addr, const std::uint8_t* data, std::size_t len) noexcept {
    if (mem_fd_ < 0) return -EBADF;
    std::size_t done = 0;
    while (done < len) {
        const long n = raw_syscall(SYS_pwrite64, mem_fd_, reinterpret_cast<long>(data + done),
                                   static_cast<long>(len - done), static_cast<long>(addr + done));
        if (n == -EINTR) continue;
        if (n <= 0) return n == 0 ? -EIO : static_cast<int>(n);
        done += static_cast<std::size_t>(n);
    }
    return 0;
}

int MemoryWriter::write_reprotect(std::uintptr_t addr, const std::uint8_t* data, std::size_t len, int prot,
                                 bool rwx) noexcept {
    const std::uintptr_t lo = page_floor(addr);
    const std::uintptr_t hi = page_ceil(addr + len);
    if (!rwx && (prot & kProtExec) && overlaps_forbidden(lo, hi)) return -EPERM;
    const int tmp = rwx ? (kProtRead | kProtWrite | kProtExec) : ((prot & kProtRead) | kProtWrite);
    long r = raw_mprotect(lo, hi - lo, tmp);
    if (r != 0) return static_cast<int>(r);
    volatile_copy(addr, data, len);
    r = raw_mprotect(lo, hi - lo, prot);
    return r != 0 ? static_cast<int>(r) : 0;
}

int MemoryWriter::write_code(std::uintptr_t addr, const std::uint8_t* data, std::size_t len, int prot) noexcept {
    if (take_write_fault()) return -EIO;
    int rc = -EINVAL;
    switch (method_) {
        case WriteMethod::ProcMem:
            rc = write_direct(addr, data, len);
            break;
        case WriteMethod::Auto:
            rc = write_direct(addr, data, len);
            if (rc != 0) rc = write_reprotect(addr, data, len, prot, false);
            break;
        case WriteMethod::MprotectRW:
            rc = write_reprotect(addr, data, len, prot, false);
            break;
        case WriteMethod::MprotectRWX:
            rc = write_reprotect(addr, data, len, prot, true);
            break;
    }
    if (rc != 0) return rc;
    if ((prot & kProtRead) && !volatile_equal(addr, data, len)) return -EIO;
    __builtin___clear_cache(reinterpret_cast<char*>(addr), reinterpret_cast<char*>(addr + len));
    cpu_serialize();
    return 0;
}

int MemoryWriter::write_pointer(std::uintptr_t* slot, std::uintptr_t value, int prot) noexcept {
    if (take_write_fault()) return -EIO;
    const std::uintptr_t a = reinterpret_cast<std::uintptr_t>(slot);
    if (a % alignof(std::uintptr_t) != 0) return -EINVAL;
    if (prot & kProtWrite) {
        __atomic_store_n(slot, value, __ATOMIC_SEQ_CST);
        return 0;
    }
    if (prot & kProtExec) return -EPERM;  // never make an executable page writable
    const std::uintptr_t lo = page_floor(a);
    long r = raw_mprotect(lo, page_size(), prot | kProtWrite);
    if (r != 0) return static_cast<int>(r);
    __atomic_store_n(slot, value, __ATOMIC_SEQ_CST);
    r = raw_mprotect(lo, page_size(), prot);
    return r != 0 ? static_cast<int>(r) : 0;
}

// ---------------------------------------------------------------- near blocks

Result map_near(std::uintptr_t lo, std::uintptr_t hi, std::size_t size, NearBlock& out) {
    size = page_ceil(size);
    constexpr std::uintptr_t kMinAddr = 0x10000;
    constexpr std::uintptr_t kMaxAddr = 0x7ffffffff000ull;
    lo = std::max<std::uintptr_t>(page_ceil(lo), kMinAddr);
    hi = std::min<std::uintptr_t>(page_floor(hi), kMaxAddr);
    if (lo >= hi || hi - lo < size) return {Status::OutOfRange, "empty window for near allocation"};

    std::vector<MapEntry> maps;
    Result r = read_maps(maps);
    if (!r) return r;

    // Free gaps intersected with [lo, hi); keep away from the stack's guard gap.
    struct Cand { std::uintptr_t addr; std::uintptr_t dist; };
    std::vector<Cand> cands;
    const std::uintptr_t center = lo + (hi - lo) / 2;
    auto add_gap = [&](std::uintptr_t g_lo, std::uintptr_t g_hi) {
        g_lo = std::max(g_lo, lo);
        g_hi = std::min(g_hi, hi);
        if (g_hi <= g_lo || g_hi - g_lo < size) return;
        for (std::uintptr_t a : {g_lo, g_hi - size}) {
            const std::uintptr_t d = a > center ? a - center : center - a;
            cands.push_back({a, d});
        }
        // Also the point of the gap closest to the center.
        if (center > g_lo && center + size < g_hi) cands.push_back({page_floor(center), 0});
    };
    std::uintptr_t prev = kMinAddr;
    for (const auto& m : maps) {
        std::uintptr_t gap_hi = m.start;
        if (m.path == "[stack]") gap_hi = m.start > (16u << 20) ? m.start - (16u << 20) : 0;
        if (gap_hi > prev) add_gap(prev, gap_hi);
        prev = std::max(prev, m.end);
    }
    if (prev < kMaxAddr) add_gap(prev, kMaxAddr);
    std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) { return a.dist < b.dist; });

    for (const auto& c : cands) {
        void* p = ::mmap(reinterpret_cast<void*>(c.addr), size, kProtRead | kProtWrite,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED) continue;
        const std::uintptr_t got = reinterpret_cast<std::uintptr_t>(p);
        if (got >= lo && got + size <= hi) {
            out.base = got;
            out.size = size;
            return Result::ok();
        }
        ::munmap(p, size);  // kernel without MAP_FIXED_NOREPLACE treated it as a hint
    }
    return {Status::OutOfRange, "no free address space within +-2 GiB of the target"};
}

Result protect_exec(const NearBlock& b) {
    if (::mprotect(reinterpret_cast<void*>(b.base), b.size, kProtRead | kProtExec) != 0)
        return {Status::ProtectFailed, std::string("mprotect(RX) failed: ") + std::strerror(errno)};
    return Result::ok();
}

void unmap(const NearBlock& b) noexcept {
    if (b.base) ::munmap(reinterpret_cast<void*>(b.base), b.size);
}

// ---------------------------------------------------------------- modules

std::string Module::file_path() const { return name.empty() ? std::string("/proc/self/exe") : name; }

std::vector<Module> list_modules() {
    std::vector<Module> mods;
    ::dl_iterate_phdr(
        [](struct dl_phdr_info* info, size_t, void* data) -> int {
            auto* v = static_cast<std::vector<Module>*>(data);
            Module m;
            m.name = info->dlpi_name ? info->dlpi_name : "";
            m.bias = info->dlpi_addr;
            for (int i = 0; i < info->dlpi_phnum; ++i) {
                const ElfW(Phdr)& ph = info->dlpi_phdr[i];
                if (ph.p_type == PT_LOAD) {
                    m.segments.push_back({info->dlpi_addr + ph.p_vaddr, info->dlpi_addr + ph.p_vaddr + ph.p_memsz,
                                          (ph.p_flags & PF_X) != 0});
                } else if (ph.p_type == PT_DYNAMIC) {
                    m.dynamic = info->dlpi_addr + ph.p_vaddr;
                }
            }
            v->push_back(std::move(m));
            return 0;
        },
        &mods);
    return mods;
}

Result module_exec_ranges(std::uintptr_t addr, std::vector<std::pair<std::uintptr_t, std::uintptr_t>>& out) {
    out.clear();
    for (const auto& m : list_modules()) {
        if (!m.contains(addr)) continue;
        for (const auto& s : m.segments)
            if (s.exec) out.emplace_back(page_floor(s.lo), page_ceil(s.hi));
        return Result::ok();
    }
    return {Status::NotFound, "address is not inside a loaded module"};
}

namespace {

// Read-only view of an ELF file's symbol tables.
class ElfFile {
public:
    ~ElfFile() {
        if (base_) ::munmap(base_, size_);
    }
    bool open(const std::string& path) {
        const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;
        struct stat st;
        if (::fstat(fd, &st) != 0 || st.st_size < static_cast<off_t>(sizeof(Elf64_Ehdr))) {
            ::close(fd);
            return false;
        }
        size_ = static_cast<std::size_t>(st.st_size);
        void* p = ::mmap(nullptr, size_, kProtRead, MAP_PRIVATE, fd, 0);
        ::close(fd);
        if (p == MAP_FAILED) return false;
        base_ = p;
        const auto* eh = static_cast<const Elf64_Ehdr*>(base_);
        if (std::memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_ident[EI_CLASS] != ELFCLASS64) return false;
        if (eh->e_shentsize != sizeof(Elf64_Shdr) || eh->e_shoff == 0) return false;
        if (eh->e_shoff > size_ || static_cast<std::size_t>(eh->e_shnum) * sizeof(Elf64_Shdr) > size_ - eh->e_shoff)
            return false;
        sh_ = reinterpret_cast<const Elf64_Shdr*>(static_cast<const char*>(base_) + eh->e_shoff);
        shnum_ = eh->e_shnum;
        return true;
    }

    // Calls f(name, value, size) for each defined STT_FUNC symbol of the given table type.
    template <class F>
    void for_each_function(std::uint32_t table_type, F&& f) const {
        for (std::size_t i = 0; i < shnum_; ++i) {
            const Elf64_Shdr& s = sh_[i];
            if (s.sh_type != table_type || s.sh_entsize != sizeof(Elf64_Sym)) continue;
            if (s.sh_offset > size_ || s.sh_size > size_ - s.sh_offset) continue;
            if (s.sh_link >= shnum_) continue;
            const Elf64_Shdr& strs = sh_[s.sh_link];
            if (strs.sh_offset > size_ || strs.sh_size > size_ - strs.sh_offset) continue;
            const char* strtab = static_cast<const char*>(base_) + strs.sh_offset;
            const auto* syms = reinterpret_cast<const Elf64_Sym*>(static_cast<const char*>(base_) + s.sh_offset);
            const std::size_t n = s.sh_size / sizeof(Elf64_Sym);
            for (std::size_t k = 0; k < n; ++k) {
                const Elf64_Sym& sym = syms[k];
                if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_shndx == SHN_UNDEF || sym.st_size == 0)
                    continue;
                if (sym.st_name >= strs.sh_size) continue;
                const char* nm = strtab + sym.st_name;
                const std::size_t maxlen = strs.sh_size - sym.st_name;
                const std::size_t len = ::strnlen(nm, maxlen);
                if (len == maxlen) continue;  // unterminated
                if (!f(std::string(nm, len), sym.st_value, sym.st_size)) return;
            }
        }
    }

private:
    void* base_ = nullptr;
    std::size_t size_ = 0;
    const Elf64_Shdr* sh_ = nullptr;
    std::size_t shnum_ = 0;
};

}  // namespace

Result find_function(std::uintptr_t addr, FunctionInfo& out) {
    for (const auto& m : list_modules()) {
        if (!m.contains(addr)) continue;
        ElfFile elf;
        if (!elf.open(m.file_path())) return {Status::NotFound, "cannot read ELF file " + m.file_path()};
        bool found = false;
        for (std::uint32_t table : {static_cast<std::uint32_t>(SHT_SYMTAB), static_cast<std::uint32_t>(SHT_DYNSYM)}) {
            elf.for_each_function(table, [&](const std::string& name, std::uint64_t value, std::uint64_t size) {
                const std::uintptr_t start = m.bias + value;
                if (addr >= start && addr < start + size) {
                    // Prefer a symbol that starts exactly at addr (aliases share bounds anyway).
                    if (!found || start == addr) {
                        out.start = start;
                        out.size = size;
                        out.name = name;
                        out.module = m.file_path();
                        found = true;
                    }
                    if (start == addr) return false;
                }
                return true;
            });
            if (found) return Result::ok();
        }
        return {Status::NotFound, "no function symbol covers the address in " + m.file_path()};
    }
    return {Status::NotFound, "address is not inside a loaded module"};
}

Result find_function_by_name(const std::string& name, const std::string& module_filter, FunctionInfo& out) {
    for (const auto& m : list_modules()) {
        const std::string path = m.file_path();
        if (!module_filter.empty() && path.find(module_filter) == std::string::npos) continue;
        if (m.name.find("linux-vdso") != std::string::npos) continue;
        ElfFile elf;
        if (!elf.open(path)) continue;
        bool found = false;
        for (std::uint32_t table : {static_cast<std::uint32_t>(SHT_SYMTAB), static_cast<std::uint32_t>(SHT_DYNSYM)}) {
            elf.for_each_function(table, [&](const std::string& nm, std::uint64_t value, std::uint64_t size) {
                if (nm != name) return true;
                out.start = m.bias + value;
                out.size = size;
                out.name = nm;
                out.module = path;
                found = true;
                return false;
            });
            if (found) return Result::ok();
        }
    }
    return {Status::NotFound, "function '" + name + "' not found"};
}


// ---------------------------------------------------------------- GOT slots

namespace {

// True if `value` (the content of the JUMP_SLOT with index `rel_index` in
// DT_JMPREL) still points at the lazy-binding PLT stub, i.e. the symbol is not
// bound yet. The stub is `[endbr64] push <rel_index>; jmp ...`, both in the
// classic .plt and in the IBT-enabled .plt used together with .plt.sec.
bool is_lazy_plt_stub(const Module& m, std::uintptr_t value, std::size_t rel_index) {
    if (!m.contains(value)) return false;
    std::uint8_t code[16] = {};
    if (safe_read(value, code, sizeof code) < 9) return false;
    std::size_t p = 0;
    if (code[0] == 0xF3 && code[1] == 0x0F && code[2] == 0x1E && code[3] == 0xFA) p = 4;
    if (code[p] != 0x68) return false;
    std::uint32_t imm;
    std::memcpy(&imm, code + p + 1, sizeof imm);
    return imm == rel_index;
}

std::uintptr_t dyn_ptr(const Module& m, std::uintptr_t v) {
    // glibc relocates d_ptr entries in place; other loaders may not.
    return (m.bias != 0 && v < m.bias) ? v + m.bias : v;
}

}  // namespace

Result find_import_slots(const std::string& symbol, const std::string& module_filter, std::vector<ImportSlot>& out) {
    out.clear();
    const auto self_addr = reinterpret_cast<std::uintptr_t>(&raw_syscall);
    const auto real = reinterpret_cast<std::uintptr_t>(::dlsym(RTLD_DEFAULT, symbol.c_str()));
    for (const auto& m : list_modules()) {
        if (m.dynamic == 0 || m.contains(self_addr)) continue;
        if (m.name.find("linux-vdso") != std::string::npos) continue;
        if (!module_filter.empty() && m.file_path().find(module_filter) == std::string::npos) continue;

        std::uintptr_t symtab = 0, strtab = 0, strsz = 0, jmprel = 0, pltrelsz = 0, rela = 0, relasz = 0;
        std::uintptr_t pltrel = DT_RELA, syment = sizeof(ElfW(Sym)), relaent = sizeof(ElfW(Rela));
        for (const auto* d = reinterpret_cast<const ElfW(Dyn)*>(m.dynamic); d->d_tag != DT_NULL; ++d) {
            switch (d->d_tag) {
                case DT_SYMTAB: symtab = dyn_ptr(m, d->d_un.d_ptr); break;
                case DT_STRTAB: strtab = dyn_ptr(m, d->d_un.d_ptr); break;
                case DT_STRSZ: strsz = d->d_un.d_val; break;
                case DT_JMPREL: jmprel = dyn_ptr(m, d->d_un.d_ptr); break;
                case DT_PLTRELSZ: pltrelsz = d->d_un.d_val; break;
                case DT_PLTREL: pltrel = d->d_un.d_val; break;
                case DT_RELA: rela = dyn_ptr(m, d->d_un.d_ptr); break;
                case DT_RELASZ: relasz = d->d_un.d_val; break;
                case DT_RELAENT: relaent = d->d_un.d_val; break;
                case DT_SYMENT: syment = d->d_un.d_val; break;
                default: break;
            }
        }
        if (symtab == 0 || strtab == 0 || syment != sizeof(ElfW(Sym)) || relaent != sizeof(ElfW(Rela))) continue;
        if (pltrel != DT_RELA) continue;  // x86-64 uses RELA

        auto scan = [&](std::uintptr_t table, std::uintptr_t size, bool lazy_table) {
            if (table == 0 || size == 0) return;
            const auto* r = reinterpret_cast<const ElfW(Rela)*>(table);
            const std::size_t n = size / sizeof(ElfW(Rela));
            for (std::size_t i = 0; i < n; ++i) {
                const auto type = ELF64_R_TYPE(r[i].r_info);
                if (type != R_X86_64_JUMP_SLOT && type != R_X86_64_GLOB_DAT) continue;
                const auto symi = ELF64_R_SYM(r[i].r_info);
                if (symi == 0) continue;
                const auto* sym = reinterpret_cast<const ElfW(Sym)*>(symtab) + symi;
                if (sym->st_name >= strsz) continue;
                const char* nm = reinterpret_cast<const char*>(strtab) + sym->st_name;
                if (symbol != nm) continue;
                const std::uintptr_t slot_addr = m.bias + r[i].r_offset;
                if (!m.contains(slot_addr) || slot_addr % sizeof(std::uintptr_t) != 0) continue;
                ImportSlot s;
                s.slot = reinterpret_cast<std::uintptr_t*>(slot_addr);
                s.current = __atomic_load_n(s.slot, __ATOMIC_SEQ_CST);
                s.lazy = lazy_table && type == R_X86_64_JUMP_SLOT && is_lazy_plt_stub(m, s.current, i);
                s.resolved = s.lazy ? real : s.current;
                s.module = m.file_path();
                out.push_back(std::move(s));
            }
        };
        scan(jmprel, pltrelsz, true);
        scan(rela, relasz, false);
    }
    if (out.empty()) return {Status::NotFound, "no GOT entry for '" + symbol + "' in the selected modules"};
    for (const auto& s : out)
        if (s.lazy && s.resolved == 0) return {Status::NotFound, "cannot resolve '" + symbol + "'"};
    return Result::ok();
}

}  // namespace vajra::sys
