// Vajra Binary Core - system layer, Windows (x64) implementation.
// SPDX-License-Identifier: MIT
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

#include "sys.hpp"

namespace vajra::sys {

namespace {

std::size_t query_page_size() {
    SYSTEM_INFO si;
    ::GetSystemInfo(&si);
    return si.dwPageSize;
}
std::size_t query_granularity() {
    SYSTEM_INFO si;
    ::GetSystemInfo(&si);
    return si.dwAllocationGranularity;
}
const std::size_t g_page_size = query_page_size();
const std::size_t g_granularity = query_granularity();

int prot_from_win(DWORD p) {
    if (p & (PAGE_GUARD | PAGE_NOACCESS)) return 0;
    switch (p & 0xFF) {
        case PAGE_READONLY: return kProtRead;
        case PAGE_READWRITE:
        case PAGE_WRITECOPY: return kProtRead | kProtWrite;
        case PAGE_EXECUTE: return kProtExec;
        case PAGE_EXECUTE_READ: return kProtRead | kProtExec;
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY: return kProtRead | kProtWrite | kProtExec;
        default: return 0;
    }
}

std::string narrow(const wchar_t* w) {
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(static_cast<std::size_t>(n - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}

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

const IMAGE_NT_HEADERS64* nt_headers(std::uintptr_t base) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return nullptr;
    return nt;
}

const Module* module_for(const std::vector<Module>& mods, std::uintptr_t a) {
    for (const auto& m : mods)
        if (m.contains(a)) return &m;
    return nullptr;
}

// Name of an exported function that starts at `rva`, or "".
std::string export_name_at(std::uintptr_t base, DWORD rva) {
    const auto* nt = nt_headers(base);
    if (!nt) return {};
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return {};
    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    const auto* funcs = reinterpret_cast<const DWORD*>(base + exp->AddressOfFunctions);
    const auto* names = reinterpret_cast<const DWORD*>(base + exp->AddressOfNames);
    const auto* ords = reinterpret_cast<const WORD*>(base + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        if (ords[i] < exp->NumberOfFunctions && funcs[ords[i]] == rva)
            return reinterpret_cast<const char*>(base + names[i]);
    }
    return {};
}

}  // namespace

// ---------------------------------------------------------------- threads, time

tid_t current_tid() noexcept { return static_cast<tid_t>(::GetCurrentThreadId()); }

std::uint64_t monotonic_ns() noexcept {
    static LARGE_INTEGER freq = [] {
        LARGE_INTEGER f;
        ::QueryPerformanceFrequency(&f);
        return f;
    }();
    LARGE_INTEGER now;
    ::QueryPerformanceCounter(&now);
    const auto q = static_cast<std::uint64_t>(now.QuadPart);
    const auto f = static_cast<std::uint64_t>(freq.QuadPart);
    return q / f * 1000000000ull + (q % f) * 1000000000ull / f;
}

void cpu_serialize() noexcept {
    unsigned a = 0, b, c = 0, d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d) : : "memory");
    (void)b;
    (void)d;
}

void sleep_us(long us) noexcept { ::Sleep(static_cast<DWORD>((us + 999) / 1000)); }

std::size_t page_size() noexcept { return g_page_size; }

// ---------------------------------------------------------------- address space

Result read_maps(std::vector<MapEntry>& out) {
    out.clear();
    std::uintptr_t a = 0;
    MEMORY_BASIC_INFORMATION mbi;
    while (::VirtualQuery(reinterpret_cast<void*>(a), &mbi, sizeof mbi) == sizeof mbi) {
        const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const std::uintptr_t end = base + mbi.RegionSize;
        if (mbi.State != MEM_FREE) {
            MapEntry e;
            e.start = base;
            e.end = end;
            e.prot = mbi.State == MEM_COMMIT ? prot_from_win(mbi.Protect) : 0;
            out.push_back(std::move(e));
        }
        if (end <= a) break;
        a = end;
    }
    return Result::ok();
}

std::size_t safe_read(std::uintptr_t addr, void* out, std::size_t n) noexcept {
    std::size_t done = 0;
    while (done < n) {
        const std::uintptr_t a = addr + done;
        const std::size_t chunk = std::min(n - done, static_cast<std::size_t>(page_ceil(a + 1) - a));
        SIZE_T got = 0;
        if (!::ReadProcessMemory(::GetCurrentProcess(), reinterpret_cast<const void*>(a),
                                 static_cast<char*>(out) + done, chunk, &got) ||
            got != chunk)
            break;
        done += chunk;
    }
    return done;
}

// ---------------------------------------------------------------- writer

MemoryWriter::~MemoryWriter() = default;

Result MemoryWriter::prepare(WriteMethod method) {
    method_ = method;
    forbidden_count_ = 0;
    // Code that runs while a page is temporarily non-executable: Vajra itself
    // and the DLLs on the VirtualProtect path.
    std::vector<std::uintptr_t> anchors = {reinterpret_cast<std::uintptr_t>(&page_size)};
    for (const wchar_t* dll : {L"ntdll.dll", L"kernelbase.dll", L"kernel32.dll"})
        if (HMODULE h = ::GetModuleHandleW(dll)) anchors.push_back(reinterpret_cast<std::uintptr_t>(h) + 0x1000);
    for (std::uintptr_t a : anchors) {
        std::vector<std::pair<std::uintptr_t, std::uintptr_t>> ranges;
        if (!module_exec_ranges(a, ranges)) continue;
        for (const auto& rg : ranges) {
            if (forbidden_count_ == static_cast<int>(sizeof forbidden_ / sizeof forbidden_[0])) break;
            forbidden_[forbidden_count_++] = {rg.first, rg.second};
        }
    }
    return Result::ok();
}

bool MemoryWriter::overlaps_forbidden(std::uintptr_t lo, std::uintptr_t hi) const noexcept {
    for (int i = 0; i < forbidden_count_; ++i)
        if (lo < forbidden_[i].hi && forbidden_[i].lo < hi) return true;
    return false;
}

int MemoryWriter::write_direct(std::uintptr_t addr, const std::uint8_t* data, std::size_t len) noexcept {
    SIZE_T written = 0;
    if (!::WriteProcessMemory(::GetCurrentProcess(), reinterpret_cast<void*>(addr), data, len, &written) ||
        written != len)
        return -EIO;
    return 0;
}

int MemoryWriter::write_reprotect(std::uintptr_t addr, const std::uint8_t* data, std::size_t len, int prot,
                                  bool rwx) noexcept {
    const std::uintptr_t lo = page_floor(addr);
    const std::uintptr_t hi = page_ceil(addr + len);
    if (!rwx && (prot & kProtExec) && overlaps_forbidden(lo, hi)) return -EPERM;
    DWORD old = 0;
    if (!::VirtualProtect(reinterpret_cast<void*>(lo), hi - lo, rwx ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &old)) return -EACCES;
    volatile_copy(addr, data, len);
    DWORD tmp = 0;
    if (!::VirtualProtect(reinterpret_cast<void*>(lo), hi - lo, old, &tmp)) return -EIO;
    return 0;
}

int MemoryWriter::write_code(std::uintptr_t addr, const std::uint8_t* data, std::size_t len, int prot) noexcept {
    if (take_write_fault()) return -EIO;
    int rc = -EINVAL;
    switch (method_) {
        case WriteMethod::ProcMem:
            rc = write_direct(addr, data, len);
            break;
        case WriteMethod::Auto:
            rc = write_reprotect(addr, data, len, prot, false);
            if (rc == -EPERM) rc = write_direct(addr, data, len);  // system DLL on the VirtualProtect path
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
    ::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<void*>(addr), len);
    cpu_serialize();
    return 0;
}

int MemoryWriter::write_pointer(std::uintptr_t* slot, std::uintptr_t value, int prot) noexcept {
    if (take_write_fault()) return -EIO;
    const auto a = reinterpret_cast<std::uintptr_t>(slot);
    if (a % alignof(std::uintptr_t) != 0) return -EINVAL;
    if (prot & kProtWrite) {
        __atomic_store_n(slot, value, __ATOMIC_SEQ_CST);
        return 0;
    }
    if (prot & kProtExec) return -EPERM;  // never make an executable page writable
    const std::uintptr_t lo = page_floor(a);
    DWORD old = 0;
    if (!::VirtualProtect(reinterpret_cast<void*>(lo), page_size(), PAGE_READWRITE, &old)) return -EACCES;
    __atomic_store_n(slot, value, __ATOMIC_SEQ_CST);
    DWORD tmp = 0;
    if (!::VirtualProtect(reinterpret_cast<void*>(lo), page_size(), old, &tmp)) return -EIO;
    return 0;
}

// ---------------------------------------------------------------- near blocks

Result map_near(std::uintptr_t lo, std::uintptr_t hi, std::size_t size, NearBlock& out) {
    const std::uintptr_t gran = g_granularity;
    size = (size + gran - 1) / gran * gran;
    constexpr std::uintptr_t kMinAddr = 0x10000;
    constexpr std::uintptr_t kMaxAddr = 0x7FFFFFFEFFFFull;
    lo = std::max<std::uintptr_t>((lo + gran - 1) / gran * gran, kMinAddr);
    hi = std::min<std::uintptr_t>(hi / gran * gran, kMaxAddr);
    if (lo >= hi || hi - lo < size) return {Status::OutOfRange, "empty window for near allocation"};

    struct Cand { std::uintptr_t addr; std::uintptr_t dist; };
    std::vector<Cand> cands;
    const std::uintptr_t center = lo + (hi - lo) / 2;
    std::uintptr_t a = lo;
    MEMORY_BASIC_INFORMATION mbi;
    while (a < hi && ::VirtualQuery(reinterpret_cast<void*>(a), &mbi, sizeof mbi) == sizeof mbi) {
        const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const std::uintptr_t end = base + mbi.RegionSize;
        if (mbi.State == MEM_FREE) {
            const std::uintptr_t g_lo = std::max(lo, (base + gran - 1) / gran * gran);
            const std::uintptr_t g_hi = std::min(hi, end / gran * gran);
            if (g_hi > g_lo && g_hi - g_lo >= size) {
                for (std::uintptr_t c : {g_lo, g_hi - size}) cands.push_back({c, c > center ? c - center : center - c});
            }
        }
        if (end <= a) break;
        a = end;
    }
    std::sort(cands.begin(), cands.end(), [](const Cand& x, const Cand& y) { return x.dist < y.dist; });
    for (const auto& c : cands) {
        void* p = ::VirtualAlloc(reinterpret_cast<void*>(c.addr), size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!p) continue;
        out.base = reinterpret_cast<std::uintptr_t>(p);
        out.size = size;
        return Result::ok();
    }
    return {Status::OutOfRange, "no free address space within +-2 GiB of the target"};
}

Result protect_exec(const NearBlock& b) {
    DWORD old = 0;
    if (!::VirtualProtect(reinterpret_cast<void*>(b.base), b.size, PAGE_EXECUTE_READ, &old))
        return {Status::ProtectFailed, "VirtualProtect(PAGE_EXECUTE_READ) failed: error " +
                                           std::to_string(::GetLastError())};
    ::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<void*>(b.base), b.size);
    return Result::ok();
}

void unmap(const NearBlock& b) noexcept {
    if (b.base) ::VirtualFree(reinterpret_cast<void*>(b.base), 0, MEM_RELEASE);
}

// ---------------------------------------------------------------- modules

std::string Module::file_path() const { return name; }

std::vector<Module> list_modules() {
    std::vector<Module> mods;
    std::vector<HMODULE> handles(512);
    DWORD needed = 0;
    for (;;) {
        if (!::K32EnumProcessModules(::GetCurrentProcess(), handles.data(),
                                     static_cast<DWORD>(handles.size() * sizeof(HMODULE)), &needed))
            return mods;
        if (needed <= handles.size() * sizeof(HMODULE)) break;
        handles.resize(needed / sizeof(HMODULE) + 16);
    }
    handles.resize(needed / sizeof(HMODULE));
    for (HMODULE h : handles) {
        const auto base = reinterpret_cast<std::uintptr_t>(h);
        const auto* nt = nt_headers(base);
        if (!nt) continue;
        Module m;
        wchar_t path[MAX_PATH * 2];
        const DWORD n = ::GetModuleFileNameW(h, path, static_cast<DWORD>(sizeof path / sizeof path[0]));
        if (n > 0 && n < sizeof path / sizeof path[0]) m.name = narrow(path);
        m.bias = base;
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const std::uintptr_t s_lo = base + sec[i].VirtualAddress;
            const std::uintptr_t s_hi = s_lo + std::max<DWORD>(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
            m.segments.push_back({s_lo, s_hi, (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0});
        }
        mods.push_back(std::move(m));
    }
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

// ---------------------------------------------------------------- functions (.pdata)

Result find_function(std::uintptr_t addr, FunctionInfo& out) {
    DWORD64 image = 0;
    const RUNTIME_FUNCTION* rf = ::RtlLookupFunctionEntry(addr, &image, nullptr);
    if (!rf) return {Status::NotFound, "no unwind entry covers the address (leaf function without .pdata?)"};
    // Follow chained entries to the primary function (non-contiguous functions).
    const RUNTIME_FUNCTION* primary = rf;
    for (int depth = 0; depth < 32; ++depth) {
        if (primary->UnwindData & 1) break;  // indirect entry; not produced for x64 code we handle
        const auto* info = reinterpret_cast<const std::uint8_t*>(image + primary->UnwindData);
        const std::uint8_t flags = info[0] >> 3;
        if (!(flags & UNW_FLAG_CHAININFO)) break;
        const std::uint8_t count = info[2];
        const std::size_t codes = (static_cast<std::size_t>(count) + 1) & ~static_cast<std::size_t>(1);
        primary = reinterpret_cast<const RUNTIME_FUNCTION*>(info + 4 + codes * 2);
    }
    out.start = static_cast<std::uintptr_t>(image) + primary->BeginAddress;
    out.size = primary->EndAddress - primary->BeginAddress;
    out.name = export_name_at(static_cast<std::uintptr_t>(image), primary->BeginAddress);
    const auto mods = list_modules();
    const Module* m = module_for(mods, addr);
    out.module = m ? m->file_path() : std::string();
    return Result::ok();
}

Result find_function_by_name(const std::string& name, const std::string& module_filter, FunctionInfo& out) {
    for (const auto& m : list_modules()) {
        if (!module_filter.empty() && m.file_path().find(module_filter) == std::string::npos) continue;
        FARPROC p = ::GetProcAddress(reinterpret_cast<HMODULE>(m.bias), name.c_str());
        if (!p) continue;
        const auto a = reinterpret_cast<std::uintptr_t>(p);
        FunctionInfo fi;
        if (find_function(a, fi) && fi.start == a) {
            out = fi;
        } else {
            out = FunctionInfo{};
            out.start = a;
        }
        out.name = name;
        if (out.module.empty()) out.module = m.file_path();
        return Result::ok();
    }
    return {Status::NotFound, "function '" + name + "' is not exported by any loaded module"};
}

// ---------------------------------------------------------------- IAT slots

Result find_import_slots(const std::string& symbol, const std::string& module_filter, std::vector<ImportSlot>& out) {
    out.clear();
    const auto self_addr = reinterpret_cast<std::uintptr_t>(&page_size);
    for (const auto& m : list_modules()) {
        if (m.contains(self_addr)) continue;
        if (!module_filter.empty() && m.file_path().find(module_filter) == std::string::npos) continue;
        const std::uintptr_t base = m.bias;
        const auto* nt = nt_headers(base);
        if (!nt) continue;
        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0) continue;
        for (const auto* d = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
             d->Name != 0; ++d) {
            if (d->OriginalFirstThunk == 0 || d->FirstThunk == 0) continue;  // no name table: cannot match
            const auto* names = reinterpret_cast<const IMAGE_THUNK_DATA64*>(base + d->OriginalFirstThunk);
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + d->FirstThunk);
            for (std::size_t i = 0; names[i].u1.AddressOfData != 0; ++i) {
                if (names[i].u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
                const auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + names[i].u1.AddressOfData);
                if (symbol != reinterpret_cast<const char*>(ibn->Name)) continue;
                ImportSlot s;
                s.slot = reinterpret_cast<std::uintptr_t*>(&iat[i].u1.Function);
                s.current = __atomic_load_n(s.slot, __ATOMIC_SEQ_CST);
                s.resolved = s.current;  // the IAT is bound at load time
                s.module = m.file_path() + " (from " + reinterpret_cast<const char*>(base + d->Name) + ")";
                out.push_back(std::move(s));
            }
        }
    }
    if (out.empty()) return {Status::NotFound, "no IAT entry for '" + symbol + "' in the selected modules"};
    return Result::ok();
}

}  // namespace vajra::sys
