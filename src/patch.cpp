// Vajra Binary Core - patch transactions: inline hooks, GOT redirects,
// migrations, atomic commit and rollback.
// SPDX-License-Identifier: MIT
#include "vajra/patch.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "migrate_job.hpp"
#include "stop.hpp"
#include "sys.hpp"
#include "vajra/relocate.hpp"
#include "vajra/x86.hpp"

namespace vajra {

namespace {

constexpr std::size_t kHookBytes = 5;
constexpr std::size_t kMaxFunctionScan = 1u << 20;
constexpr std::uint64_t kReach = (1ull << 31) - (1ull << 16);  // rel32 reach minus a safety margin

std::mutex& patch_mutex() {
    static std::mutex m;
    return m;
}

std::string hex(std::uintptr_t v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

struct CodeOp {
    std::uintptr_t addr = 0;
    std::uint8_t expected[16] = {};
    std::uint8_t replacement[16] = {};
    std::size_t len = 0;
    int prot = 0;
    std::string what;
};

struct GotOp {
    std::uintptr_t* slot = nullptr;
    std::uintptr_t replacement = 0;
    std::uintptr_t allowed_a = 0;  // acceptable current values before the write
    std::uintptr_t allowed_b = 0;
    std::uintptr_t observed = 0;   // value found at commit time (restored on revert)
    int prot = 0;
    std::string what;
};

struct MigOp {
    Heap* heap = nullptr;
    std::shared_ptr<MigrationPlan> plan;
    std::shared_ptr<MigrationPlan> inverse;
};

VAJRA_NO_TSAN bool volatile_equal(std::uintptr_t a, const std::uint8_t* b, std::size_t n) {
    const volatile std::uint8_t* p = reinterpret_cast<const volatile std::uint8_t*>(a);
    for (std::size_t i = 0; i < n; ++i)
        if (p[i] != b[i]) return false;
    return true;
}

// ------------------------------------------------------------ code arena

class Arena {
public:
    ~Arena() {
        if (!kept_) release();
    }
    // Returns an address for `size` bytes such that [addr, addr+size) lies in [lo, hi).
    Result alloc(std::size_t size, std::uintptr_t lo, std::uintptr_t hi, std::uintptr_t& out) {
        for (auto& b : blocks_) {
            const std::uintptr_t start = (b.block.base + b.used + 15) & ~static_cast<std::uintptr_t>(15);
            if (start + size <= b.block.base + b.block.size && start >= lo && start + size <= hi) {
                b.used = start + size - b.block.base;
                out = start;
                return Result::ok();
            }
        }
        sys::NearBlock nb;
        Result r = sys::map_near(lo, hi, std::max<std::size_t>(sys::page_size(), size), nb);
        if (!r) return r;
        blocks_.push_back({nb, size});
        out = nb.base;
        return Result::ok();
    }
    Result seal() {
        for (auto& b : blocks_) {
            Result r = sys::protect_exec(b.block);
            if (!r) return r;
        }
        return Result::ok();
    }
    void release() {
        for (auto& b : blocks_) sys::unmap(b.block);
        blocks_.clear();
    }
    std::vector<sys::NearBlock> keep() {
        kept_ = true;
        std::vector<sys::NearBlock> v;
        for (auto& b : blocks_) v.push_back(b.block);
        return v;
    }

private:
    struct Entry {
        sys::NearBlock block;
        std::size_t used;
    };
    std::vector<Entry> blocks_;
    bool kept_ = false;
};

// ------------------------------------------------------------ the engine

struct HeapLocks {
    std::vector<std::unique_lock<std::mutex>> locks;
    void unlock() { locks.clear(); }
};

// Runs prepared operations atomically. On failure nothing remains changed.
Result execute(const PatchOptions& opts, std::vector<CodeOp>& code, std::vector<GotOp>& got,
               const std::vector<std::pair<Heap*, const MigrationPlan*>>& migrations, sys::MemoryWriter& writer) {
    const bool need_signal = !code.empty() || !got.empty();
    const bool need_coop = !migrations.empty();
    if (need_signal) {
        if (Result r = detail::install_stop_handler(); !r) return r;
    }

    std::vector<std::unique_ptr<detail::MigrationJob>> jobs;
    jobs.reserve(migrations.size());
    for (const auto& [heap, plan] : migrations) jobs.push_back(std::make_unique<detail::MigrationJob>(*heap, *plan));

    if (need_coop) {
        if (Result r = detail::coop_stop(opts.stop_timeout_ms); !r) return r;
    }
    struct CoopGuard {
        bool on;
        ~CoopGuard() {
            if (on) detail::coop_resume();
        }
    } coop_guard{need_coop};

    // Lock each heap once, in address order.
    HeapLocks heap_locks;
    {
        std::vector<std::mutex*> mus;
        for (auto& j : jobs) mus.push_back(&j->heap_mutex());
        std::sort(mus.begin(), mus.end());
        mus.erase(std::unique(mus.begin(), mus.end()), mus.end());
        for (std::mutex* m : mus) heap_locks.locks.emplace_back(*m);
    }
    for (auto& j : jobs) {
        if (Result r = j->prepare(); !r) return r;  // job destructors free prepared objects
    }

    if (!need_signal) {
        for (auto& j : jobs) j->commit();
        heap_locks.unlock();
        for (auto& j : jobs) j->finalize();
        return Result::ok();
    }

    enum class Outcome { Done, Busy, Mismatch, WriteFailed, RollbackFailed };
    Outcome outcome = Outcome::Busy;
    sys::tid_t busy_tid = 0;
    std::uintptr_t busy_pc = 0;
    std::size_t bad_index = 0;
    bool bad_is_got = false;
    int write_rc = 0;

    const int attempts = std::max(1, opts.busy_retries + 1);
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (Result r = detail::world_stop(opts.stop_timeout_ms); !r) return r;
        // ---- the world is stopped: no allocation, no locks from here to resume ----
        bool busy = false;
        const std::size_t n = detail::world_stopped_count();
        for (std::size_t i = 0; i < n && !busy; ++i) {
            const detail::StoppedThread t = detail::world_stopped_thread(i);
            for (const CodeOp& op : code) {
                if (t.pc > op.addr && t.pc < op.addr + op.len) {
                    busy = true;
                    busy_tid = t.tid;
                    busy_pc = t.pc;
                    break;
                }
            }
        }
        if (busy) {
            detail::world_resume();
            if (attempt + 1 < attempts) sys::sleep_us(opts.busy_retry_delay_us);
            continue;
        }

        outcome = Outcome::Done;
        for (std::size_t i = 0; i < code.size() && outcome == Outcome::Done; ++i) {
            if (!volatile_equal(code[i].addr, code[i].expected, code[i].len)) {
                outcome = Outcome::Mismatch;
                bad_index = i;
            }
        }
        for (std::size_t i = 0; i < got.size() && outcome == Outcome::Done; ++i) {
            const std::uintptr_t cur = __atomic_load_n(got[i].slot, __ATOMIC_SEQ_CST);
            if (cur != got[i].allowed_a && cur != got[i].allowed_b) {
                outcome = Outcome::Mismatch;
                bad_index = i;
                bad_is_got = true;
            }
            got[i].observed = cur;
        }

        std::size_t code_done = 0;
        std::size_t got_done = 0;
        if (outcome == Outcome::Done) {
            for (; code_done < code.size(); ++code_done) {
                const CodeOp& op = code[code_done];
                write_rc = writer.write_code(op.addr, op.replacement, op.len, op.prot);
                if (write_rc != 0) {
                    outcome = Outcome::WriteFailed;
                    bad_index = code_done;
                    break;
                }
            }
        }
        if (outcome == Outcome::Done) {
            for (; got_done < got.size(); ++got_done) {
                write_rc = writer.write_pointer(got[got_done].slot, got[got_done].replacement, got[got_done].prot);
                if (write_rc != 0) {
                    outcome = Outcome::WriteFailed;
                    bad_index = got_done;
                    bad_is_got = true;
                    break;
                }
            }
        }
        if (outcome == Outcome::WriteFailed) {
            // Roll back in reverse order.
            while (got_done > 0) {
                --got_done;
                if (writer.write_pointer(got[got_done].slot, got[got_done].observed, got[got_done].prot) != 0)
                    outcome = Outcome::RollbackFailed;
            }
            while (code_done > 0) {
                --code_done;
                const CodeOp& op = code[code_done];
                if (writer.write_code(op.addr, op.expected, op.len, op.prot) != 0) outcome = Outcome::RollbackFailed;
            }
        }
        if (outcome == Outcome::Done) {
            for (auto& j : jobs) j->commit();
        }
        detail::world_resume();
        // ---- the world runs again ----
        break;
    }

    switch (outcome) {
        case Outcome::Done:
            break;
        case Outcome::Busy:
            return {Status::Busy, "thread " + std::to_string(busy_tid) + " kept executing inside patched bytes (pc " +
                                      hex(busy_pc) + ")"};
        case Outcome::Mismatch:
            return {Status::Mismatch, (bad_is_got ? got[bad_index].what : code[bad_index].what) +
                                          ": memory no longer holds the expected contents"};
        case Outcome::WriteFailed:
            return {Status::WriteFailed, (bad_is_got ? got[bad_index].what : code[bad_index].what) + ": " +
                                             std::strerror(-write_rc) + "; earlier writes were rolled back"};
        case Outcome::RollbackFailed:
            return {Status::Internal, (bad_is_got ? got[bad_index].what : code[bad_index].what) +
                                          ": write failed and rolling back earlier writes also failed"};
    }
    heap_locks.unlock();
    for (auto& j : jobs) j->finalize();

    // A thread that was inside the lazy-binding resolver may have written the
    // resolved address over a fresh GOT redirect. Re-apply it in that case.
    for (const GotOp& op : got) {
        if (!(op.prot & sys::kProtWrite)) continue;  // read-only GOT: no lazy binding possible
        std::uintptr_t cur = __atomic_load_n(op.slot, __ATOMIC_SEQ_CST);
        if (cur != op.replacement && (cur == op.allowed_a || cur == op.allowed_b))
            __atomic_compare_exchange_n(op.slot, &cur, op.replacement, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    }
    return Result::ok();
}

// ------------------------------------------------------------ hook preparation

struct HookRequest {
    void* target = nullptr;
    std::string name;
    std::string module;
    void* detour = nullptr;
    void** original = nullptr;
};

struct PreparedHook {
    CodeOp op;
    std::uintptr_t trampoline = 0;
};

Result scan_function_body(std::uintptr_t start, std::size_t size, const PatchOptions& opts) {
    if (size > kMaxFunctionScan) {
        if (opts.allow_unknown_bounds) return Result::ok();
        return {Status::Unsupported, "function is larger than the body scan limit"};
    }
    std::vector<std::uint8_t> body(size + x86::kMaxInsnLength, 0);
    const std::size_t got = sys::safe_read(start, body.data(), size);
    if (got < size) return {Status::NotFound, "function body is not fully readable"};
    std::size_t off = 0;
    while (off < size) {
        x86::Insn insn;
        x86::DecodeError err;
        if (!x86::decode(body.data() + off, size - off, insn, &err)) {
            if (opts.allow_unknown_bounds) return Result::ok();
            return {Status::DecodeFailed, "cannot verify the function body: undecodable bytes at +" +
                                              std::to_string(off) + " (" + x86::decode_error_name(err) + ")"};
        }
        if (insn.branch != x86::Branch::None) {
            const std::uint64_t t = insn.branch_target(start + off);
            if (t > start && t < start + kHookBytes)
                return {Status::RelocationFailed, "branch at +" + std::to_string(off) +
                                                      " targets the bytes the hook overwrites"};
        }
        off += insn.length;
    }
    return Result::ok();
}

Result prepare_hook(const HookRequest& req, const PatchOptions& opts, const std::vector<sys::MapEntry>& maps,
                    const std::vector<std::pair<std::uintptr_t, std::uintptr_t>>& own_code, Arena& arena,
                    PreparedHook& out) {
    const std::uintptr_t t = reinterpret_cast<std::uintptr_t>(req.target);
    const std::string where = req.name.empty() ? hex(t) : req.name;
    if (t == 0 || req.detour == nullptr) return {Status::InvalidArgument, "hook needs a target and a detour"};
    for (const auto& r : own_code)
        if (t >= r.first && t < r.second) return {Status::Unsupported, where + ": cannot hook Vajra's own code"};
    int prot = 0;
    if (Result r = sys::range_protection(maps, t, kHookBytes, &prot); !r) return {r.status(), where + ": " + r.message()};
    if (!(prot & sys::kProtExec)) return {Status::InvalidArgument, where + ": target is not in executable memory"};

    sys::FunctionInfo fi;
    std::size_t fsize = 0;
    std::string fname = req.name;
    Result fr = sys::find_function(t, fi);
    if (fr && fi.start == t) {
        fsize = fi.size;
        if (fname.empty()) fname = fi.name;
    } else if (fr) {
        if (!opts.allow_unknown_bounds)
            return {Status::InvalidArgument, where + ": address is inside " + fi.name + " (+" +
                                                 std::to_string(t - fi.start) + "), not at a function entry"};
    } else if (!opts.allow_unknown_bounds) {
        return {Status::Unsupported, where + ": function bounds unknown (no symbol); set allow_unknown_bounds to "
                                             "hook it without the body check"};
    }
    const std::string label = fname.empty() ? hex(t) : fname + " (" + hex(t) + ")";

    std::uint8_t snap[64] = {};
    const std::size_t got = sys::safe_read(t, snap, sizeof snap);
    if (got < kHookBytes) return {Status::NotFound, label + ": code is not readable"};

    if (fsize != 0 && fsize < kHookBytes) {
        // The patch extends past the function: those bytes must not belong to another symbol.
        for (std::size_t k = fsize; k < kHookBytes; ++k) {
            sys::FunctionInfo next;
            if (sys::find_function(t + k, next))
                return {Status::RelocationFailed, label + ": function " + next.name + " starts inside the patch window"};
        }
    }
    if (fsize != 0 && snap[0] != 0xE9) {  // E9: already hooked; the window was checked then
        if (Result r = scan_function_body(t, fsize, opts); !r) return {r.status(), label + ": " + r.message()};
    }

    PrologueInput in;
    in.code = snap;
    in.code_size = got;
    in.source = t;
    in.min_bytes = kHookBytes;
    // An existing jmp rel32 (chained hook) may extend into checked padding.
    in.function_size = snap[0] == 0xE9 ? 0 : fsize;
    PrologueAnalysis an;
    if (Result r = analyze_prologue(in, an); !r) return {r.status(), label + ": " + r.message()};

    std::uint64_t amin = t, amax = t;
    for (std::uint64_t a : an.rip_targets) {
        amin = std::min(amin, a);
        amax = std::max(amax, a);
    }
    if (amax - amin >= 2 * kReach) return {Status::OutOfRange, label + ": RIP-relative operands are too far apart"};
    const std::uintptr_t lo = amax > kReach ? amax - kReach : 0;
    const std::uintptr_t hi = amin + kReach;
    const std::size_t relay_size = 16;
    std::uintptr_t chunk = 0;
    if (Result r = arena.alloc(relay_size + an.max_relocated_size, lo, hi, chunk); !r)
        return {r.status(), label + ": " + r.message()};
    const std::uintptr_t relay = chunk;
    const std::uintptr_t tramp = chunk + relay_size;

    std::vector<std::uint8_t> relay_code;
    enc::jmp_abs(relay_code, reinterpret_cast<std::uintptr_t>(req.detour));
    std::vector<std::uint8_t> tramp_code;
    if (Result r = relocate_prologue(in, an, tramp, tramp_code); !r) return {r.status(), label + ": " + r.message()};
    std::memcpy(reinterpret_cast<void*>(relay), relay_code.data(), relay_code.size());
    std::memcpy(reinterpret_cast<void*>(tramp), tramp_code.data(), tramp_code.size());

    CodeOp op;
    op.addr = t;
    op.len = kHookBytes;
    op.prot = prot;
    std::memcpy(op.expected, snap, kHookBytes);
    if (!enc::jmp_rel32(op.replacement, t, relay)) return {Status::Internal, label + ": relay out of range"};
    op.what = "hook " + label;
    out.op = std::move(op);
    out.trampoline = tramp;
    return Result::ok();
}

// ------------------------------------------------------------ import (GOT/IAT) preparation

struct ImportRequest {
    std::string symbol;
    void* replacement = nullptr;
    void** original = nullptr;
    std::string module_filter;
};

Result prepare_import(const ImportRequest& req, const std::vector<sys::MapEntry>& maps, std::vector<GotOp>& out,
                      std::uintptr_t& original) {
    if (req.symbol.empty() || req.replacement == nullptr)
        return {Status::InvalidArgument, "import redirect needs a symbol and a replacement"};
    const auto repl = reinterpret_cast<std::uintptr_t>(req.replacement);
    original = 0;
    std::vector<sys::ImportSlot> slots;
    if (Result r = sys::find_import_slots(req.symbol, req.module_filter, slots); !r) return r;
    std::uintptr_t lazy_target = 0;
    for (const sys::ImportSlot& s : slots) {
        if (s.current == repl) return {Status::AlreadyApplied, req.symbol + " is already redirected in " + s.module};
        GotOp op;
        op.slot = s.slot;
        op.replacement = repl;
        op.allowed_a = s.current;
        op.allowed_b = s.resolved;  // a lazy slot may get bound between now and the commit
        if (s.lazy) {
            if (lazy_target == 0) lazy_target = s.resolved;
        } else if (original == 0) {
            original = s.current;
        }
        int prot = 0;
        const auto slot_addr = reinterpret_cast<std::uintptr_t>(s.slot);
        if (Result pr = sys::range_protection(maps, slot_addr, sizeof(std::uintptr_t), &prot); !pr) return pr;
        op.prot = prot;
        op.what = "import slot for " + req.symbol + " in " + s.module + " (" + hex(slot_addr) + ")";
        out.push_back(std::move(op));
    }
    if (original == 0) original = lazy_target;
    if (original == 0) return {Status::NotFound, "cannot resolve the original address of '" + req.symbol + "'"};
    return Result::ok();
}

}  // namespace

// ------------------------------------------------------------ Patch

struct Patch::State {
    std::vector<CodeOp> code;
    std::vector<GotOp> got;
    std::vector<MigOp> migrations;
    std::vector<sys::NearBlock> blocks;  // kept mapped forever: threads may still run trampolines
    bool active = false;
    std::string description;
};

Patch::Patch() = default;
Patch::~Patch() = default;
Patch::Patch(Patch&&) noexcept = default;
Patch& Patch::operator=(Patch&&) noexcept = default;

bool Patch::active() const noexcept {
    std::lock_guard<std::mutex> g(patch_mutex());
    return state_ && state_->active;
}

std::string Patch::describe() const {
    std::lock_guard<std::mutex> g(patch_mutex());
    if (!state_) return "(empty patch)";
    return state_->description + (state_->active ? "" : "[reverted]\n");
}

Result Patch::revert(const PatchOptions& options) {
    std::lock_guard<std::mutex> g(patch_mutex());
    if (!state_ || !state_->active) return {Status::NotApplied, "patch is not active"};
    State& s = *state_;
    for (const MigOp& m : s.migrations)
        if (!m.inverse)
            return {Status::NotRevertible, "migration of " + m.plan->from().name + " has no inverse plan"};

    std::vector<CodeOp> code;
    for (const CodeOp& op : s.code) {
        CodeOp r = op;
        std::memcpy(r.expected, op.replacement, sizeof r.expected);
        std::memcpy(r.replacement, op.expected, sizeof r.replacement);
        r.what = "revert " + op.what;
        code.push_back(std::move(r));
    }
    std::reverse(code.begin(), code.end());
    std::vector<GotOp> got;
    for (const GotOp& op : s.got) {
        GotOp r = op;
        r.replacement = op.observed;
        r.allowed_a = r.allowed_b = op.replacement;
        r.what = "revert " + op.what;
        got.push_back(std::move(r));
    }
    std::vector<std::pair<Heap*, const MigrationPlan*>> migs;
    for (auto it = s.migrations.rbegin(); it != s.migrations.rend(); ++it) migs.emplace_back(it->heap, it->inverse.get());

    sys::MemoryWriter writer;
    if (!code.empty()) {
        if (Result r = writer.prepare(options.write_method); !r) return r;
    }
    if (Result r = execute(options, code, got, migs, writer); !r) return r;
    s.active = false;
    return Result::ok();
}

Result set_stop_signal(int sig) {
    std::lock_guard<std::mutex> g(patch_mutex());
    return detail::set_stop_signal_impl(sig);
}

int stop_signal() noexcept { return detail::stop_signal_impl(); }

void* find_function(const std::string& name, const std::string& module) {
    sys::FunctionInfo fi;
    if (!sys::find_function_by_name(name, module, fi)) return nullptr;
    return reinterpret_cast<void*>(fi.start);
}

// ------------------------------------------------------------ Transaction

struct Transaction::Impl {
    PatchOptions opts;
    std::vector<HookRequest> hooks;
    std::vector<ImportRequest> imports;
    std::vector<MigOp> migrations;
    Result error;
    bool committed = false;
};

Transaction::Transaction(PatchOptions options) : impl_(std::make_unique<Impl>()) { impl_->opts = options; }
Transaction::~Transaction() = default;

std::size_t Transaction::size() const noexcept {
    return impl_->hooks.size() + impl_->imports.size() + impl_->migrations.size();
}

Transaction& Transaction::hook(void* target, void* detour, void** original) {
    HookRequest r;
    r.target = target;
    r.detour = detour;
    r.original = original;
    impl_->hooks.push_back(std::move(r));
    return *this;
}

Transaction& Transaction::hook(const std::string& function, void* detour, void** original, const std::string& module) {
    HookRequest r;
    r.name = function;
    r.module = module;
    r.detour = detour;
    r.original = original;
    impl_->hooks.push_back(std::move(r));
    return *this;
}

Transaction& Transaction::redirect_import(const std::string& symbol, void* replacement, void** original,
                                          const std::string& module_filter) {
    ImportRequest r;
    r.symbol = symbol;
    r.replacement = replacement;
    r.original = original;
    r.module_filter = module_filter;
    impl_->imports.push_back(std::move(r));
    return *this;
}

Transaction& Transaction::migrate(Heap& heap, MigrationPlan plan, std::optional<MigrationPlan> inverse) {
    if (!impl_->error.is_ok()) return *this;
    MigOp m;
    m.heap = &heap;
    m.plan = std::make_shared<MigrationPlan>(std::move(plan));
    if (Result r = m.plan->compile(); !r) {
        impl_->error = r;
        return *this;
    }
    if (inverse) {
        m.inverse = std::make_shared<MigrationPlan>(std::move(*inverse));
        if (Result r = m.inverse->compile(); !r) {
            impl_->error = Result(r.status(), "inverse plan: " + r.message());
            return *this;
        }
        if (!m.inverse->from().same_layout(m.plan->to()) || !m.inverse->to().same_layout(m.plan->from())) {
            impl_->error = Result(Status::InvalidArgument, "inverse plan does not mirror the forward plan");
            return *this;
        }
    }
    impl_->migrations.push_back(std::move(m));
    return *this;
}

Result Transaction::commit(Patch* out) {
    std::lock_guard<std::mutex> g(patch_mutex());
    Impl& im = *impl_;
    if (im.committed) return {Status::AlreadyApplied, "transaction was already committed"};
    if (!im.error.is_ok()) return im.error;
    if (size() == 0) return {Status::InvalidArgument, "empty transaction"};

    for (std::size_t i = 0; i < im.migrations.size(); ++i)
        for (std::size_t j = i + 1; j < im.migrations.size(); ++j)
            if (im.migrations[i].heap == im.migrations[j].heap &&
                im.migrations[i].plan->from().name == im.migrations[j].plan->from().name)
                return {Status::InvalidArgument, "two migrations of the same type in one transaction"};

    std::vector<sys::MapEntry> maps;
    if (Result r = sys::read_maps(maps); !r) return r;
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> own_code;
    if (Result r = sys::module_exec_ranges(reinterpret_cast<std::uintptr_t>(&sys::page_size), own_code); !r)
        return r;

    sys::MemoryWriter writer;
    if (!im.hooks.empty()) {
        if (Result r = writer.prepare(im.opts.write_method); !r) return r;
    }

    std::string description;
    Arena arena;
    std::vector<CodeOp> code;
    std::vector<std::uintptr_t> trampolines;
    for (const HookRequest& req0 : im.hooks) {
        HookRequest req = req0;
        if (!req.name.empty()) {
            sys::FunctionInfo fi;
            if (Result r = sys::find_function_by_name(req.name, req.module, fi); !r) return r;
            req.target = reinterpret_cast<void*>(fi.start);
        }
        PreparedHook ph;
        if (Result r = prepare_hook(req, im.opts, maps, own_code, arena, ph); !r) return r;
        for (const CodeOp& other : code)
            if (ph.op.addr < other.addr + other.len && other.addr < ph.op.addr + ph.op.len)
                return {Status::InvalidArgument, ph.op.what + " overlaps " + other.what};
        description += ph.op.what + " -> " + hex(reinterpret_cast<std::uintptr_t>(req.detour)) + "\n";
        code.push_back(std::move(ph.op));
        trampolines.push_back(ph.trampoline);
    }
    if (Result r = arena.seal(); !r) return r;

    std::vector<GotOp> got;
    std::vector<std::uintptr_t> import_originals;
    for (const ImportRequest& req : im.imports) {
        std::vector<GotOp> ops;
        std::uintptr_t orig = 0;
        if (Result r = prepare_import(req, maps, ops, orig); !r) return r;
        for (const GotOp& op : ops) {
            for (const GotOp& prev : got)
                if (prev.slot == op.slot) return {Status::InvalidArgument, op.what + " is redirected twice"};
            description += "redirect " + op.what + " -> " + hex(op.replacement) + "\n";
        }
        got.insert(got.end(), ops.begin(), ops.end());
        import_originals.push_back(orig);
    }

    std::vector<std::pair<Heap*, const MigrationPlan*>> migs;
    for (const MigOp& m : im.migrations) {
        migs.emplace_back(m.heap, m.plan.get());
        description += "migrate " + m.plan->from().name + " v" + std::to_string(m.plan->from().version) + " -> v" +
                       std::to_string(m.plan->to().version) + (m.inverse ? " (revertible)" : "") + "\n";
    }

    // Publish "original" pointers before the patch can be reached.
    std::vector<std::pair<void**, void*>> saved;
    for (std::size_t i = 0; i < im.hooks.size(); ++i) {
        if (!im.hooks[i].original) continue;
        saved.emplace_back(im.hooks[i].original, *im.hooks[i].original);
        __atomic_store_n(im.hooks[i].original, reinterpret_cast<void*>(trampolines[i]), __ATOMIC_SEQ_CST);
    }
    for (std::size_t i = 0; i < im.imports.size(); ++i) {
        if (!im.imports[i].original) continue;
        saved.emplace_back(im.imports[i].original, *im.imports[i].original);
        __atomic_store_n(im.imports[i].original, reinterpret_cast<void*>(import_originals[i]), __ATOMIC_SEQ_CST);
    }

    if (Result r = execute(im.opts, code, got, migs, writer); !r) {
        for (auto it = saved.rbegin(); it != saved.rend(); ++it) __atomic_store_n(it->first, it->second, __ATOMIC_SEQ_CST);
        return r;  // the arena destructor unmaps the unused trampolines
    }

    auto state = std::make_shared<Patch::State>();
    state->code = std::move(code);
    state->got = std::move(got);
    state->migrations = im.migrations;
    state->blocks = arena.keep();
    state->active = true;
    state->description = std::move(description);
    if (out) out->state_ = std::move(state);
    im.committed = true;
    return Result::ok();
}

}  // namespace vajra
