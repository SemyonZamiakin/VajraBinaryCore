// Vajra Binary Core - patch transactions.
//
// A Transaction collects operations and applies them atomically with respect
// to every other thread of the process:
//
//   * hook()            - inline detour at a function entry (5-byte jmp to a
//                         relay, relocated prologue in a trampoline);
//   * redirect_import() - rewrite GOT entries (JUMP_SLOT / GLOB_DAT) so calls
//                         through the PLT/GOT go to a replacement;
//   * migrate()         - convert all live objects of a type in a Heap to a new
//                         layout and fix up pointers to them.
//
// commit() prepares everything that can fail first (decoding, relocation,
// trampolines, new objects), then stops the world: attached mutator threads at
// their safe points (when a migration is involved) and all threads by signal
// (when code or GOT entries change). It checks that no thread is executing
// inside bytes to be rewritten and that memory still holds the expected bytes,
// writes everything, and resumes. If any write fails, the writes already done
// are undone before the world resumes; prepared objects are freed. Either all
// operations take effect or none do.
//
// A committed transaction yields a Patch, which can be reverted later. Code
// and GOT changes revert by restoring the original bytes (only if they still
// hold what Vajra wrote); migrations revert only if an inverse plan was given.
// SPDX-License-Identifier: MIT
#pragma once

#include <memory>
#include <optional>
#include <string>

#include "vajra/migrate.hpp"
#include "vajra/options.hpp"
#include "vajra/status.hpp"

namespace vajra {

class Patch;

class Transaction {
public:
    explicit Transaction(PatchOptions options = {});
    ~Transaction();
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    // Redirects calls to `target` to `detour`. If `original` is non-null it
    // receives (before the patch goes live) a pointer through which the
    // original function can be called.
    Transaction& hook(void* target, void* detour, void** original = nullptr);
    template <class F>
    Transaction& hook(F* target, F* detour, F** original = nullptr) {
        return hook(reinterpret_cast<void*>(target), reinterpret_cast<void*>(detour),
                    reinterpret_cast<void**>(original));
    }
    // Same, looking the function up by symbol name in loaded modules
    // (module: substring of the module path; empty = any module).
    Transaction& hook(const std::string& function, void* detour, void** original = nullptr,
                      const std::string& module = "");

    // Rewrites GOT entries for `symbol` in every loaded module whose path
    // contains `module_filter` (empty = all), except Vajra itself. `original`
    // receives the address calls resolved to before. The replacement must call
    // the original through `original`, not by name: a call by name from a
    // redirected module goes through the redirected GOT entry and recurses.
    Transaction& redirect_import(const std::string& symbol, void* replacement, void** original = nullptr,
                                 const std::string& module_filter = "");

    // Migrates every object of plan.from().name in `heap`. `inverse` (to ->
    // from) makes the migration revertible.
    Transaction& migrate(Heap& heap, MigrationPlan plan, std::optional<MigrationPlan> inverse = std::nullopt);

    std::size_t size() const noexcept;
    Result commit(Patch* out = nullptr);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class Patch {
public:
    Patch();
    ~Patch();  // does NOT revert; a patch stays applied when its handle is gone
    Patch(Patch&&) noexcept;
    Patch& operator=(Patch&&) noexcept;
    Patch(const Patch&) = delete;
    Patch& operator=(const Patch&) = delete;

    bool active() const noexcept;
    // Reverts all operations atomically (same machinery as commit).
    Result revert(const PatchOptions& options = {});
    std::string describe() const;

    struct State;

private:
    friend class Transaction;
    std::shared_ptr<State> state_;
};

// The real-time signal used to stop threads (default SIGRTMIN+7). Must have no
// other handler in the process.
Result set_stop_signal(int sig);
int stop_signal() noexcept;

}  // namespace vajra
