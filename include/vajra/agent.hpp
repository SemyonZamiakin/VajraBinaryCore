// Vajra Binary Core - in-process patch agent.
//
// The agent lets an operator apply patch modules to a running program that
// links Vajra. It listens on
//   Linux:   a Unix domain socket (mode 0600, peer uid checked with SO_PEERCRED);
//   Windows: a named pipe such as \\.\pipe\myapp-vajra (local clients only,
//            DACL granting access to the current user only)
// and accepts one-line commands, normally sent by the `vajractl` tool:
//
//   ping                 -> ok vajra <version>
//   apply <module>       -> loads the module (.so / .dll), runs its entry point
//                           to build a Transaction, commits it; replies "ok <id>"
//   revert <id>          -> reverts that patch
//   list                 -> one line per patch: <id> <active|reverted> <module>
//
// A patch module is a shared library exporting
//
//   VAJRA_PATCH_ENTRY {            // extern "C" int vajra_patch_entry(vajra::PatchContext*)
//       ctx->tx->hook(...).migrate(*ctx->heap, ...);
//       return 0;                  // non-zero: abort, nothing is applied
//   }
//
// Modules are never unloaded: their code may be running in patched functions.
// SPDX-License-Identifier: MIT
#pragma once

#include <memory>
#include <string>

#include "vajra/migrate.hpp"
#include "vajra/options.hpp"
#include "vajra/patch.hpp"
#include "vajra/status.hpp"

namespace vajra {

struct PatchContext {
    Heap* heap = nullptr;      // the heap given to the agent (may be null)
    void* user = nullptr;      // application pointer given to the agent
    Transaction* tx = nullptr; // add operations here
    std::string message;       // optional text returned to the operator
};

using PatchEntryFn = int (*)(PatchContext*);

#if defined(_WIN32)
#define VAJRA_PATCH_ENTRY extern "C" __declspec(dllexport) int vajra_patch_entry(::vajra::PatchContext* ctx)
#else
#define VAJRA_PATCH_ENTRY \
    extern "C" __attribute__((visibility("default"))) int vajra_patch_entry(::vajra::PatchContext* ctx)
#endif

class Agent {
public:
    struct Options {
        // Linux: path of the socket (put it in a private directory).
        // Windows: pipe name, \\.\pipe\<name>.
        std::string socket_path;
        Heap* heap = nullptr;
        void* user = nullptr;
        PatchOptions patch;
        // Refuse modules not owned by this user (or root; on Windows also
        // Administrators, SYSTEM, TrustedInstaller). Linux additionally refuses
        // files writable by group or others.
        bool check_module_owner = true;
    };

    Agent();
    ~Agent();  // stops the listener; applied patches stay applied
    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;

    Result start(const Options& options);
    void stop();

    // The same operations without the socket.
    Result apply_module(const std::string& path, std::string* id = nullptr, std::string* message = nullptr);
    Result revert(const std::string& id);
    std::string list() const;
    // Executes one protocol line and returns the reply (used by the listener).
    std::string handle_command(const std::string& line);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

const char* version() noexcept;

}  // namespace vajra
