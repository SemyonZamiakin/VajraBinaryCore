// Vajra Binary Core - stopping threads (internal).
//
// Two mechanisms, used together by the transaction engine:
//
// 1. Cooperative stop (coop_stop): waits until every thread attached through
//    vajra::Safepoints is parked in poll() or inside a BlockingRegion. Needed
//    for type migration, because only the application knows where its threads
//    hold no raw pointers into migratable objects.
//
// 2. World stop (world_stop): stops every other thread of the process and
//    records its interrupted program counter, which the engine checks against
//    the bytes it is about to rewrite.
//      Linux:   a real-time signal is sent to every thread listed in
//               /proc/self/task (repeated until no new thread appears); each
//               thread parks inside the signal handler on a futex.
//      Windows: threads are enumerated with NtGetNextThread (repeated until
//               no new thread appears), suspended with SuspendThread, and
//               their context read with GetThreadContext.
//
// Between world_stop() and world_resume() the caller must not allocate memory,
// take locks other threads may hold, or call library functions that do.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>

#include "vajra/status.hpp"

namespace vajra::detail {

// ---- cooperative ----
Result coop_stop(int timeout_ms);
void coop_resume() noexcept;

// ---- world stop ----
struct StoppedThread {
    long tid = 0;  // kernel thread id (Linux) or thread id (Windows)
    std::uintptr_t pc = 0;
    std::uintptr_t sp = 0;
};

// Prepares the mechanism (installs the signal handler / resolves NtGetNextThread).
// Not stop-safe; called before stopping.
Result install_stop_handler();
// Stops all other threads. On failure the world is already resumed.
Result world_stop(int timeout_ms);
void world_resume() noexcept;
std::size_t world_stopped_count() noexcept;
StoppedThread world_stopped_thread(std::size_t i) noexcept;

// Linux only: choose the real-time signal. Windows: Unsupported.
Result set_stop_signal_impl(int sig);
int stop_signal_impl() noexcept;  // 0 on Windows

}  // namespace vajra::detail
