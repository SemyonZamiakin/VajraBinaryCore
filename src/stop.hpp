// Vajra Binary Core - stopping threads (internal).
//
// Two mechanisms, used together by the transaction engine:
//
// 1. Cooperative stop (coop_stop): waits until every thread attached through
//    vajra::Safepoints is parked in poll() or inside a BlockingRegion. Needed
//    for type migration, because only the application knows where its threads
//    hold no raw pointers into migratable objects.
//
// 2. Signal stop (world_stop): sends a real-time signal to every other thread
//    of the process (enumerated from /proc/self/task, repeated until no new
//    thread appears). Each thread records its interrupted program counter and
//    parks inside the signal handler on a futex. Used for code patches: the
//    engine checks every recorded PC against the bytes it is about to rewrite.
//
// Between world_stop() and world_resume() the caller must not allocate memory,
// take locks other threads may hold, or call into libc functions that do.
// SPDX-License-Identifier: MIT
#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>

#include "vajra/status.hpp"

namespace vajra::detail {

// ---- cooperative ----
Result coop_stop(int timeout_ms);
void coop_resume() noexcept;

// ---- signal-based ----
struct StoppedThread {
    pid_t tid = 0;
    std::uintptr_t pc = 0;
    std::uintptr_t sp = 0;
};

// Installs the handler if needed (not signal-safe; called before stopping).
Result install_stop_handler();
// Stops all other threads. On failure the world is already resumed.
Result world_stop(int timeout_ms);
void world_resume() noexcept;
std::size_t world_stopped_count() noexcept;
StoppedThread world_stopped_thread(std::size_t i) noexcept;

Result set_stop_signal_impl(int sig);
int stop_signal_impl() noexcept;

}  // namespace vajra::detail
