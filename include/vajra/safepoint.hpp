// Vajra Binary Core - cooperative safe points for mutator threads.
//
// Type migration rewrites objects and the pointers to them, so every thread
// that touches migratable objects ("mutator") must be at a point where it holds
// no raw pointers into them other than registered roots. Such threads attach
// once and call Safepoints::poll() regularly, typically at the top of their
// main loop. poll() is one relaxed-acquire load when nothing is pending.
//
// A thread that blocks for a long time (sleep, I/O, waiting on a queue) wraps
// the blocking call in a BlockingRegion so that a migration does not have to
// wait for it. Inside a region the thread must not touch migratable objects.
//
//   vajra::ScopedAttach attach;            // per mutator thread
//   while (running) {
//       vajra::Safepoints::poll();          // migrations happen here
//       update_world();
//       { vajra::BlockingRegion idle; wait_for_next_tick(); }
//   }
// SPDX-License-Identifier: MIT
#pragma once

#include <atomic>
#include <cstddef>

namespace vajra {

namespace detail {
extern std::atomic<bool> g_safepoint_requested;
void safepoint_slow() noexcept;
}  // namespace detail

class Safepoints {
public:
    // Registers the calling thread as a mutator. Idempotent. If a stop is in
    // progress the thread parks before returning.
    static void attach();
    // Unregisters the calling thread. Idempotent.
    static void detach() noexcept;
    static bool attached() noexcept;
    static std::size_t attached_count() noexcept;

    static inline void poll() noexcept {
        if (detail::g_safepoint_requested.load(std::memory_order_acquire)) detail::safepoint_slow();
    }

    static void enter_region() noexcept;
    static void leave_region() noexcept;
};

class ScopedAttach {
public:
    ScopedAttach() { Safepoints::attach(); }
    ~ScopedAttach() { Safepoints::detach(); }
    ScopedAttach(const ScopedAttach&) = delete;
    ScopedAttach& operator=(const ScopedAttach&) = delete;
};

class BlockingRegion {
public:
    BlockingRegion() noexcept { Safepoints::enter_region(); }
    ~BlockingRegion() { Safepoints::leave_region(); }
    BlockingRegion(const BlockingRegion&) = delete;
    BlockingRegion& operator=(const BlockingRegion&) = delete;
};

}  // namespace vajra
