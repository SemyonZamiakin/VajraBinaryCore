// Stopping threads: signal-based stop-the-world (PC capture, threads created
// during the stop, blocked signals) and cooperative safe points.
// SPDX-License-Identifier: MIT
#if !defined(_WIN32)
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

#include "asm_targets.hpp"
#include "check.hpp"
#include "platform.hpp"
#include "stop.hpp"
#include "vajra/safepoint.hpp"

using namespace vajra;

namespace {

#if !defined(_WIN32)
int count_tasks() {
    int n = 0;
    DIR* d = ::opendir("/proc/self/task");
    while (dirent* e = ::readdir(d))
        if (e->d_name[0] != '.') ++n;
    ::closedir(d);
    return n;
}
void on_usr2(int) {}
#endif

struct Spinners {
    std::atomic<bool> quit{false};
    std::vector<std::thread> threads;
    std::vector<std::atomic<std::uint64_t>> counters;
    explicit Spinners(int n) : counters(static_cast<std::size_t>(n)) {
        for (int i = 0; i < n; ++i)
            threads.emplace_back([this, i] {
                while (!quit.load(std::memory_order_relaxed)) counters[static_cast<std::size_t>(i)].fetch_add(1, std::memory_order_relaxed);
            });
    }
    std::uint64_t sum() const {
        std::uint64_t s = 0;
        for (const auto& c : counters) s += c.load(std::memory_order_relaxed);
        return s;
    }
    ~Spinners() {
        quit = true;
        for (auto& t : threads) t.join();
    }
};

}  // namespace

TEST(signal_stop_freezes_everyone) {
    CHECK_OK(detail::install_stop_handler());
    Spinners s(4);
    while (s.sum() < 1000) std::this_thread::yield();
    for (int round = 0; round < 20; ++round) {
        CHECK_OK(detail::world_stop(2000));
        const std::size_t stopped = detail::world_stopped_count();
        std::uintptr_t pcs[64] = {};  // read while stopped; the list is cleared on resume
        for (std::size_t i = 0; i < stopped && i < 64; ++i) pcs[i] = detail::world_stopped_thread(i).pc;
        const std::uint64_t frozen = s.sum();
        testplat::raw_sleep_ms(5);  // no user-mode locks while others are stopped
        const std::uint64_t later = s.sum();
        detail::world_resume();
        CHECK(stopped >= 4);
        CHECK_EQ(frozen, later);
        for (std::size_t i = 0; i < stopped && i < 64; ++i) CHECK(pcs[i] != 0);
        const std::uint64_t resumed = s.sum();
        while (s.sum() == resumed) std::this_thread::yield();  // they run again
    }
}

#if !defined(_WIN32)
TEST(pc_of_blocked_thread) {
    CHECK_OK(detail::install_stop_handler());
    struct sigaction sa;
    std::memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr2;
    sigaction(SIGUSR2, &sa, nullptr);
    std::atomic<bool> quit{false};
    std::atomic<long> tid{0};
    std::thread t([&] {
        tid = testplat::current_tid();
        while (!quit) asm_block(SYS_pause);
    });
    while (tid == 0) std::this_thread::yield();
    ::usleep(20000);
    CHECK_OK(detail::world_stop(2000));
    std::uintptr_t pc = 0;
    for (std::size_t i = 0; i < detail::world_stopped_count(); ++i)
        if (detail::world_stopped_thread(i).tid == tid) pc = detail::world_stopped_thread(i).pc;
    detail::world_resume();
    CHECK_EQ(pc, reinterpret_cast<std::uintptr_t>(&asm_block) + 4);
    quit = true;
    pthread_kill(t.native_handle(), SIGUSR2);
    t.join();
}
#else
TEST(pc_of_suspended_thread) {
    // Windows: a thread parked (suspended) at a known address is reported there.
    CHECK_OK(detail::install_stop_handler());
    std::atomic<bool> quit{false};
    std::atomic<long> tid{0};
    std::thread t([&] {
        tid = testplat::current_tid();
        while (!quit) ::Sleep(1);
    });
    while (tid == 0) std::this_thread::yield();
    HANDLE h = ::OpenThread(THREAD_ALL_ACCESS, FALSE, static_cast<DWORD>(tid.load()));
    CHECK(h != nullptr);
    ::SuspendThread(h);
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof ctx);
    ctx.ContextFlags = CONTEXT_CONTROL;
    ::GetThreadContext(h, &ctx);
    const CONTEXT saved = ctx;
    ctx.Rip = reinterpret_cast<DWORD64>(&asm_window) + 3;
    ::SetThreadContext(h, &ctx);
    CHECK_OK(detail::world_stop(2000));
    std::uintptr_t pc = 0;
    for (std::size_t i = 0; i < detail::world_stopped_count(); ++i)
        if (detail::world_stopped_thread(i).tid == tid) pc = detail::world_stopped_thread(i).pc;
    detail::world_resume();
    CHECK_EQ(pc, reinterpret_cast<std::uintptr_t>(&asm_window) + 3);
    ::SetThreadContext(h, &saved);  // back to where it was
    quit = true;
    ::ResumeThread(h);
    ::CloseHandle(h);
    t.join();
}
#endif

TEST(threads_created_during_stop_are_caught) {
    CHECK_OK(detail::install_stop_handler());
    std::atomic<bool> quit{false};
    std::atomic<std::uint64_t> spawned{0};
    // A thread that keeps creating short-lived threads.
    std::thread spawner([&] {
        while (!quit) {
            std::thread child([&] { spawned.fetch_add(1); });
            child.join();
        }
    });
    for (int round = 0; round < 50; ++round) {
        CHECK_OK(detail::world_stop(2000));
        const std::uint64_t a = spawned.load();
        testplat::raw_sleep_ms(2);
        const std::uint64_t b = spawned.load();
        detail::world_resume();
        CHECK_EQ(a, b);  // no thread ran while stopped, including brand-new ones
    }
    quit = true;
    spawner.join();
    CHECK(spawned.load() > 0);
}

#if !defined(_WIN32)
TEST(blocked_signal_times_out_and_resumes) {
    CHECK_OK(detail::install_stop_handler());
    Spinners s(2);
    std::atomic<bool> quit{false};
    std::atomic<bool> ready{false};
    std::thread deaf([&] {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, detail::stop_signal_impl());
        pthread_sigmask(SIG_BLOCK, &set, nullptr);
        ready = true;
        while (!quit) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    });
    while (!ready) std::this_thread::yield();
    const Result r = detail::world_stop(200);
    CHECK_STATUS(r, Status::Timeout);
    const std::uint64_t a = s.sum();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(s.sum() > a);  // the other threads were resumed
    quit = true;
    deaf.join();  // its pending signal is discarded as stale when it exits
    CHECK_OK(detail::world_stop(2000));
    detail::world_resume();
}

TEST(stop_with_no_other_threads) {
    CHECK_OK(detail::install_stop_handler());
    const int before = count_tasks();
    CHECK_OK(detail::world_stop(1000));
    CHECK_EQ(detail::world_stopped_count(), static_cast<std::size_t>(before - 1));
    detail::world_resume();
}
#endif

TEST(coop_stop_parks_attached_threads) {
    std::atomic<bool> quit{false};
    std::vector<std::atomic<std::uint64_t>> counters(3);
    std::vector<std::thread> ts;
    for (int i = 0; i < 3; ++i)
        ts.emplace_back([&, i] {
            ScopedAttach a;
            while (!quit) {
                Safepoints::poll();
                counters[static_cast<std::size_t>(i)].fetch_add(1);
            }
        });
    // One more thread that spends its time in a blocking region.
    std::thread sleeper([&] {
        ScopedAttach a;
        while (!quit) {
            Safepoints::poll();
            BlockingRegion r;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });
    while (Safepoints::attached_count() < 4) std::this_thread::yield();
    for (int round = 0; round < 20; ++round) {
        CHECK_OK(detail::coop_stop(2000));
        std::uint64_t a = 0, b = 0;
        for (auto& c : counters) a += c.load();
        std::this_thread::sleep_for(std::chrono::milliseconds(3));
        for (auto& c : counters) b += c.load();
        detail::coop_resume();
        CHECK_EQ(a, b);
    }
    // A thread that attaches while a stop is active parks before returning.
    CHECK_OK(detail::coop_stop(2000));
    std::atomic<bool> attached_returned{false};
    std::thread late([&] {
        ScopedAttach a;
        attached_returned = true;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(!attached_returned.load());
    detail::coop_resume();
    late.join();
    CHECK(attached_returned.load());
    quit = true;
    for (auto& t : ts) t.join();
    sleeper.join();
}

TEST(coop_stop_times_out_on_non_polling_thread) {
    std::atomic<bool> quit{false};
    std::atomic<bool> ready{false};
    std::thread lazy([&] {
        ScopedAttach a;
        ready = true;
        while (!quit) std::this_thread::sleep_for(std::chrono::milliseconds(1));  // never polls
    });
    while (!ready) std::this_thread::yield();
    CHECK_STATUS(detail::coop_stop(100), Status::Timeout);
    quit = true;
    lazy.join();
    CHECK_OK(detail::coop_stop(1000));
    detail::coop_resume();
}

TEST_MAIN()
