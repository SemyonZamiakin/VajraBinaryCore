// GOT/PLT redirection. Built three times: lazy binding (writable .got.plt,
// unresolved slots), full RELRO (read-only GOT), and -fno-plt (GLOB_DAT slots).
// SPDX-License-Identifier: MIT
#include <atomic>
#include <thread>
#include <vector>

#include "check.hpp"
#include "sys.hpp"
#include "vajra/vajra.hpp"

using namespace vajra;

extern "C" int testlib_value(int x);
extern "C" int testlib_other(int x);

namespace {

int (*orig_value)(int) = nullptr;
int repl_value(int x) { return __atomic_load_n(&orig_value, __ATOMIC_ACQUIRE)(x) * 100; }
int (*orig_value2)(int) = nullptr;
int repl_value2(int x) { return __atomic_load_n(&orig_value2, __ATOMIC_ACQUIRE)(x) + 5; }

// The call must go through the PLT/GOT of this executable.
__attribute__((noinline)) int call_value(int x) { return testlib_value(x); }
__attribute__((noinline)) int call_other(int x) { return testlib_other(x); }

}  // namespace

TEST(redirect_before_first_call) {
    // In the lazy build the slot is still unresolved here.
    Patch p;
    CHECK_OK(Transaction().redirect_import("testlib_value", reinterpret_cast<void*>(&repl_value),
                                           reinterpret_cast<void**>(&orig_value))
                 .commit(&p));
    CHECK(orig_value != nullptr);
    CHECK_EQ(call_value(1), 200);
    CHECK_EQ(orig_value(1), 2);
    CHECK_EQ(call_other(3), 6);  // other imports untouched
    CHECK_OK(p.revert());
    CHECK_EQ(call_value(1), 2);
    CHECK_EQ(call_value(1), 2);  // and lazy resolution still works after restoring the stub
}

TEST(redirect_after_resolution_and_stacking) {
    CHECK_EQ(call_value(4), 5);
    Patch a, b;
    CHECK_OK(Transaction().redirect_import("testlib_value", reinterpret_cast<void*>(&repl_value),
                                           reinterpret_cast<void**>(&orig_value))
                 .commit(&a));
    CHECK_STATUS(Transaction().redirect_import("testlib_value", reinterpret_cast<void*>(&repl_value)).commit(),
                 Status::AlreadyApplied);
    CHECK_OK(Transaction().redirect_import("testlib_value", reinterpret_cast<void*>(&repl_value2),
                                           reinterpret_cast<void**>(&orig_value2))
                 .commit(&b));
    CHECK_EQ(call_value(4), 505);  // repl_value2 -> repl_value -> testlib
    CHECK_STATUS(a.revert(), Status::Mismatch);  // b sits on top
    CHECK_OK(b.revert());
    CHECK_EQ(call_value(4), 500);
    CHECK_OK(a.revert());
    CHECK_EQ(call_value(4), 5);
}

TEST(not_found_and_filters) {
    CHECK_STATUS(Transaction().redirect_import("no_such_symbol_xyz", reinterpret_cast<void*>(&repl_value)).commit(),
                 Status::NotFound);
    CHECK_STATUS(Transaction()
                     .redirect_import("testlib_value", reinterpret_cast<void*>(&repl_value), nullptr, "no-such-module")
                     .commit(),
                 Status::NotFound);
    CHECK_STATUS(Transaction().redirect_import("", reinterpret_cast<void*>(&repl_value)).commit(),
                 Status::InvalidArgument);
}

TEST(write_fault_rolls_back) {
    sys::set_write_fault_countdown(1);
    CHECK_STATUS(Transaction().redirect_import("testlib_value", reinterpret_cast<void*>(&repl_value),
                                               reinterpret_cast<void**>(&orig_value))
                     .commit(),
                 Status::WriteFailed);
    sys::set_write_fault_countdown(0);
    CHECK_EQ(call_value(7), 8);
}

TEST(redirect_while_threads_call) {
    std::atomic<bool> quit{false};
    std::atomic<long> bad{0};
    std::atomic<long> calls{0};
    std::vector<std::thread> ts;
    for (int t = 0; t < 4; ++t)
        ts.emplace_back([&, t] {
            int x = t;
            while (!quit.load(std::memory_order_relaxed)) {
                const int r = call_value(x);
                if (r != x + 1 && r != (x + 1) * 100) bad.fetch_add(1);
                calls.fetch_add(1, std::memory_order_relaxed);
                x = (x + 1) & 1023;
            }
        });
    for (int i = 0; i < 300; ++i) {
        Patch p;
        CHECK_OK(Transaction().redirect_import("testlib_value", reinterpret_cast<void*>(&repl_value),
                                               reinterpret_cast<void**>(&orig_value))
                     .commit(&p));
        CHECK_OK(p.revert());
    }
    quit = true;
    for (auto& t : ts) t.join();
    CHECK_EQ(bad.load(), 0);
    CHECK(calls.load() > 0);
    CHECK_EQ(call_value(1), 2);
}

TEST_MAIN()
