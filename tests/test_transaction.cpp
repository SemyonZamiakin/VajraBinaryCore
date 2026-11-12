// Transactions: all-or-nothing commit, rollback after a failed write (fault
// injection), busy detection, code + data patched together, revert rules.
// SPDX-License-Identifier: MIT
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include <atomic>
#include <cstring>
#include <thread>

#include "asm_targets.hpp"
#include "check.hpp"
#include "sys.hpp"
#include "vajra/vajra.hpp"

using namespace vajra;

extern "C" {
VAJRA_PATCHABLE int tx_a(int x) {
    int r = x + 1;
    __asm__ volatile("" : "+r"(r));
    return r;
}
VAJRA_PATCHABLE int tx_b(int x) {
    int r = x + 2;
    __asm__ volatile("" : "+r"(r));
    return r;
}
VAJRA_PATCHABLE int tx_c(int x) {
    int r = x + 3;
    __asm__ volatile("" : "+r"(r));
    return r;
}
}

namespace {

template <class F>
F* opaque(F* f) {
    F* volatile p = f;
    return p;
}

int neg(int x) { return -x; }

struct Snap {
    std::uint8_t a[8], b[8], c[8];
    Snap() {
        std::memcpy(a, reinterpret_cast<void*>(&tx_a), 8);
        std::memcpy(b, reinterpret_cast<void*>(&tx_b), 8);
        std::memcpy(c, reinterpret_cast<void*>(&tx_c), 8);
    }
    bool same() const {
        return std::memcmp(a, reinterpret_cast<void*>(&tx_a), 8) == 0 &&
               std::memcmp(b, reinterpret_cast<void*>(&tx_b), 8) == 0 &&
               std::memcmp(c, reinterpret_cast<void*>(&tx_c), 8) == 0;
    }
};

// ---- a small migratable type used together with a code patch ----
struct ItemV1 {
    std::int32_t value;
    std::uint32_t id;
};
struct ItemV2 {
    std::uint64_t id;
    double value;
    std::int32_t bonus;
    std::int32_t pad;
};
const TypeDesc kItemV1 = describe<ItemV1>("Item", 1, {VAJRA_FIELD(ItemV1, value), VAJRA_FIELD(ItemV1, id)});
const TypeDesc kItemV2 = describe<ItemV2>("Item", 2, {VAJRA_FIELD(ItemV2, id), VAJRA_FIELD(ItemV2, value),
                                                      VAJRA_FIELD(ItemV2, bonus), VAJRA_FIELD(ItemV2, pad)});

}  // namespace

extern "C" VAJRA_PATCHABLE double item_score(const void* p) {
    const auto* it = static_cast<const ItemV1*>(p);
    double r = it->value * 2.0 + it->id;
    __asm__ volatile("" : "+x"(r));
    return r;
}

namespace {
double item_score_v2(const void* p) {
    const auto* it = static_cast<const ItemV2*>(p);
    return it->value * 2.0 + static_cast<double>(it->id) + it->bonus;
}
}  // namespace

TEST(fault_on_third_write_rolls_back_all) {
    const Snap before;
    int (*oa)(int) = nullptr;
    int (*ob)(int) = nullptr;
    int (*oc)(int) = nullptr;
    sys::set_write_fault_countdown(3);
    Patch p;
    CHECK_STATUS(Transaction().hook(&tx_a, &neg, &oa).hook(&tx_b, &neg, &ob).hook(&tx_c, &neg, &oc).commit(&p),
                 Status::WriteFailed);
    sys::set_write_fault_countdown(0);
    CHECK(before.same());
    CHECK(!p.active());
    CHECK(oa == nullptr && ob == nullptr && oc == nullptr);  // original pointers restored
    CHECK_EQ(opaque(&tx_a)(1), 2);
    CHECK_EQ(opaque(&tx_b)(1), 3);
    CHECK_EQ(opaque(&tx_c)(1), 4);
}

TEST(each_fault_position) {
    for (int n = 1; n <= 3; ++n) {
        const Snap before;
        sys::set_write_fault_countdown(n);
        CHECK_STATUS(Transaction().hook(&tx_a, &neg).hook(&tx_b, &neg).hook(&tx_c, &neg).commit(),
                     Status::WriteFailed);
        sys::set_write_fault_countdown(0);
        CHECK(before.same());
    }
    Patch p;
    CHECK_OK(Transaction().hook(&tx_a, &neg).hook(&tx_b, &neg).hook(&tx_c, &neg).commit(&p));
    CHECK_EQ(opaque(&tx_a)(5) + opaque(&tx_b)(5) + opaque(&tx_c)(5), -15);
    // A failing revert leaves the patch fully applied.
    sys::set_write_fault_countdown(2);
    CHECK_STATUS(p.revert(), Status::WriteFailed);
    sys::set_write_fault_countdown(0);
    CHECK(p.active());
    CHECK_EQ(opaque(&tx_a)(5) + opaque(&tx_b)(5) + opaque(&tx_c)(5), -15);
    CHECK_OK(p.revert());
    CHECK_EQ(opaque(&tx_a)(5) + opaque(&tx_b)(5) + opaque(&tx_c)(5), 6 + 7 + 8);
}

#if !defined(_WIN32)
namespace {
std::atomic<bool> g_block_quit{false};
void on_usr2(int) {}
}  // namespace

TEST(busy_when_a_thread_sits_inside_the_patch) {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr2;  // no SA_RESTART: pause() returns
    sigaction(SIGUSR2, &sa, nullptr);
    std::atomic<bool> started{false};
    std::thread t([&] {
        started = true;
        while (!g_block_quit.load()) asm_block(SYS_pause);  // PC = asm_block+4 while blocked
    });
    while (!started.load()) std::this_thread::yield();
    ::usleep(20000);

    std::uint8_t before[5];
    std::memcpy(before, reinterpret_cast<void*>(&asm_block), 5);
    PatchOptions o;
    o.busy_retries = 5;
    o.busy_retry_delay_us = 2000;
    auto fake = +[](long) -> long { return 0; };
    CHECK_STATUS(Transaction(o).hook(&asm_block, fake).commit(), Status::Busy);
    CHECK(std::memcmp(before, reinterpret_cast<void*>(&asm_block), 5) == 0);

    g_block_quit = true;
    pthread_kill(t.native_handle(), SIGUSR2);
    t.join();
    // Nobody is inside now: the same patch goes through.
    Patch p;
    CHECK_OK(Transaction(o).hook(&asm_block, fake).commit(&p));
    CHECK_EQ(opaque(&asm_block)(SYS_getpid), 0);
    CHECK_OK(p.revert());
    CHECK_EQ(opaque(&asm_block)(SYS_getpid), static_cast<long>(::getpid()));
}
#else
namespace {
std::atomic<bool> g_spin_quit{false};
DWORD WINAPI spin_thread(void*) {
    while (!g_spin_quit.load()) ::Sleep(1);
    return 0;
}
[[noreturn]] void park_exit() { ::ExitThread(0); }
}  // namespace

TEST(busy_when_a_thread_sits_inside_the_patch) {
    // A suspended thread whose instruction pointer we place at asm_window+2,
    // inside the five bytes the hook overwrites.
    HANDLE t = ::CreateThread(nullptr, 0, spin_thread, nullptr, 0, nullptr);
    CHECK(t != nullptr);
    if (!t) return;
    ::Sleep(20);
    CHECK(::SuspendThread(t) != static_cast<DWORD>(-1));
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof ctx);
    ctx.ContextFlags = CONTEXT_CONTROL;
    CHECK(::GetThreadContext(t, &ctx));
    const CONTEXT saved = ctx;
    ctx.Rip = reinterpret_cast<DWORD64>(&asm_window) + 2;
    CHECK(::SetThreadContext(t, &ctx));

    std::uint8_t before[5];
    std::memcpy(before, reinterpret_cast<void*>(&asm_window), 5);
    PatchOptions o;
    o.busy_retries = 5;
    o.busy_retry_delay_us = 2000;
    auto fake = +[]() -> int { return 0; };
    CHECK_STATUS(Transaction(o).hook(&asm_window, fake).commit(), Status::Busy);
    CHECK(std::memcmp(before, reinterpret_cast<void*>(&asm_window), 5) == 0);

    // Send the thread to ExitThread with a fresh, correctly aligned stack frame.
    ctx = saved;
    ctx.Rip = reinterpret_cast<DWORD64>(&park_exit);
    ctx.Rsp = ((saved.Rsp - 512) & ~static_cast<DWORD64>(15)) - 8;
    CHECK(::SetThreadContext(t, &ctx));
    g_spin_quit = true;
    ::ResumeThread(t);
    CHECK(::WaitForSingleObject(t, 5000) == WAIT_OBJECT_0);
    ::CloseHandle(t);

    Patch p;
    CHECK_OK(Transaction(o).hook(&asm_window, fake).commit(&p));
    CHECK_EQ(opaque(&asm_window)(), 0);
    CHECK_OK(p.revert());
    CHECK_EQ(opaque(&asm_window)(), 7);
}
#endif

TEST(code_and_data_together) {
    Heap heap;
    CHECK_OK(heap.register_type(kItemV1));
    void* roots[3] = {};
    for (int i = 0; i < 3; ++i) {
        auto* it = static_cast<ItemV1*>(heap.allocate("Item", 1));
        it->value = 10 * (i + 1);
        it->id = static_cast<std::uint32_t>(i);
        roots[i] = it;
    }
    heap.add_root_range(roots, 3);
    double before = 0;
    for (void* r : roots) before += opaque(&item_score)(r);

    MigrationPlan fwd(kItemV1, kItemV2);
    fwd.fill_int("bonus", 0);
    MigrationPlan inv(kItemV2, kItemV1);
    inv.drop("bonus").drop("pad");
    Patch p;
    CHECK_OK(Transaction().hook(&item_score, &item_score_v2).migrate(heap, fwd, inv).commit(&p));
    CHECK_EQ(heap.version("Item"), 2u);
    double after = 0;
    for (void* r : roots) after += opaque(&item_score)(r);
    CHECK(after == before);
    CHECK(heap.allocate("Item", 1) == nullptr);  // stale code is caught
    static_cast<ItemV2*>(roots[0])->bonus = 0;
    CHECK_OK(p.revert());
    CHECK_EQ(heap.version("Item"), 1u);
    double reverted = 0;
    for (void* r : roots) reverted += opaque(&item_score)(r);
    CHECK(reverted == before);
}

TEST(failed_migration_leaves_code_untouched) {
    Heap heap;
    CHECK_OK(heap.register_type(kItemV1));
    void* root = heap.allocate("Item", 1);
    static_cast<ItemV1*>(root)->value = 7;
    heap.add_root(&root);
    void* const old_root = root;
    std::uint8_t before[8];
    std::memcpy(before, reinterpret_cast<void*>(&item_score), 8);
    MigrationPlan fwd(kItemV1, kItemV2);
    fwd.transform([](const ObjectView&, ObjectView&, MigrationContext& ctx) {
        ctx.fail("refusing on purpose");
        return false;
    });
    const Result r = Transaction().hook(&item_score, &item_score_v2).migrate(heap, fwd).commit();
    CHECK_STATUS(r, Status::MigrationFailed);
    CHECK(r.message().find("refusing on purpose") != std::string::npos);
    CHECK(std::memcmp(before, reinterpret_cast<void*>(&item_score), 8) == 0);
    CHECK(root == old_root);
    CHECK_EQ(heap.version("Item"), 1u);
    CHECK_EQ(static_cast<ItemV1*>(root)->value, 7);
}

TEST(revert_rules) {
    Heap heap;
    CHECK_OK(heap.register_type(kItemV1));
    MigrationPlan fwd(kItemV1, kItemV2);
    Patch p;
    CHECK_OK(Transaction().migrate(heap, fwd).commit(&p));
    CHECK_STATUS(p.revert(), Status::NotRevertible);
    CHECK(p.active());
    Patch empty;
    CHECK_STATUS(empty.revert(), Status::NotApplied);
    // The inverse must mirror the forward plan.
    CHECK_STATUS(Transaction().migrate(heap, MigrationPlan(kItemV2, kItemV1).drop("bonus").drop("pad"),
                                       MigrationPlan(kItemV1, kItemV1))
                     .commit(),
                 Status::InvalidArgument);
}

TEST_MAIN()
