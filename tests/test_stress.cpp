// Stress: patching while threads hammer the patched code, and migrating data
// (together with the code that uses it) while mutator threads keep working.
// SPDX-License-Identifier: MIT
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <thread>
#include <vector>

#include "check.hpp"
#include "vajra/vajra.hpp"

using namespace vajra;

extern "C" {
VAJRA_PATCHABLE int stress_target(int x) {
    int r = x * 3;
    __asm__ volatile("" : "+r"(r));
    return r;
}
VAJRA_PATCHABLE int stress_other(int x) {
    int r = x + 11;
    __asm__ volatile("" : "+r"(r));
    return r;
}
}

namespace {

int (*orig_target)(int) = nullptr;
int detour_target(int x) { return __atomic_load_n(&orig_target, __ATOMIC_ACQUIRE)(x) + 1; }
int (*orig_other)(int) = nullptr;
int detour_other(int x) { return __atomic_load_n(&orig_other, __ATOMIC_ACQUIRE)(x) * 2; }

template <class F>
F* opaque(F* f) {
    F* volatile p = f;
    return p;
}

int env_int(const char* name, int def) {
    const char* v = std::getenv(name);
    return v ? std::atoi(v) : def;
}

}  // namespace

TEST(hook_storm) {
    const int cycles = env_int("VAJRA_STRESS_CYCLES", 500);
    std::atomic<bool> quit{false};
    std::atomic<long> bad{0}, calls{0};
    std::vector<std::thread> ts;
    for (int t = 0; t < 8; ++t)
        ts.emplace_back([&, t] {
            auto* f = opaque(&stress_target);
            auto* g = opaque(&stress_other);
            int x = t;
            long local = 0;
            while (!quit.load(std::memory_order_relaxed)) {
                const int r = f(x);
                if (r != 3 * x && r != 3 * x + 1) bad.fetch_add(1);
                const int s = g(x);
                if (s != x + 11 && s != 2 * (x + 11)) bad.fetch_add(1);
                x = (x + 7) & 0xFFFF;
                ++local;
            }
            calls.fetch_add(local);
        });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    // Two patcher threads working on different functions at the same time.
    std::thread other_patcher([&] {
        for (int i = 0; i < cycles / 2; ++i) {
            Patch p;
            CHECK_OK(Transaction().hook(&stress_other, &detour_other, &orig_other).commit(&p));
            CHECK_OK(p.revert());
        }
    });
    for (int i = 0; i < cycles; ++i) {
        Patch p;
        CHECK_OK(Transaction().hook(&stress_target, &detour_target, &orig_target).commit(&p));
        CHECK_OK(p.revert());
    }
    other_patcher.join();
    quit = true;
    for (auto& t : ts) t.join();
    CHECK_EQ(bad.load(), 0);
    CHECK(calls.load() > 0);
    CHECK_EQ(opaque(&stress_target)(5), 15);
    CHECK_EQ(opaque(&stress_other)(5), 16);
    std::fprintf(stderr, "    %d hook/revert cycles, %ld calls from 8 threads\n", cycles + cycles / 2, calls.load());
}

// ---------------------------------------------------------------- migration storm

namespace {

struct AccountV1 {
    std::int64_t balance;
    std::uint32_t id;
    std::uint32_t pad;
};
struct AccountV2 {
    std::uint64_t id;
    std::int64_t ops;
    double balance;
};
const TypeDesc kAccV1 = describe<AccountV1>("Account", 1, {VAJRA_FIELD(AccountV1, balance), VAJRA_FIELD(AccountV1, id),
                                                           VAJRA_FIELD(AccountV1, pad)});
const TypeDesc kAccV2 = describe<AccountV2>("Account", 2, {VAJRA_FIELD(AccountV2, id), VAJRA_FIELD(AccountV2, ops),
                                                           VAJRA_FIELD(AccountV2, balance)});

constexpr int kAccounts = 64;
constexpr int kMutators = 4;
void* g_accounts[kAccounts];

}  // namespace

extern "C" VAJRA_PATCHABLE void transfer(void* from, void* to, int amount) {
    auto* a = static_cast<AccountV1*>(from);
    auto* b = static_cast<AccountV1*>(to);
    a->balance -= amount;
    b->balance += amount;
}

namespace {
void transfer_v2(void* from, void* to, int amount) {
    auto* a = static_cast<AccountV2*>(from);
    auto* b = static_cast<AccountV2*>(to);
    a->balance -= amount;
    b->balance += amount;
    ++a->ops;
    ++b->ops;
}
}  // namespace

TEST(migration_storm) {
    const int cycles = env_int("VAJRA_STRESS_MIGRATIONS", 60);
    Heap heap;
    CHECK_OK(heap.register_type(kAccV1));
    for (int i = 0; i < kAccounts; ++i) {
        auto* a = static_cast<AccountV1*>(heap.allocate("Account", 1));
        a->balance = 1000;
        a->id = static_cast<std::uint32_t>(i);
        g_accounts[i] = a;
    }
    heap.add_root_range(g_accounts, kAccounts);

    std::atomic<bool> quit{false};
    std::atomic<long> transfers{0};
    std::vector<std::thread> ts;
    for (int t = 0; t < kMutators; ++t)
        ts.emplace_back([&, t] {
            ScopedAttach attach;
            unsigned rng = 12345u + static_cast<unsigned>(t);
            const int base = t * (kAccounts / kMutators);
            long local = 0;
            auto* fn = opaque(&transfer);
            while (!quit.load(std::memory_order_relaxed)) {
                Safepoints::poll();  // no raw account pointers are held across this point
                rng = rng * 1103515245u + 12345u;
                const int i = base + static_cast<int>((rng >> 8) % (kAccounts / kMutators));
                const int j = base + static_cast<int>((rng >> 16) % (kAccounts / kMutators));
                if (i == j) continue;
                fn(g_accounts[i], g_accounts[j], 1 + static_cast<int>((rng >> 4) % 5));
                ++local;
            }
            transfers.fetch_add(local);
        });

    MigrationPlan fwd(kAccV1, kAccV2);
    fwd.drop("pad");
    MigrationPlan inv(kAccV2, kAccV1);
    inv.drop("ops");
    for (int c = 0; c < cycles; ++c) {
        Patch p;
        CHECK_OK(Transaction().hook(&transfer, &transfer_v2).migrate(heap, fwd, inv).commit(&p));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        CHECK_OK(p.revert());
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    quit = true;
    for (auto& t : ts) t.join();

    CHECK_EQ(heap.version("Account"), 1u);
    std::int64_t total = 0;
    for (int i = 0; i < kAccounts; ++i) {
        auto* a = static_cast<AccountV1*>(g_accounts[i]);
        CHECK(heap.owns(a));
        CHECK_EQ(a->id, static_cast<std::uint32_t>(i));
        total += a->balance;
    }
    CHECK_EQ(total, static_cast<std::int64_t>(kAccounts) * 1000);
    CHECK(transfers.load() > 0);
    std::fprintf(stderr, "    %d migrate+hook/revert cycles, %ld transfers from %d mutators\n", cycles,
                 transfers.load(), kMutators);
}

TEST_MAIN()
