// Inline hooks on real functions: compiled C++ targets, hand-written asm
// prologues, a libc function, chaining, refusals and all write methods.
// SPDX-License-Identifier: MIT
#include <dlfcn.h>

#include <cstring>

#include "asm_targets.hpp"
#include "check.hpp"
#include "vajra/vajra.hpp"

using namespace vajra;

extern "C" {
VAJRA_PATCHABLE int target_mul3(int x) {
    int r = x * 3;
    __asm__ volatile("" : "+r"(r));
    return r;
}
VAJRA_PATCHABLE int target_named(int x) {
    int r = x - 7;
    __asm__ volatile("" : "+r"(r));
    return r;
}
VAJRA_PATCHABLE long target_sum(const long* v, int n) {
    long s = 0;
    for (int i = 0; i < n; ++i) s += v[i] * (i + 1);
    return s;
}
}

namespace {

int (*orig_mul3)(int) = nullptr;
int detour_mul3(int x) { return orig_mul3(x) + 1000; }
int replacement_mul3(int x) { return -x; }

int (*orig_chain1)(int) = nullptr;
int (*orig_chain2)(int) = nullptr;
int detour_chain1(int x) { return orig_chain1(x) + 1; }    // first hook: +1
int detour_chain2(int x) { return orig_chain2(x) * 10; }   // second hook: *10

int (*orig_rip)(int) = nullptr;
int (*orig_jcc)(int) = nullptr;
int (*orig_call)(int) = nullptr;
int (*orig_short)() = nullptr;
int detour_rip(int x) { return orig_rip(x) + 1; }
int detour_jcc(int x) { return orig_jcc(x) + 1; }
int detour_call(int x) { return orig_call(x) + 1; }
int detour_short() { return 77; }
int detour_named(int x) { return x; }

long (*orig_labs)(long) = nullptr;
long detour_labs(long x) { return orig_labs(x) * 10; }

long (*orig_sum)(const long*, int) = nullptr;
long detour_sum(const long* v, int n) { return orig_sum(v, n) + 1; }

// Calls through a volatile pointer so the compiler cannot fold the call.
template <class F>
F* opaque(F* f) {
    F* volatile p = f;
    return p;
}

bool bytes_equal(const void* a, const std::uint8_t* b, std::size_t n) { return std::memcmp(a, b, n) == 0; }

}  // namespace

TEST(hook_call_original_revert) {
    std::uint8_t before[16];
    std::memcpy(before, reinterpret_cast<void*>(&target_mul3), sizeof before);
    CHECK_EQ(opaque(&target_mul3)(5), 15);
    Patch p;
    CHECK_OK(Transaction().hook(&target_mul3, &detour_mul3, &orig_mul3).commit(&p));
    CHECK(p.active());
    CHECK_EQ(opaque(&target_mul3)(5), 1015);
    CHECK_EQ(orig_mul3(5), 15);
    CHECK(!bytes_equal(reinterpret_cast<void*>(&target_mul3), before, 5));
    CHECK(bytes_equal(reinterpret_cast<const std::uint8_t*>(reinterpret_cast<void*>(&target_mul3)) + 5, before + 5, 11));
    CHECK_OK(p.revert());
    CHECK(!p.active());
    CHECK_EQ(opaque(&target_mul3)(5), 15);
    CHECK(bytes_equal(reinterpret_cast<void*>(&target_mul3), before, sizeof before));
    CHECK_STATUS(p.revert(), Status::NotApplied);
    // The trampoline stays usable after revert (threads may still hold it).
    CHECK_EQ(orig_mul3(6), 18);
}

TEST(replace_without_original) {
    Patch p;
    CHECK_OK(Transaction().hook(&target_mul3, &replacement_mul3).commit(&p));
    CHECK_EQ(opaque(&target_mul3)(9), -9);
    CHECK_OK(p.revert());
    CHECK_EQ(opaque(&target_mul3)(9), 27);
}

TEST(trampoline_starts_with_endbr64) {
    Patch p;
    CHECK_OK(Transaction().hook(&target_sum, &detour_sum, &orig_sum).commit(&p));
    const std::uint8_t endbr[4] = {0xF3, 0x0F, 0x1E, 0xFA};
    CHECK(bytes_equal(reinterpret_cast<void*>(orig_sum), endbr, 4));
    const long v[4] = {1, 2, 3, 4};
    CHECK_EQ(opaque(&target_sum)(v, 4), 1 + 4 + 9 + 16 + 1);
    CHECK_OK(p.revert());
}

TEST(chained_hooks_and_revert_order) {
    Patch first, second;
    CHECK_OK(Transaction().hook(&target_mul3, &detour_chain1, &orig_chain1).commit(&first));
    CHECK_OK(Transaction().hook(&target_mul3, &detour_chain2, &orig_chain2).commit(&second));
    CHECK_EQ(opaque(&target_mul3)(2), (6 + 1) * 10);
    // Reverting the inner hook first would clobber the outer one: refused.
    CHECK_STATUS(first.revert(), Status::Mismatch);
    CHECK_EQ(opaque(&target_mul3)(2), 70);
    CHECK_OK(second.revert());
    CHECK_EQ(opaque(&target_mul3)(2), 7);
    CHECK_OK(first.revert());
    CHECK_EQ(opaque(&target_mul3)(2), 6);
}

TEST(asm_prologues) {
    Patch p;
    CHECK_OK(Transaction()
                 .hook(&asm_rip, &detour_rip, &orig_rip)
                 .hook(&asm_jcc, &detour_jcc, &orig_jcc)
                 .hook(&asm_call, &detour_call, &orig_call)
                 .commit(&p));
    CHECK_EQ(opaque(&asm_rip)(10), 5 + 10 + 1);
    asm_rip_data = 50;  // the relocated RIP-relative load must read the same variable
    CHECK_EQ(opaque(&asm_rip)(10), 50 + 10 + 1);
    asm_rip_data = 5;
    CHECK_EQ(opaque(&asm_jcc)(0), 101);  // je taken: jumps back into the original body
    CHECK_EQ(opaque(&asm_jcc)(4), 6);    // fall-through inside the trampoline
    CHECK_EQ(opaque(&asm_call)(3), 1004);
    CHECK_EQ(orig_call(3), 1003);
    CHECK_OK(p.revert());
    CHECK_EQ(opaque(&asm_rip)(10), 15);
    CHECK_EQ(opaque(&asm_jcc)(0), 100);
    CHECK_EQ(opaque(&asm_call)(3), 1003);
}

TEST(short_function_with_padding) {
    Patch p;
    CHECK_OK(Transaction().hook(&asm_short, &detour_short, &orig_short).commit(&p));
    CHECK_EQ(opaque(&asm_short)(), 77);
    CHECK_EQ(orig_short(), 0);
    CHECK_OK(p.revert());
    CHECK_EQ(opaque(&asm_short)(), 0);
}

TEST(hook_by_name) {
    Patch p;
    CHECK_OK(Transaction().hook("target_named", reinterpret_cast<void*>(&detour_named)).commit(&p));
    CHECK_EQ(opaque(&target_named)(10), 10);
    CHECK_OK(p.revert());
    CHECK_EQ(opaque(&target_named)(10), 3);
    CHECK_STATUS(Transaction().hook("no_such_function_xyz", reinterpret_cast<void*>(&detour_named)).commit(),
                 Status::NotFound);
}

TEST(hook_libc_function) {
    auto* labs_ptr = reinterpret_cast<long (*)(long)>(::dlsym(RTLD_DEFAULT, "labs"));
    CHECK(labs_ptr != nullptr);
    if (!labs_ptr) return;
    Patch p;
    CHECK_OK(Transaction().hook(labs_ptr, &detour_labs, &orig_labs).commit(&p));
    CHECK_EQ(labs_ptr(-5), 50);
    CHECK_OK(p.revert());
    CHECK_EQ(labs_ptr(-5), 5);
}

TEST(refusals) {
    // Branch back into the overwritten bytes (found by the body scan).
    CHECK_STATUS(Transaction().hook(&asm_loopback, &detour_rip).commit(), Status::RelocationFailed);
    CHECK_EQ(opaque(&asm_loopback)(5), 5);
    // Not a function entry.
    void* mid = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(&target_mul3) + 1);
    CHECK_STATUS(Transaction().hook(mid, reinterpret_cast<void*>(&detour_mul3)).commit(), Status::InvalidArgument);
    // Not executable.
    static int data_object = 0;
    CHECK_STATUS(Transaction().hook(&data_object, reinterpret_cast<void*>(&detour_mul3)).commit(),
                 Status::InvalidArgument);
    // Vajra's own code.
    CHECK_STATUS(Transaction().hook(reinterpret_cast<void*>(&vajra::status_name), reinterpret_cast<void*>(&detour_mul3))
                     .commit(),
                 Status::Unsupported);
    // Null detour, overlapping hooks, empty transaction, double commit.
    CHECK_STATUS(Transaction().hook(reinterpret_cast<void*>(&target_mul3), nullptr).commit(), Status::InvalidArgument);
    CHECK_STATUS(Transaction().hook(&target_mul3, &detour_mul3).hook(&target_mul3, &replacement_mul3).commit(),
                 Status::InvalidArgument);
    CHECK_STATUS(Transaction().commit(), Status::InvalidArgument);
    Transaction tx;
    tx.hook(&target_mul3, &replacement_mul3);
    Patch p;
    CHECK_OK(tx.commit(&p));
    CHECK_STATUS(tx.commit(), Status::AlreadyApplied);
    CHECK_OK(p.revert());
    CHECK_EQ(opaque(&target_mul3)(3), 9);
}

TEST(write_methods) {
    for (WriteMethod m : {WriteMethod::ProcMem, WriteMethod::MprotectRW, WriteMethod::MprotectRWX, WriteMethod::Auto}) {
        PatchOptions o;
        o.write_method = m;
        Patch p;
        CHECK_OK(Transaction(o).hook(&target_mul3, &replacement_mul3).commit(&p));
        CHECK_EQ(opaque(&target_mul3)(4), -4);
        CHECK_OK(p.revert(o));
        CHECK_EQ(opaque(&target_mul3)(4), 12);
    }
}

TEST(describe) {
    Patch p;
    CHECK_OK(Transaction().hook(&target_mul3, &replacement_mul3).commit(&p));
    const std::string d = p.describe();
    CHECK(d.find("target_mul3") != std::string::npos);
    CHECK_OK(p.revert());
    CHECK(p.describe().find("reverted") != std::string::npos);
}

TEST_MAIN()
