// Prologue analysis and relocation: byte-exact checks of the re-encoded code.
// SPDX-License-Identifier: MIT
#include <cstring>
#include <initializer_list>
#include <vector>

#include "check.hpp"
#include "vajra/relocate.hpp"

using namespace vajra;

namespace {

constexpr std::uint64_t kSrc = 0x401000;

std::vector<std::uint8_t> B(std::initializer_list<int> v) {
    std::vector<std::uint8_t> r;
    for (int x : v) r.push_back(static_cast<std::uint8_t>(x));
    while (r.size() < 32) r.push_back(0xCC);
    return r;
}

PrologueInput input(const std::vector<std::uint8_t>& code, std::size_t fsize = 0) {
    PrologueInput in;
    in.code = code.data();
    in.code_size = code.size();
    in.source = kSrc;
    in.min_bytes = 5;
    in.function_size = fsize;
    return in;
}

std::int32_t rel_at(const std::vector<std::uint8_t>& v, std::size_t off) {
    std::int32_t r;
    std::memcpy(&r, v.data() + off, 4);
    return r;
}

std::uint64_t abs_at(const std::vector<std::uint8_t>& v, std::size_t off) {
    std::uint64_t r;
    std::memcpy(&r, v.data() + off, 8);
    return r;
}

}  // namespace

TEST(endbr_push_mov) {
    const auto code = B({0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5, 0xC3});
    const auto in = input(code);
    PrologueAnalysis an;
    CHECK_OK(analyze_prologue(in, an));
    CHECK_EQ(an.stolen, 5u);
    CHECK_EQ(an.instruction_count, 2u);
    CHECK(an.falls_through);
    std::vector<std::uint8_t> out;
    const std::uint64_t dest = 0x500000;
    CHECK_OK(relocate_prologue(in, an, dest, out));
    // endbr64 is copied (not duplicated), push rbp, then jmp back to +5
    CHECK_EQ(out.size(), 4u + 1u + 5u);
    CHECK(std::memcmp(out.data(), code.data(), 5) == 0);
    CHECK_EQ(out[5], 0xE9);
    CHECK_EQ(dest + 10 + static_cast<std::uint64_t>(static_cast<std::int64_t>(rel_at(out, 6))), kSrc + 5);
    CHECK(out.size() <= an.max_relocated_size);
}

TEST(prepends_endbr_when_missing) {
    const auto code = B({0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10});
    const auto in = input(code);
    PrologueAnalysis an;
    CHECK_OK(analyze_prologue(in, an));
    CHECK_EQ(an.stolen, 8u);  // push(1) + mov(3) + sub(4)
    std::vector<std::uint8_t> out;
    CHECK_OK(relocate_prologue(in, an, 0x500000, out));
    const std::uint8_t endbr[4] = {0xF3, 0x0F, 0x1E, 0xFA};
    CHECK(std::memcmp(out.data(), endbr, 4) == 0);
    CHECK(std::memcmp(out.data() + 4, code.data(), 8) == 0);
}

TEST(rip_relative_fixup) {
    // mov rax, [rip+0x10]; ret   -> target 0x401017
    const auto code = B({0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, 0xC3});
    const auto in = input(code);
    PrologueAnalysis an;
    CHECK_OK(analyze_prologue(in, an));
    CHECK_EQ(an.rip_targets.size(), 1u);
    CHECK_EQ(an.rip_targets[0], kSrc + 7 + 0x10);
    std::vector<std::uint8_t> out;
    const std::uint64_t dest = 0x402000;
    CHECK_OK(relocate_prologue(in, an, dest, out));
    // after the 4-byte endbr, the mov sits at dest+4 and ends at dest+11
    CHECK_EQ(out[4], 0x48);
    CHECK_EQ(out[6], 0x05);
    CHECK_EQ(static_cast<std::int64_t>(rel_at(out, 7)), static_cast<std::int64_t>(kSrc + 0x17) -
                                                            static_cast<std::int64_t>(dest + 11));
}

TEST(rip_relative_out_of_range) {
    const auto code = B({0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, 0xC3});
    const auto in = input(code);
    PrologueAnalysis an;
    CHECK_OK(analyze_prologue(in, an));
    std::vector<std::uint8_t> out;
    CHECK_STATUS(relocate_prologue(in, an, kSrc + (3ull << 30), out), Status::OutOfRange);
}

TEST(jcc_rel8_becomes_rel32) {
    // je +0x10; nop; nop; nop
    const auto code = B({0x74, 0x10, 0x90, 0x90, 0x90});
    const auto in = input(code);
    PrologueAnalysis an;
    CHECK_OK(analyze_prologue(in, an));
    std::vector<std::uint8_t> out;
    const std::uint64_t dest = 0x500000;
    CHECK_OK(relocate_prologue(in, an, dest, out));
    CHECK_EQ(out[4], 0x0F);
    CHECK_EQ(out[5], 0x84);
    CHECK_EQ(dest + 4 + 6 + static_cast<std::uint64_t>(static_cast<std::int64_t>(rel_at(out, 6))), kSrc + 2 + 0x10);
}

TEST(jcc_far_uses_inverted_short_jump) {
    const auto code = B({0x74, 0x10, 0x90, 0x90, 0x90});
    const auto in = input(code);
    PrologueAnalysis an;
    CHECK_OK(analyze_prologue(in, an));
    std::vector<std::uint8_t> out;
    const std::uint64_t dest = kSrc + (8ull << 30);  // 8 GiB away: rel32 impossible
    CHECK_OK(relocate_prologue(in, an, dest, out));
    CHECK_EQ(out[4], 0x75);  // jne (inverted)
    CHECK_EQ(out[5], 14);    // skips the absolute jump
    CHECK_EQ(out[6], 0xFF);
    CHECK_EQ(out[7], 0x25);
    CHECK_EQ(abs_at(out, 12), kSrc + 0x12);
    // the jump back is absolute too
    CHECK_EQ(out[23], 0xFF);
    CHECK_EQ(abs_at(out, 23 + 6), kSrc + 5);
    CHECK(out.size() <= an.max_relocated_size);
}

TEST(call_rel32) {
    const auto code = B({0xE8, 0x00, 0x01, 0x00, 0x00, 0xC3});  // call +0x100
    const auto in = input(code);
    PrologueAnalysis an;
    CHECK_OK(analyze_prologue(in, an));
    std::vector<std::uint8_t> near_out, far_out;
    CHECK_OK(relocate_prologue(in, an, 0x500000, near_out));
    CHECK_EQ(near_out[4], 0xE8);
    CHECK_EQ(0x500000u + 9 + static_cast<std::uint64_t>(static_cast<std::int64_t>(rel_at(near_out, 5))),
             kSrc + 5 + 0x100);
    CHECK_OK(relocate_prologue(in, an, kSrc + (8ull << 30), far_out));
    CHECK_EQ(far_out[4], 0xFF);
    CHECK_EQ(far_out[5], 0x15);
    CHECK_EQ(far_out[10], 0xEB);
    CHECK_EQ(far_out[11], 0x08);
    CHECK_EQ(abs_at(far_out, 12), kSrc + 5 + 0x100);
}

TEST(refusals) {
    PrologueAnalysis an;
    // call rax at +0 returns to +2, inside the overwritten bytes
    CHECK_STATUS(analyze_prologue(input(B({0xFF, 0xD0, 0x90, 0x90, 0x90})), an), Status::RelocationFailed);
    // loop / jrcxz
    CHECK_STATUS(analyze_prologue(input(B({0xE2, 0x10, 0x90, 0x90, 0x90})), an), Status::RelocationFailed);
    // xbegin
    CHECK_STATUS(analyze_prologue(input(B({0xC7, 0xF8, 0, 0, 0, 0})), an), Status::RelocationFailed);
    // jmp +1 lands at +3, inside the window (the int3s pass the padding check)
    CHECK_STATUS(analyze_prologue(input(B({0xEB, 0x01, 0xCC, 0xCC, 0xCC})), an), Status::RelocationFailed);
    // je to +5, which is the middle of the mov that straddles the patch end
    CHECK_STATUS(analyze_prologue(input(B({0x74, 0x03, 0x90, 0x48, 0x89, 0xE5, 0xC3})), an),
                 Status::RelocationFailed);
    // je back to the function start
    CHECK_STATUS(analyze_prologue(input(B({0x90, 0x74, 0xFD, 0x90, 0x90})), an), Status::RelocationFailed);
    // EIP-relative operand
    CHECK_STATUS(analyze_prologue(input(B({0x67, 0x8B, 0x05, 0, 0, 0, 0})), an), Status::RelocationFailed);
    // function shorter than the patch without padding
    CHECK_STATUS(analyze_prologue(input(B({0x31, 0xC0, 0xC3, 0x55, 0x48})), an), Status::RelocationFailed);
    // instruction crossing the known function end
    CHECK_STATUS(analyze_prologue(input(B({0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10}), 5), an),
                 Status::RelocationFailed);
    // undecodable
    CHECK_STATUS(analyze_prologue(input(B({0x06, 0x90, 0x90, 0x90, 0x90})), an), Status::DecodeFailed);
}

TEST(short_function_with_padding) {
    const auto code = B({0x31, 0xC0, 0xC3, 0xCC, 0xCC});  // xor eax,eax; ret; int3 int3
    const auto in = input(code, 3);
    PrologueAnalysis an;
    CHECK_OK(analyze_prologue(in, an));
    CHECK(!an.falls_through);
    CHECK_EQ(an.stolen, 5u);
    std::vector<std::uint8_t> out;
    CHECK_OK(relocate_prologue(in, an, 0x500000, out));
    CHECK_EQ(out.size(), 4u + 3u);  // endbr + xor + ret, no jump back
}

TEST(chained_hook_prologue) {
    // An already-hooked function starts with jmp rel32 to a relay.
    const auto code = B({0xE9, 0x00, 0x10, 0x00, 0x00, 0x48, 0x89, 0xE5});
    const auto in = input(code);
    PrologueAnalysis an;
    CHECK_OK(analyze_prologue(in, an));
    CHECK(!an.falls_through);
    std::vector<std::uint8_t> out;
    CHECK_OK(relocate_prologue(in, an, 0x500000, out));
    CHECK_EQ(out[4], 0xE9);
    CHECK_EQ(0x500000u + 9 + static_cast<std::uint64_t>(static_cast<std::int64_t>(rel_at(out, 5))), kSrc + 5 + 0x1000);
}

TEST(encoders) {
    std::uint8_t j[5];
    CHECK(enc::jmp_rel32(j, 0x1000, 0x2000));
    CHECK_EQ(j[0], 0xE9);
    std::int32_t r;
    std::memcpy(&r, j + 1, 4);
    CHECK_EQ(r, 0x2000 - 0x1005);
    CHECK(!enc::jmp_rel32(j, 0x1000, 0x1000 + (3ull << 30)));
    CHECK(enc::fits_rel32(0x80000000ull, 0x80000000ull + 0x7FFFFFFFull));
    CHECK(!enc::fits_rel32(0x80000000ull, 0x80000000ull + 0x80000000ull));
    CHECK(enc::fits_rel32(0x80000000ull, 0));
    CHECK(!enc::fits_rel32(0x80000001ull, 0));
}

TEST_MAIN()
