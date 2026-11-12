// Decoder unit tests: lengths and relocation-relevant properties of
// hand-assembled x86-64 instructions.
// SPDX-License-Identifier: MIT
#include <initializer_list>
#include <vector>

#include "check.hpp"
#include "vajra/x86.hpp"

using namespace vajra::x86;

namespace {

std::vector<std::uint8_t> B(std::initializer_list<int> v) {
    std::vector<std::uint8_t> r;
    for (int x : v) r.push_back(static_cast<std::uint8_t>(x));
    return r;
}

Insn dec(const std::vector<std::uint8_t>& b, bool expect_ok = true) {
    // Pad with garbage so the decoder cannot rely on the buffer end.
    std::vector<std::uint8_t> buf = b;
    for (int i = 0; i < 16; ++i) buf.push_back(0xCC);
    Insn insn;
    DecodeError err;
    const bool ok = decode(buf.data(), buf.size(), insn, &err);
    if (ok != expect_ok) {
        std::string hexs;
        for (auto x : b) {
            char t[4];
            std::snprintf(t, sizeof t, "%02x ", x);
            hexs += t;
        }
        ::check::report(__FILE__, __LINE__, "decode(" + hexs + ") ok=" + std::to_string(ok) + " err=" +
                                                decode_error_name(err));
    }
    return insn;
}

void expect_len(const std::vector<std::uint8_t>& b) {
    const Insn i = dec(b);
    if (i.length != b.size()) {
        std::string hexs;
        for (auto x : b) {
            char t[4];
            std::snprintf(t, sizeof t, "%02x ", x);
            hexs += t;
        }
        ::check::report(__FILE__, __LINE__, "length of " + hexs + "= " + std::to_string(i.length) + ", expected " +
                                                std::to_string(b.size()));
    }
}

DecodeError err_of(const std::vector<std::uint8_t>& b, bool pad = true) {
    std::vector<std::uint8_t> buf = b;
    if (pad)
        for (int i = 0; i < 16; ++i) buf.push_back(0x90);
    Insn insn;
    DecodeError err = DecodeError::None;
    decode(buf.data(), buf.size(), insn, &err);
    return err;
}

}  // namespace

TEST(simple_lengths) {
    expect_len(B({0x90}));
    expect_len(B({0x55}));
    expect_len(B({0x48, 0x89, 0xE5}));
    expect_len(B({0x48, 0x83, 0xEC, 0x10}));
    expect_len(B({0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00}));
    expect_len(B({0xB8, 0x01, 0x00, 0x00, 0x00}));
    expect_len(B({0x66, 0xB8, 0x01, 0x00}));
    expect_len(B({0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8}));
    expect_len(B({0x41, 0xFF, 0xD3}));
    expect_len(B({0xC8, 0x10, 0x00, 0x00}));
    expect_len(B({0xC2, 0x08, 0x00}));
    expect_len(B({0xF0, 0x48, 0x0F, 0xB1, 0x0E}));
    expect_len(B({0x48, 0x0F, 0xC7, 0x0E}));
    expect_len(B({0x0F, 0xAE, 0xF0}));
    expect_len(B({0xD9, 0xC9}));
    expect_len(B({0xFE, 0xC0}));
    expect_len(B({0x0F, 0x05}));
    expect_len(B({0x8F, 0xC0}));
}

TEST(nops_and_endbr) {
    expect_len(B({0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}));
    expect_len(B({0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}));
    expect_len(B({0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}));
    const Insn e = dec(B({0xF3, 0x0F, 0x1E, 0xFA}));
    CHECK_EQ(e.length, 4);
    CHECK(e.is_endbr64);
    CHECK(!dec(B({0xF3, 0x0F, 0x1E, 0xFB})).is_endbr64);  // endbr32
}

TEST(modrm_sib_disp) {
    expect_len(B({0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0}));        // [disp32] via SIB, no base
    expect_len(B({0x48, 0x8B, 0x44, 0x24, 0x08}));              // [rsp+8]
    expect_len(B({0x48, 0x8B, 0x84, 0x24, 0x00, 0x01, 0, 0}));  // [rsp+0x100]
    expect_len(B({0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0, 0, 0}));
    expect_len(B({0x8B, 0x45, 0xFC}));                          // [rbp-4]
    expect_len(B({0x8B, 0x85, 0x00, 0xFF, 0xFF, 0xFF}));        // [rbp-0x100]
    const Insn sib = dec(B({0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0}));
    CHECK(!sib.rip_relative);
}

TEST(rip_relative) {
    const auto mov = B({0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00});
    const Insn a = dec(mov);
    CHECK_EQ(a.length, 7);
    CHECK(a.rip_relative);
    CHECK_EQ(a.disp_offset, 3);
    CHECK_EQ(a.rip_target(0x1000, mov.data()), 0x1000u + 7 + 0x10);

    const auto store = B({0xC7, 0x05, 0x08, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00});  // mov dword [rip+8], 42
    const Insn b = dec(store);
    CHECK_EQ(b.length, 10);
    CHECK(b.rip_relative);
    CHECK_EQ(b.imm_size, 4);
    CHECK_EQ(b.rip_target(0x1000, store.data()), 0x1000u + 10 + 8);  // relative to the end, past the immediate

    const auto lea = B({0x48, 0x8D, 0x3D, 0xF0, 0xFF, 0xFF, 0xFF});
    CHECK_EQ(dec(lea).rip_target(0x1000, lea.data()), 0x1000u + 7 - 0x10);
    CHECK(dec(B({0xFF, 0x25, 0, 0, 0, 0})).rip_relative);
    CHECK(dec(B({0xDD, 0x05, 0, 0, 0, 0})).rip_relative);  // fld qword [rip]
    const Insn e32 = dec(B({0x67, 0x8B, 0x05, 0, 0, 0, 0}));
    CHECK(e32.rip_relative && e32.addr32);
}

TEST(branches) {
    Insn i = dec(B({0xE8, 0, 0, 0, 0}));
    CHECK(i.branch == Branch::CallRel32 && i.is_call && i.length == 5);
    i = dec(B({0xE9, 0xFB, 0xFF, 0xFF, 0xFF}));
    CHECK(i.branch == Branch::JmpRel32 && i.terminates);
    CHECK_EQ(i.rel, -5);
    CHECK_EQ(i.branch_target(0x1000), 0x1000u);
    i = dec(B({0xEB, 0xFE}));
    CHECK(i.branch == Branch::JmpRel8 && i.rel == -2 && i.terminates);
    i = dec(B({0x74, 0x05}));
    CHECK(i.branch == Branch::JccRel8 && i.cond == 4 && !i.terminates);
    i = dec(B({0x0F, 0x85, 0x00, 0x01, 0x00, 0x00}));
    CHECK(i.branch == Branch::JccRel32 && i.cond == 5 && i.rel == 0x100 && i.length == 6);
    CHECK(dec(B({0xE2, 0xFE})).branch == Branch::LoopRel8);
    CHECK(dec(B({0xE3, 0x00})).branch == Branch::LoopRel8);
    i = dec(B({0xC7, 0xF8, 0, 0, 0, 0}));
    CHECK(i.branch == Branch::XBegin && i.length == 6);
    CHECK_EQ(dec(B({0xC6, 0xF8, 0x01})).length, 3);  // xabort
    // TLS general-dynamic sequence: data16 data16 rex.W call rel32
    i = dec(B({0x66, 0x66, 0x48, 0xE8, 0, 0, 0, 0}));
    CHECK(i.branch == Branch::CallRel32 && i.length == 8);
    CHECK(err_of(B({0x66, 0xE8, 0, 0})) == DecodeError::Unsupported);  // rel16 vs rel32 differs by vendor
    CHECK(err_of(B({0x66, 0x74, 0x00})) == DecodeError::Unsupported);
}

TEST(indirect_and_terminators) {
    Insn i = dec(B({0xFF, 0x15, 0, 0, 0, 0}));
    CHECK(i.is_call && i.rip_relative && !i.terminates);
    i = dec(B({0xFF, 0xD0}));
    CHECK(i.is_call && i.length == 2);
    i = dec(B({0xFF, 0xE0}));
    CHECK(i.terminates && !i.is_call);
    i = dec(B({0xC3}));
    CHECK(i.is_ret && i.terminates);
    CHECK(dec(B({0xCC})).terminates);
    CHECK(dec(B({0x0F, 0x0B})).terminates);
    CHECK(!dec(B({0xF4})).terminates);  // hlt is privileged, not modelled as a terminator
}

TEST(group3_immediates) {
    expect_len(B({0xF6, 0xC1, 0x01}));              // test cl, 1
    expect_len(B({0xF7, 0xC1, 0x01, 0, 0, 0}));     // test ecx, 1
    expect_len(B({0x66, 0xF7, 0xC1, 0x01, 0x00}));  // test cx, 1
    expect_len(B({0x48, 0xF7, 0xC1, 1, 0, 0, 0}));  // test rcx, imm32
    expect_len(B({0xF6, 0xD1}));                    // not cl
    expect_len(B({0xF7, 0xE1}));                    // mul ecx
}

TEST(moffs) {
    expect_len(B({0xA1, 1, 2, 3, 4, 5, 6, 7, 8}));
    expect_len(B({0x67, 0xA1, 1, 2, 3, 4}));
    expect_len(B({0x48, 0xA3, 1, 2, 3, 4, 5, 6, 7, 8}));
}

TEST(two_and_three_byte_maps) {
    expect_len(B({0x0F, 0x3A, 0x0F, 0xC1, 0x08}));        // palignr mm, mm, 8
    expect_len(B({0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x08}));  // palignr xmm
    expect_len(B({0x66, 0x0F, 0x38, 0x00, 0xC1}));        // pshufb
    expect_len(B({0x0F, 0x20, 0xC0}));                    // mov rax, cr0
    expect_len(B({0x0F, 0x20, 0x05}));                    // mod bits ignored for CR moves
    expect_len(B({0x66, 0x0F, 0x78, 0xC0, 0x01, 0x02}));  // extrq xmm0, 1, 2
    expect_len(B({0xF2, 0x0F, 0x78, 0xC1, 0x01, 0x02}));  // insertq
    expect_len(B({0x0F, 0x78, 0xC0}));                    // vmread
    expect_len(B({0x0F, 0x0F, 0xC1, 0xB4}));              // 3DNow! pfmul
    expect_len(B({0x0F, 0xBA, 0xE0, 0x05}));              // bt eax, 5
    expect_len(B({0x0F, 0xA4, 0xC2, 0x04}));              // shld edx, eax, 4
    expect_len(B({0x66, 0x0F, 0xC6, 0xC1, 0x1B}));        // shufpd
    expect_len(B({0x0F, 0xC8}));                          // bswap eax
    expect_len(B({0x0F, 0x01, 0xD0}));                    // xgetbv
    expect_len(B({0x66, 0x0F, 0x70, 0xC1, 0x1B}));        // pshufd
}

TEST(vex_evex) {
    Insn i = dec(B({0xC5, 0xF8, 0x77}));
    CHECK(i.vex && i.length == 3);  // vzeroupper, no ModRM
    i = dec(B({0xC5, 0xFD, 0x6F, 0x05, 0, 0, 0, 0}));
    CHECK(i.vex && i.rip_relative && i.length == 8);
    expect_len(B({0xC4, 0xE3, 0x7D, 0x18, 0xC1, 0x01}));             // vinsertf128 (map 3, imm8)
    expect_len(B({0xC4, 0xE2, 0x79, 0x18, 0x05, 0, 0, 0, 0}));       // vbroadcastss xmm0, [rip]
    expect_len(B({0xC5, 0xF9, 0x70, 0xC1, 0x1B}));                   // vpshufd (map 1, imm8)
    i = dec(B({0x62, 0xF1, 0x7C, 0x48, 0x10, 0x05, 0, 0, 0, 0}));  // vmovups zmm0, [rip]
    CHECK(i.evex && i.rip_relative && i.length == 10);
    expect_len(B({0x62, 0xF3, 0x7D, 0x48, 0x1E, 0xC1, 0x05}));       // vpcmpud k0, zmm0, zmm1, 5
    expect_len(B({0x62, 0xF1, 0x7C, 0x48, 0x10, 0x40, 0x01}));       // disp8*N: still one byte
    CHECK(err_of(B({0x62, 0xF4, 0x7C, 0x08, 0x00, 0xC0})) == DecodeError::Unsupported);  // APX map 4
    CHECK(err_of(B({0x48, 0xC5, 0xF8, 0x77})) == DecodeError::Invalid);  // REX before VEX
    CHECK(err_of(B({0x66, 0xC5, 0xF8, 0x77})) == DecodeError::Invalid);  // 66 before VEX
    CHECK(err_of(B({0xC4, 0xE0, 0x7D, 0x18, 0xC1})) == DecodeError::Invalid);  // map 0
}

TEST(prefix_rules) {
    // REX followed by a legacy prefix is ignored, but still part of the instruction.
    const Insn i = dec(B({0x48, 0x66, 0xB8, 0x01, 0x00}));
    CHECK_EQ(i.length, 5);
    CHECK(!i.rex_w && i.operand16);
    std::vector<std::uint8_t> ok15(15, 0x66);
    ok15[14] = 0x90;
    expect_len(ok15);
    std::vector<std::uint8_t> too_long(16, 0x66);
    too_long[15] = 0x90;
    CHECK(err_of(too_long) == DecodeError::TooLong);
}

TEST(invalid_and_unsupported) {
    for (int op : {0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x27, 0x2F, 0x37, 0x3F, 0x60, 0x61, 0x82, 0x9A, 0xCE,
                   0xD4, 0xD6, 0xEA})
        CHECK(err_of(B({op, 0x00})) == DecodeError::Invalid);
    CHECK(err_of(B({0x0F, 0x04})) == DecodeError::Invalid);
    CHECK(err_of(B({0x0F, 0x0A})) == DecodeError::Invalid);
    CHECK(err_of(B({0xFE, 0xF0})) == DecodeError::Invalid);  // FE /6
    CHECK(err_of(B({0xFF, 0xF8})) == DecodeError::Invalid);  // FF /7
    CHECK(err_of(B({0x8F, 0xE8, 0x78, 0xC2, 0xC1, 0x01})) == DecodeError::Unsupported);  // AMD XOP
    CHECK(err_of(B({0xD5, 0x9B, 0x01, 0x00})) == DecodeError::Unsupported);              // APX REX2
}

TEST(truncated) {
    CHECK(err_of(B({0x48, 0x8B}), false) == DecodeError::Truncated);
    CHECK(err_of(B({0xE8, 0x00, 0x00}), false) == DecodeError::Truncated);
    CHECK(err_of(B({0x48, 0x8B, 0x05, 0x00}), false) == DecodeError::Truncated);
    CHECK(err_of(B({0xC4, 0xE3}), false) == DecodeError::Truncated);
    CHECK(err_of(B({}), false) == DecodeError::Truncated);
}

TEST_MAIN()
