// Vajra Binary Core - x86-64 instruction length decoder.
// SPDX-License-Identifier: MIT
#include "vajra/x86.hpp"

#include <array>
#include <cstring>

namespace vajra::x86 {

namespace {

// Operand flags for the one-byte and 0F opcode maps.
enum : std::uint8_t {
    kNone = 0,
    kM = 1 << 0,       // ModRM follows
    kIb = 1 << 1,      // 8-bit immediate
    kIw = 1 << 2,      // 16-bit immediate
    kIz = 1 << 3,      // 16/32-bit immediate (operand size)
    kInv = 1 << 4,     // invalid in 64-bit mode
    kSpecial = 1 << 5, // handled explicitly in the decoder
};

constexpr std::array<std::uint8_t, 256> make_one_byte() {
    std::array<std::uint8_t, 256> t{};
    for (int row = 0; row < 4; ++row) {  // 00-3F: ALU blocks
        for (int half = 0; half < 2; ++half) {
            const int b = row * 16 + half * 8;
            t[b + 0] = kM;
            t[b + 1] = kM;
            t[b + 2] = kM;
            t[b + 3] = kM;
            t[b + 4] = kIb;
            t[b + 5] = kIz;
            t[b + 6] = kInv;  // push/pop seg, prefixes and 0F are fixed up below
            t[b + 7] = kInv;
        }
    }
    t[0x0F] = kSpecial;                       // two-byte escape
    t[0x26] = t[0x2E] = t[0x36] = t[0x3E] = kSpecial;  // segment prefixes (prefix loop)
    for (int i = 0x40; i <= 0x4F; ++i) t[i] = kSpecial;  // REX (prefix loop)
    for (int i = 0x50; i <= 0x5F; ++i) t[i] = kNone;
    t[0x60] = t[0x61] = kInv;
    t[0x62] = kSpecial;  // EVEX
    t[0x63] = kM;        // movsxd
    t[0x64] = t[0x65] = t[0x66] = t[0x67] = kSpecial;  // prefixes
    t[0x68] = kIz;
    t[0x69] = kM | kIz;
    t[0x6A] = kIb;
    t[0x6B] = kM | kIb;
    for (int i = 0x6C; i <= 0x6F; ++i) t[i] = kNone;
    for (int i = 0x70; i <= 0x7F; ++i) t[i] = kSpecial;  // Jcc rel8
    t[0x80] = kM | kIb;
    t[0x81] = kM | kIz;
    t[0x82] = kInv;
    t[0x83] = kM | kIb;
    for (int i = 0x84; i <= 0x8E; ++i) t[i] = kM;
    t[0x8F] = kSpecial;  // pop r/m or XOP
    for (int i = 0x90; i <= 0x9F; ++i) t[i] = kNone;
    t[0x9A] = kInv;
    for (int i = 0xA0; i <= 0xA3; ++i) t[i] = kSpecial;  // mov moffs
    for (int i = 0xA4; i <= 0xA7; ++i) t[i] = kNone;
    t[0xA8] = kIb;
    t[0xA9] = kIz;
    for (int i = 0xAA; i <= 0xAF; ++i) t[i] = kNone;
    for (int i = 0xB0; i <= 0xB7; ++i) t[i] = kIb;
    for (int i = 0xB8; i <= 0xBF; ++i) t[i] = kSpecial;  // mov r, imm (imm64 with REX.W)
    t[0xC0] = t[0xC1] = kM | kIb;
    t[0xC2] = kIw;
    t[0xC3] = kNone;
    t[0xC4] = t[0xC5] = kSpecial;  // VEX
    t[0xC6] = kM | kIb;
    t[0xC7] = kSpecial;            // mov r/m, imm / xbegin
    t[0xC8] = kSpecial;            // enter iw, ib
    t[0xC9] = kNone;
    t[0xCA] = kIw;
    t[0xCB] = t[0xCC] = kNone;
    t[0xCD] = kIb;
    t[0xCE] = kInv;
    t[0xCF] = kNone;
    for (int i = 0xD0; i <= 0xD3; ++i) t[i] = kM;
    t[0xD4] = t[0xD6] = kInv;
    t[0xD5] = kSpecial;  // REX2 (Intel APX) - refused as unsupported
    t[0xD7] = kNone;
    for (int i = 0xD8; i <= 0xDF; ++i) t[i] = kM;  // x87
    for (int i = 0xE0; i <= 0xE3; ++i) t[i] = kSpecial;  // loop / jrcxz
    for (int i = 0xE4; i <= 0xE7; ++i) t[i] = kIb;
    t[0xE8] = t[0xE9] = kSpecial;  // call / jmp rel32
    t[0xEA] = kInv;
    t[0xEB] = kSpecial;            // jmp rel8
    for (int i = 0xEC; i <= 0xEF; ++i) t[i] = kNone;
    t[0xF0] = kSpecial;            // lock
    t[0xF1] = kNone;
    t[0xF2] = t[0xF3] = kSpecial;  // rep prefixes
    t[0xF4] = t[0xF5] = kNone;
    t[0xF6] = t[0xF7] = kSpecial;  // group 3
    for (int i = 0xF8; i <= 0xFD; ++i) t[i] = kNone;
    t[0xFE] = kM;
    t[0xFF] = kM;
    return t;
}

constexpr std::array<std::uint8_t, 256> make_two_byte() {
    std::array<std::uint8_t, 256> t{};
    for (auto& v : t) v = kM;  // the bulk of the 0F map takes ModRM and no immediate
    t[0x04] = kInv;
    t[0x05] = t[0x06] = t[0x07] = t[0x08] = t[0x09] = kNone;  // syscall clts sysret invd wbinvd
    t[0x0A] = kInv;
    t[0x0B] = kNone;  // ud2
    t[0x0C] = kInv;
    t[0x0E] = kNone;  // femms
    t[0x0F] = kM | kIb;  // 3DNow!: ModRM + opcode suffix byte
    t[0x24] = t[0x25] = t[0x26] = t[0x27] = kInv;
    for (int i = 0x30; i <= 0x35; ++i) t[i] = kNone;  // wrmsr rdtsc rdmsr rdpmc sysenter sysexit
    t[0x36] = kInv;
    t[0x37] = kNone;  // getsec
    t[0x38] = t[0x3A] = kSpecial;  // three-byte escapes
    t[0x39] = kInv;
    for (int i = 0x3B; i <= 0x3F; ++i) t[i] = kInv;
    for (int i = 0x70; i <= 0x73; ++i) t[i] = kM | kIb;
    t[0x77] = kNone;  // emms
    t[0x78] = kSpecial;  // vmread / extrq / insertq
    t[0x7A] = t[0x7B] = kInv;
    for (int i = 0x80; i <= 0x8F; ++i) t[i] = kSpecial;  // Jcc rel32
    t[0xA0] = t[0xA1] = t[0xA2] = kNone;  // push fs, pop fs, cpuid
    t[0xA4] = kM | kIb;  // shld imm
    t[0xA6] = t[0xA7] = kInv;
    t[0xA8] = t[0xA9] = t[0xAA] = kNone;  // push gs, pop gs, rsm
    t[0xAC] = kM | kIb;  // shrd imm
    t[0xBA] = kM | kIb;  // bt group imm
    t[0xC2] = kM | kIb;  // cmpps
    t[0xC4] = t[0xC5] = t[0xC6] = kM | kIb;  // pinsrw pextrw shufps
    for (int i = 0xC8; i <= 0xCF; ++i) t[i] = kNone;  // bswap
    return t;
}

constexpr auto kOneByte = make_one_byte();
constexpr auto kTwoByte = make_two_byte();

bool is_legacy_prefix(std::uint8_t b) {
    switch (b) {
        case 0xF0: case 0xF2: case 0xF3:
        case 0x2E: case 0x36: case 0x3E: case 0x26: case 0x64: case 0x65:
        case 0x66: case 0x67:
            return true;
        default:
            return false;
    }
}

// Has an imm8 in VEX/EVEX map 1 (0F) - the same opcodes as in the legacy map.
bool vex_map1_has_imm8(std::uint8_t op) {
    return (op >= 0x70 && op <= 0x73) || op == 0xC2 || op == 0xC4 || op == 0xC5 || op == 0xC6;
}

class Cursor {
public:
    Cursor(const std::uint8_t* p, std::size_t avail) : p_(p), avail_(avail) {}
    bool has(std::size_t n) const { return pos_ + n <= avail_; }
    std::uint8_t peek(std::size_t k = 0) const { return p_[pos_ + k]; }
    std::uint8_t next() { return p_[pos_++]; }
    void skip(std::size_t n) { pos_ += n; }
    std::size_t pos() const { return pos_; }

private:
    const std::uint8_t* p_;
    std::size_t avail_;
    std::size_t pos_ = 0;
};

}  // namespace

std::int32_t Insn::disp32(const std::uint8_t* code) const noexcept {
    std::int32_t v = 0;
    std::memcpy(&v, code + disp_offset, sizeof v);
    return v;
}

const char* decode_error_name(DecodeError e) noexcept {
    switch (e) {
        case DecodeError::None: return "none";
        case DecodeError::Truncated: return "truncated";
        case DecodeError::TooLong: return "too long";
        case DecodeError::Invalid: return "invalid in 64-bit mode";
        case DecodeError::Unsupported: return "unsupported encoding";
    }
    return "?";
}

bool decode(const std::uint8_t* code, std::size_t avail, Insn& out, DecodeError* err) noexcept {
    out = Insn{};
    auto fail = [&](DecodeError e) {
        if (err) *err = e;
        return false;
    };
    if (avail > kMaxInsnLength) avail = kMaxInsnLength + 1;  // read at most 16 bytes
    Cursor c(code, avail);

    std::uint8_t rex = 0;
    std::uint8_t rep = 0;  // last F2/F3
    bool lock_or_rep_or_66 = false;
    std::uint8_t prefixes = 0;

    // Legacy prefixes and REX. REX only counts when it immediately precedes the opcode.
    for (;;) {
        if (!c.has(1)) return fail(DecodeError::Truncated);
        const std::uint8_t b = c.peek();
        if (is_legacy_prefix(b)) {
            if (b == 0x66) out.operand16 = true;
            if (b == 0x67) out.addr32 = true;
            if (b == 0xF2 || b == 0xF3) rep = b;
            if (b == 0x66 || b == 0xF0 || b == 0xF2 || b == 0xF3) lock_or_rep_or_66 = true;
            rex = 0;
            c.skip(1);
            ++prefixes;
        } else if ((b & 0xF0) == 0x40) {
            rex = b;
            c.skip(1);
            ++prefixes;
        } else {
            break;
        }
        if (c.pos() >= kMaxInsnLength) return fail(DecodeError::TooLong);
    }
    out.prefix_count = prefixes;
    out.rex_w = (rex & 0x08) != 0;

    auto read_modrm = [&](bool force_register) -> bool {
        if (!c.has(1)) return false;
        out.has_modrm = true;
        out.modrm = c.next();
        const std::uint8_t mod = out.modrm >> 6;
        const std::uint8_t rm = out.modrm & 7;
        if (mod == 3 || force_register) return true;
        if (rm == 4) {
            if (!c.has(1)) return false;
            const std::uint8_t sib = c.next();
            if (mod == 0 && (sib & 7) == 5) {
                out.disp_offset = static_cast<std::uint8_t>(c.pos());
                out.disp_size = 4;
            }
        } else if (mod == 0 && rm == 5) {
            out.rip_relative = true;
            out.disp_offset = static_cast<std::uint8_t>(c.pos());
            out.disp_size = 4;
        }
        if (mod == 1) {
            out.disp_offset = static_cast<std::uint8_t>(c.pos());
            out.disp_size = 1;
        } else if (mod == 2) {
            out.disp_offset = static_cast<std::uint8_t>(c.pos());
            out.disp_size = 4;
        }
        if (!c.has(out.disp_size)) return false;
        c.skip(out.disp_size);
        return true;
    };
    auto take_imm = [&](std::size_t n) -> bool {
        if (n == 0) return true;
        if (!c.has(n)) return false;
        if (out.imm_size == 0) out.imm_offset = static_cast<std::uint8_t>(c.pos());
        out.imm_size = static_cast<std::uint8_t>(out.imm_size + n);
        c.skip(n);
        return true;
    };
    auto iz_size = [&]() -> std::size_t { return out.rex_w ? 4 : (out.operand16 ? 2 : 4); };
    auto finish = [&]() -> bool {
        if (c.pos() > kMaxInsnLength) return fail(DecodeError::TooLong);
        out.length = static_cast<std::uint8_t>(c.pos());
        if (err) *err = DecodeError::None;
        return true;
    };
    auto read_rel = [&](std::size_t n) {
        std::int64_t v = 0;
        if (n == 1) {
            v = static_cast<std::int8_t>(code[out.imm_offset]);
        } else {
            std::int32_t r32 = 0;
            std::memcpy(&r32, code + out.imm_offset, 4);
            v = r32;
        }
        out.rel = v;
    };

    if (!c.has(1)) return fail(DecodeError::Truncated);
    const std::uint8_t op = c.next();

    // ---- VEX (C4 / C5) and EVEX (62); always these in 64-bit mode ----
    if (op == 0xC4 || op == 0xC5 || op == 0x62) {
        if (rex != 0 || lock_or_rep_or_66) return fail(DecodeError::Invalid);  // #UD
        std::uint8_t map = 1;
        if (op == 0xC5) {
            if (!c.has(1)) return fail(DecodeError::Truncated);
            c.skip(1);
            out.vex = true;
        } else if (op == 0xC4) {
            if (!c.has(2)) return fail(DecodeError::Truncated);
            const std::uint8_t p0 = c.next();
            const std::uint8_t p1 = c.next();
            map = p0 & 0x1F;
            out.rex_w = (p1 & 0x80) != 0;
            if (map < 1 || map > 3) return fail(map == 0 ? DecodeError::Invalid : DecodeError::Unsupported);
            out.vex = true;
        } else {
            if (!c.has(3)) return fail(DecodeError::Truncated);
            const std::uint8_t p0 = c.next();
            const std::uint8_t p1 = c.next();
            c.skip(1);  // P2
            if ((p1 & 0x04) == 0) return fail(DecodeError::Invalid);  // fixed bit must be 1
            if ((p0 & 0x08) != 0) return fail(DecodeError::Unsupported);  // APX extended EVEX
            map = p0 & 0x07;
            out.rex_w = (p1 & 0x80) != 0;
            if (map == 0) return fail(DecodeError::Invalid);
            if (map == 4 || map == 7) return fail(DecodeError::Unsupported);  // APX / newer maps
            out.evex = true;
        }
        if (!c.has(1)) return fail(DecodeError::Truncated);
        out.map = map;
        out.opcode = c.next();
        const bool vzero = out.vex && map == 1 && out.opcode == 0x77;  // vzeroupper / vzeroall
        if (!vzero) {
            if (!read_modrm(false)) return fail(DecodeError::Truncated);
        }
        std::size_t imm = 0;
        if (map == 3) imm = 1;
        if (map == 1 && vex_map1_has_imm8(out.opcode)) imm = 1;
        if (!take_imm(imm)) return fail(DecodeError::Truncated);
        return finish();
    }

    // ---- Legacy two- and three-byte maps ----
    if (op == 0x0F) {
        if (!c.has(1)) return fail(DecodeError::Truncated);
        const std::uint8_t op2 = c.next();
        if (op2 == 0x38 || op2 == 0x3A) {
            if (!c.has(1)) return fail(DecodeError::Truncated);
            out.map = op2 == 0x38 ? 2 : 3;
            out.opcode = c.next();
            if (!read_modrm(false)) return fail(DecodeError::Truncated);
            if (!take_imm(op2 == 0x3A ? 1 : 0)) return fail(DecodeError::Truncated);
            return finish();
        }
        out.map = 1;
        out.opcode = op2;
        const std::uint8_t f = kTwoByte[op2];
        if (f & kInv) return fail(DecodeError::Invalid);
        if (op2 >= 0x80 && op2 <= 0x8F) {  // Jcc rel32
            if (out.operand16 && !out.rex_w) return fail(DecodeError::Unsupported);  // rel16 on AMD
            if (!take_imm(4)) return fail(DecodeError::Truncated);
            out.branch = Branch::JccRel32;
            out.cond = op2 & 0x0F;
            read_rel(4);
            return finish();
        }
        if (op2 == 0x78) {  // vmread r/m, r | 66: extrq xmm, ib, ib | F2: insertq xmm, xmm, ib, ib
            if (!read_modrm(false)) return fail(DecodeError::Truncated);
            const bool two_imm = rep == 0xF2 || (rep == 0 && out.operand16);
            if (!take_imm(two_imm ? 2 : 0)) return fail(DecodeError::Truncated);
            return finish();
        }
        if (f & kM) {
            const bool cr_dr = op2 >= 0x20 && op2 <= 0x23;  // mov to/from CR/DR: always register form
            if (!read_modrm(cr_dr)) return fail(DecodeError::Truncated);
        }
        if (f & kIb) {
            if (!take_imm(1)) return fail(DecodeError::Truncated);
        }
        if (op2 == 0x0B) out.terminates = true;  // ud2
        if (op2 == 0x1E && rep == 0xF3 && out.modrm == 0xFA) out.is_endbr64 = true;
        return finish();
    }

    // ---- One-byte map ----
    out.map = 0;
    out.opcode = op;
    const std::uint8_t f = kOneByte[op];
    if (f & kInv) return fail(DecodeError::Invalid);

    if (f & kSpecial) {
        if (op >= 0x70 && op <= 0x7F) {
            if (out.operand16 && !out.rex_w) return fail(DecodeError::Unsupported);
            if (!take_imm(1)) return fail(DecodeError::Truncated);
            out.branch = Branch::JccRel8;
            out.cond = op & 0x0F;
            read_rel(1);
            return finish();
        }
        switch (op) {
            case 0xD5:  // REX2 prefix of Intel APX; invalid on CPUs without APX
                return fail(DecodeError::Unsupported);
            case 0x8F: {  // pop r/m64, or AMD XOP when ModRM.reg != 0
                if (!c.has(1)) return fail(DecodeError::Truncated);
                if ((c.peek() & 0x38) != 0) return fail(DecodeError::Unsupported);
                if (!read_modrm(false)) return fail(DecodeError::Truncated);
                return finish();
            }
            case 0xA0: case 0xA1: case 0xA2: case 0xA3:  // mov al/eax <-> moffs
                if (!take_imm(out.addr32 ? 4 : 8)) return fail(DecodeError::Truncated);
                return finish();
            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                if (!take_imm(out.rex_w ? 8 : (out.operand16 ? 2 : 4))) return fail(DecodeError::Truncated);
                return finish();
            case 0xC7: {  // mov r/m, imm  /  C7 F8: xbegin rel
                if (!read_modrm(false)) return fail(DecodeError::Truncated);
                if (!take_imm(iz_size())) return fail(DecodeError::Truncated);
                if (out.modrm == 0xF8) out.branch = Branch::XBegin;
                return finish();
            }
            case 0xC8:  // enter iw, ib
                if (!take_imm(3)) return fail(DecodeError::Truncated);
                return finish();
            case 0xE0: case 0xE1: case 0xE2: case 0xE3:
                if (!take_imm(1)) return fail(DecodeError::Truncated);
                out.branch = Branch::LoopRel8;
                read_rel(1);
                return finish();
            case 0xE8: case 0xE9:
                if (out.operand16 && !out.rex_w) return fail(DecodeError::Unsupported);
                if (!take_imm(4)) return fail(DecodeError::Truncated);
                out.branch = op == 0xE8 ? Branch::CallRel32 : Branch::JmpRel32;
                out.is_call = op == 0xE8;
                out.terminates = op == 0xE9;
                read_rel(4);
                return finish();
            case 0xEB:
                if (out.operand16 && !out.rex_w) return fail(DecodeError::Unsupported);
                if (!take_imm(1)) return fail(DecodeError::Truncated);
                out.branch = Branch::JmpRel8;
                out.terminates = true;
                read_rel(1);
                return finish();
            case 0xF6: case 0xF7: {  // group 3: test has an immediate
                if (!read_modrm(false)) return fail(DecodeError::Truncated);
                const std::uint8_t reg = (out.modrm >> 3) & 7;
                if (reg <= 1) {
                    if (!take_imm(op == 0xF6 ? 1 : iz_size())) return fail(DecodeError::Truncated);
                }
                return finish();
            }
            default:
                // Prefix bytes are consumed above; reaching here means a prefix
                // byte in opcode position, which cannot happen.
                return fail(DecodeError::Invalid);
        }
    }

    if (f & kM) {
        if (!read_modrm(false)) return fail(DecodeError::Truncated);
    }
    if (f & kIb) {
        if (!take_imm(1)) return fail(DecodeError::Truncated);
    }
    if (f & kIw) {
        if (!take_imm(2)) return fail(DecodeError::Truncated);
    }
    if (f & kIz) {
        if (!take_imm(iz_size())) return fail(DecodeError::Truncated);
    }

    switch (op) {
        case 0xC3: case 0xC2: case 0xCB: case 0xCA: case 0xCF:
            out.is_ret = true;
            out.terminates = true;
            break;
        case 0xCC:
            out.terminates = true;
            break;
        case 0xFF: {
            const std::uint8_t reg = (out.modrm >> 3) & 7;
            if (reg == 2 || reg == 3) out.is_call = true;
            if (reg == 4 || reg == 5) out.terminates = true;
            if (reg == 7) return fail(DecodeError::Invalid);
            break;
        }
        case 0xFE:
            if (((out.modrm >> 3) & 7) > 1) return fail(DecodeError::Invalid);  // only inc/dec
            break;
        default:
            break;
    }
    return finish();
}

}  // namespace vajra::x86
