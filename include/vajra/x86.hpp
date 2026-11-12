// Vajra Binary Core - x86-64 instruction length decoder.
//
// The decoder determines the length and the relocation-relevant properties of
// one 64-bit-mode instruction: prefixes, REX, VEX (2/3 byte), EVEX, the legacy
// opcode maps 0F / 0F38 / 0F3A, ModRM / SIB / displacement, immediates,
// RIP-relative operands and relative branches. It does not produce mnemonics.
//
// Anything it does not understand is rejected (decode() returns false). It
// never guesses: a wrong length would corrupt relocated code.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>

namespace vajra::x86 {

constexpr std::size_t kMaxInsnLength = 15;

enum class Branch : std::uint8_t {
    None,
    JmpRel8,    // EB cb
    JmpRel32,   // E9 cd
    JccRel8,    // 70-7F cb
    JccRel32,   // 0F 80-8F cd
    CallRel32,  // E8 cd
    LoopRel8,   // E0-E3 (loopne, loope, loop, jrcxz) - not relocatable
    XBegin,     // C7 F8 cd (RTM) - not relocatable
};

struct Insn {
    std::uint8_t length = 0;
    std::uint8_t prefix_count = 0;  // legacy prefixes + REX
    std::uint8_t opcode = 0;        // final opcode byte
    std::uint8_t map = 0;           // 0 one-byte, 1 0F, 2 0F38, 3 0F3A, 5/6 EVEX maps
    bool has_modrm = false;
    std::uint8_t modrm = 0;
    bool rip_relative = false;      // ModRM mod=00 rm=101 (disp32 relative to next insn)
    bool addr32 = false;            // 67h address-size override present
    bool operand16 = false;         // 66h present
    bool rex_w = false;
    bool vex = false;
    bool evex = false;
    std::uint8_t disp_offset = 0;   // offset of displacement within the instruction
    std::uint8_t disp_size = 0;     // 0, 1 or 4
    std::uint8_t imm_offset = 0;    // offset of the immediate (first byte)
    std::uint8_t imm_size = 0;      // total immediate bytes (incl. rel for branches)
    Branch branch = Branch::None;
    std::uint8_t cond = 0;          // condition code (low nibble) for Jcc
    std::int64_t rel = 0;           // sign-extended branch displacement
    bool is_call = false;           // any call (direct, indirect, far)
    bool is_ret = false;            // ret / retf / iret
    bool terminates = false;        // control never falls through (ret, jmp, ud2, int3)
    bool is_endbr64 = false;        // F3 0F 1E FA

    // Target of a relative branch, given the address the instruction lives at.
    std::uint64_t branch_target(std::uint64_t address) const noexcept {
        return address + length + static_cast<std::uint64_t>(rel);
    }
    // Absolute address referenced by a RIP-relative operand.
    std::int32_t disp32(const std::uint8_t* code) const noexcept;
    std::uint64_t rip_target(std::uint64_t address, const std::uint8_t* code) const noexcept {
        return address + length + static_cast<std::uint64_t>(static_cast<std::int64_t>(disp32(code)));
    }
};

enum class DecodeError : std::uint8_t {
    None,
    Truncated,     // buffer ended inside the instruction
    TooLong,       // more than 15 bytes
    Invalid,       // opcode is undefined/invalid in 64-bit mode
    Unsupported,   // valid but deliberately refused (XOP, APX/REX2, EVEX map 4, ...)
};

// Decodes one instruction at `code` (at most `avail` bytes are read).
// Returns false and sets `err` (if non-null) on failure.
bool decode(const std::uint8_t* code, std::size_t avail, Insn& out, DecodeError* err = nullptr) noexcept;

const char* decode_error_name(DecodeError e) noexcept;

}  // namespace vajra::x86
