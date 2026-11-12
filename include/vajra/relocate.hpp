// Vajra Binary Core - relocation of function prologue instructions.
//
// An inline hook overwrites the first `min_bytes` bytes of a function with a
// 5-byte `jmp rel32`. The instructions covering those bytes ("stolen"
// instructions) are re-encoded at a new address (the trampoline) so that the
// original function can still be called. Relocation rules:
//
//   * plain instructions are copied;
//   * RIP-relative memory operands get a new disp32 (must stay in +-2 GiB);
//   * jmp/jcc rel8/rel32 become rel32 forms, or an absolute indirect jump when
//     the target is out of range;
//   * call rel32 becomes call rel32 or `call [rip+2]; jmp +8; .quad target`;
//   * loop/jrcxz, xbegin, EIP-relative (67h) operands are refused;
//   * a branch into the overwritten bytes is refused;
//   * a call that ends inside the overwritten bytes is refused (its return
//     address would point into rewritten code);
//   * an instruction that ends the function early (ret/jmp) is accepted only
//     when the remaining overwritten bytes are int3/nop padding.
//
// Bytes after the first `min_bytes` are left untouched in the original code,
// so a thread that is positioned on any instruction boundary at or after
// `min_bytes` keeps executing valid original instructions.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "vajra/status.hpp"

namespace vajra {

struct PrologueInput {
    const std::uint8_t* code = nullptr;  // snapshot of the original bytes
    std::size_t code_size = 0;           // valid bytes in the snapshot (>= min_bytes)
    std::uint64_t source = 0;            // runtime address of the original code
    std::size_t min_bytes = 5;           // bytes that will be overwritten
    std::size_t function_size = 0;       // size of the function, 0 if unknown
};

struct PrologueAnalysis {
    std::size_t stolen = 0;                  // bytes covered by whole stolen instructions
    std::size_t instruction_count = 0;
    bool falls_through = true;               // execution continues at source + stolen
    std::vector<std::uint64_t> rip_targets;  // must be reachable with rel32 from the trampoline
    std::vector<std::size_t> boundaries;     // instruction start offsets within the window
    std::size_t max_relocated_size = 0;      // upper bound for relocate_prologue output
};

// Decodes and validates the window. Does not depend on the destination.
Result analyze_prologue(const PrologueInput& in, PrologueAnalysis& out);

// Encodes the stolen instructions for execution at `dest`, followed by a jump
// back to source + stolen when the code falls through. An endbr64 is placed
// first unless the original already starts with one, so the trampoline is a
// valid indirect-branch target under CET/IBT.
Result relocate_prologue(const PrologueInput& in, const PrologueAnalysis& analysis,
                         std::uint64_t dest, std::vector<std::uint8_t>& out);

// Small encoders, exposed for tests and for the hook engine.
namespace enc {
bool fits_rel32(std::uint64_t from_next, std::uint64_t to);
// jmp rel32 when reachable, else `jmp qword [rip+0]; .quad to` (14 bytes).
void jmp(std::vector<std::uint8_t>& out, std::uint64_t at, std::uint64_t to);
// The 5-byte `jmp rel32` written at a hook site. Returns false if out of range.
bool jmp_rel32(std::uint8_t out[5], std::uint64_t at, std::uint64_t to);
// `jmp qword [rip+0]; .quad to`
void jmp_abs(std::vector<std::uint8_t>& out, std::uint64_t to);
}  // namespace enc

}  // namespace vajra
