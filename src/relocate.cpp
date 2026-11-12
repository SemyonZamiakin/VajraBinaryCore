// Vajra Binary Core - relocation of function prologue instructions.
// SPDX-License-Identifier: MIT
#include "vajra/relocate.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

#include "vajra/x86.hpp"

namespace vajra {

namespace {

std::string hex(std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

void put32(std::vector<std::uint8_t>& out, std::int32_t v) {
    std::uint8_t b[4];
    std::memcpy(b, &v, 4);
    out.insert(out.end(), b, b + 4);
}

void put64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    std::uint8_t b[8];
    std::memcpy(b, &v, 8);
    out.insert(out.end(), b, b + 8);
}

// One padding instruction at p: int3, nop / xchg ax,ax, or the multi-byte
// `0F 1F /0` nop, optionally with 66/2E/3E prefixes (as GCC and Clang emit).
bool padding_insn(const std::uint8_t* p, std::size_t avail, std::size_t& len) {
    x86::Insn i;
    if (!x86::decode(p, avail, i)) return false;
    for (std::size_t k = 0; k < i.prefix_count; ++k)
        if (p[k] != 0x66 && p[k] != 0x2E && p[k] != 0x3E) return false;
    len = i.length;
    if (i.map == 0 && (i.opcode == 0x90 || i.opcode == 0xCC)) return true;
    return i.map == 1 && i.opcode == 0x1F && ((i.modrm >> 3) & 7) == 0;
}

constexpr std::size_t kEndbrSize = 4;
constexpr std::size_t kAbsJmpSize = 14;   // ff 25 00000000 + imm64
constexpr std::size_t kMaxJccSize = 16;   // 7x 0e + abs jmp
constexpr std::size_t kMaxCallSize = 16;  // ff 15 02000000, eb 08, imm64

}  // namespace

namespace enc {

bool fits_rel32(std::uint64_t from_next, std::uint64_t to) {
    const std::int64_t d = static_cast<std::int64_t>(to - from_next);
    return d >= INT32_MIN && d <= INT32_MAX;
}

void jmp_abs(std::vector<std::uint8_t>& out, std::uint64_t to) {
    const std::uint8_t ind[6] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    out.insert(out.end(), ind, ind + 6);
    put64(out, to);
}

void jmp(std::vector<std::uint8_t>& out, std::uint64_t at, std::uint64_t to) {
    if (fits_rel32(at + 5, to)) {
        out.push_back(0xE9);
        put32(out, static_cast<std::int32_t>(to - (at + 5)));
    } else {
        jmp_abs(out, to);
    }
}

bool jmp_rel32(std::uint8_t out[5], std::uint64_t at, std::uint64_t to) {
    if (!fits_rel32(at + 5, to)) return false;
    const std::int32_t rel = static_cast<std::int32_t>(to - (at + 5));
    out[0] = 0xE9;
    std::memcpy(out + 1, &rel, 4);
    return true;
}

}  // namespace enc

Result analyze_prologue(const PrologueInput& in, PrologueAnalysis& out) {
    out = PrologueAnalysis{};
    if (in.code == nullptr || in.min_bytes == 0 || in.code_size < in.min_bytes)
        return {Status::InvalidArgument, "prologue snapshot is smaller than the patch size"};
    if (in.function_size != 0 && in.function_size < in.min_bytes) {
        // Only acceptable if the function ends in padding; checked below via the
        // terminator rule, but a function that is shorter than the patch and has
        // no terminator inside it is malformed.
    }

    std::size_t off = 0;
    std::size_t max_size = kEndbrSize;
    std::vector<std::uint64_t> branch_targets;

    while (off < in.min_bytes) {
        x86::Insn insn;
        x86::DecodeError derr = x86::DecodeError::None;
        if (!x86::decode(in.code + off, in.code_size - off, insn, &derr))
            return {Status::DecodeFailed, "cannot decode instruction at +" + std::to_string(off) + " (" +
                                              x86::decode_error_name(derr) + ")"};
        const std::uint64_t addr = in.source + off;
        const std::size_t end = off + insn.length;
        if (in.function_size != 0 && end > in.function_size)
            return {Status::RelocationFailed, "instruction at +" + std::to_string(off) + " crosses the function end"};
        out.boundaries.push_back(off);
        ++out.instruction_count;

        switch (insn.branch) {
            case x86::Branch::LoopRel8:
                return {Status::RelocationFailed, "loop/jrcxz in prologue cannot be relocated"};
            case x86::Branch::XBegin:
                return {Status::RelocationFailed, "xbegin in prologue cannot be relocated"};
            case x86::Branch::JmpRel8:
            case x86::Branch::JmpRel32:
                branch_targets.push_back(insn.branch_target(addr));
                max_size += kAbsJmpSize;
                break;
            case x86::Branch::JccRel8:
            case x86::Branch::JccRel32:
                branch_targets.push_back(insn.branch_target(addr));
                max_size += kMaxJccSize;
                break;
            case x86::Branch::CallRel32:
                max_size += kMaxCallSize;
                break;
            case x86::Branch::None:
                if (insn.rip_relative) {
                    if (insn.addr32)
                        return {Status::RelocationFailed, "EIP-relative (67h) operand at +" + std::to_string(off)};
                    out.rip_targets.push_back(insn.rip_target(addr, in.code + off));
                }
                max_size += insn.length;
                break;
        }
        if (insn.is_call && end < in.min_bytes)
            return {Status::RelocationFailed, "call at +" + std::to_string(off) +
                                                  " returns into the overwritten bytes"};
        off = end;
        if (insn.terminates && off < in.min_bytes) {
            // The function ends before the patch does: the rest must be padding.
            for (std::size_t i = off; i < in.min_bytes;) {
                std::size_t len = 0;
                if (!padding_insn(in.code + i, in.code_size - i, len))
                    return {Status::RelocationFailed,
                            "function is shorter than the patch (" + std::to_string(off) + " bytes) and is not "
                            "followed by int3/nop padding"};
                i += len;
            }
            out.falls_through = false;
            out.stolen = in.min_bytes;  // padding included; nothing after it is ours
            break;
        }
        if (insn.terminates) out.falls_through = false;
        out.stolen = off;
    }

    // Branches from the window back into itself.
    const std::uint64_t win_lo = in.source;
    const std::uint64_t overwrite_hi = in.source + in.min_bytes;
    const std::uint64_t win_hi = in.source + out.stolen;
    for (std::uint64_t t : branch_targets) {
        if (t >= win_lo && t < overwrite_hi)
            return {Status::RelocationFailed, "branch in prologue targets the overwritten bytes (" + hex(t) + ")"};
        if (t >= overwrite_hi && t < win_hi) {
            const std::size_t rel = static_cast<std::size_t>(t - win_lo);
            if (std::find(out.boundaries.begin(), out.boundaries.end(), rel) == out.boundaries.end())
                return {Status::RelocationFailed, "branch in prologue targets the middle of an instruction"};
        }
    }

    if (out.falls_through) max_size += kAbsJmpSize;
    out.max_relocated_size = max_size;
    return Result::ok();
}

Result relocate_prologue(const PrologueInput& in, const PrologueAnalysis& an, std::uint64_t dest,
                         std::vector<std::uint8_t>& out) {
    out.clear();
    out.reserve(an.max_relocated_size);
    {
        x86::Insn first;
        const bool first_is_endbr = x86::decode(in.code, in.code_size, first) && first.is_endbr64;
        if (!first_is_endbr) {
            const std::uint8_t endbr[4] = {0xF3, 0x0F, 0x1E, 0xFA};
            out.insert(out.end(), endbr, endbr + 4);
        }
    }

    for (std::size_t idx = 0; idx < an.boundaries.size(); ++idx) {
        const std::size_t off = an.boundaries[idx];
        x86::Insn insn;
        if (!x86::decode(in.code + off, in.code_size - off, insn))
            return {Status::DecodeFailed, "decode failed during relocation"};
        const std::uint64_t src = in.source + off;
        const std::uint64_t at = dest + out.size();
        const std::uint8_t* bytes = in.code + off;

        switch (insn.branch) {
            case x86::Branch::JmpRel8:
            case x86::Branch::JmpRel32:
                enc::jmp(out, at, insn.branch_target(src));
                break;
            case x86::Branch::JccRel8:
            case x86::Branch::JccRel32: {
                const std::uint64_t target = insn.branch_target(src);
                if (enc::fits_rel32(at + 6, target)) {
                    out.push_back(0x0F);
                    out.push_back(static_cast<std::uint8_t>(0x80 | insn.cond));
                    put32(out, static_cast<std::int32_t>(target - (at + 6)));
                } else {
                    // Inverted short jcc over an absolute jump.
                    out.push_back(static_cast<std::uint8_t>(0x70 | (insn.cond ^ 1)));
                    out.push_back(static_cast<std::uint8_t>(kAbsJmpSize));
                    enc::jmp_abs(out, target);
                }
                break;
            }
            case x86::Branch::CallRel32: {
                const std::uint64_t target = insn.branch_target(src);
                if (enc::fits_rel32(at + 5, target)) {
                    out.push_back(0xE8);
                    put32(out, static_cast<std::int32_t>(target - (at + 5)));
                } else {
                    const std::uint8_t seq[8] = {0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08};
                    out.insert(out.end(), seq, seq + 8);
                    put64(out, target);
                }
                break;
            }
            case x86::Branch::LoopRel8:
            case x86::Branch::XBegin:
                return {Status::RelocationFailed, "unrelocatable branch"};
            case x86::Branch::None: {
                const std::size_t pos = out.size();
                out.insert(out.end(), bytes, bytes + insn.length);
                if (insn.rip_relative) {
                    const std::uint64_t target = insn.rip_target(src, bytes);
                    const std::uint64_t next = at + insn.length;
                    if (!enc::fits_rel32(next, target))
                        return {Status::OutOfRange, "RIP-relative target " + hex(target) +
                                                        " is out of rel32 range from the trampoline"};
                    const std::int32_t disp = static_cast<std::int32_t>(target - next);
                    std::memcpy(out.data() + pos + insn.disp_offset, &disp, 4);
                }
                break;
            }
        }
    }

    if (an.falls_through) enc::jmp(out, dest + out.size(), in.source + an.stolen);
    if (out.size() > an.max_relocated_size)
        return {Status::Internal, "relocated code exceeds its size bound"};
    return Result::ok();
}

}  // namespace vajra
