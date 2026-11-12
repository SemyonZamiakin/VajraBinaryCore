// Cross-checks the decoder against GNU objdump on real binaries: every
// instruction objdump decodes must get the same length from Vajra.
//
//   vajra-decode-check <objdump> <file>...
// SPDX-License-Identifier: MIT
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "vajra/x86.hpp"

namespace {

bool parse_line(const std::string& line, std::vector<std::uint8_t>& bytes, std::string& mnemonic) {
    // "  401000:\tf3 0f 1e fa          \tendbr64"
    const std::size_t colon = line.find(":\t");
    if (colon == std::string::npos) return false;
    for (std::size_t i = 0; i < colon; ++i) {
        const char c = line[i];
        if (!(c == ' ' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    const std::size_t tab2 = line.find('\t', colon + 2);
    const std::string hexpart = line.substr(colon + 2, tab2 == std::string::npos ? std::string::npos : tab2 - colon - 2);
    mnemonic = tab2 == std::string::npos ? "" : line.substr(tab2 + 1);
    bytes.clear();
    std::size_t p = 0;
    while (p < hexpart.size()) {
        while (p < hexpart.size() && hexpart[p] == ' ') ++p;
        if (p >= hexpart.size()) break;
        if (p + 2 > hexpart.size()) return false;
        const std::string h = hexpart.substr(p, 2);
        char* end = nullptr;
        const unsigned long v = std::strtoul(h.c_str(), &end, 16);
        if (end != h.c_str() + 2) return false;
        bytes.push_back(static_cast<std::uint8_t>(v));
        p += 2;
    }
    return !bytes.empty();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <objdump> <file>...\n", argv[0]);
        return 2;
    }
    long total = 0, mismatches = 0, skipped = 0;
    std::map<std::string, long> refused;  // decoder refused valid-looking instruction, by mnemonic
    for (int f = 2; f < argc; ++f) {
        const std::string cmd = std::string(argv[1]) + " -d -w --insn-width=16 '" + argv[f] + "' 2>/dev/null";
        FILE* p = ::popen(cmd.c_str(), "r");
        if (!p) {
            std::fprintf(stderr, "cannot run %s\n", cmd.c_str());
            return 2;
        }
        char buf[4096];
        long file_total = 0;
        while (std::fgets(buf, sizeof buf, p)) {
            std::string line(buf);
            if (!line.empty() && line.back() == '\n') line.pop_back();
            std::vector<std::uint8_t> bytes;
            std::string mn;
            if (!parse_line(line, bytes, mn)) continue;
            static const char* kBarePrefixes[] = {"lock", "cs", "ds", "es", "fs", "gs", "ss", "data16", "addr32", "repnz", "repz", "rep", "udb", "bnd", "notrack"};
            bool bare = false;  // a lone prefix byte objdump shows before data/padding
            for (const char* bp : kBarePrefixes) bare = bare || mn == bp;
            if (bare || mn.find("(bad)") != std::string::npos || mn.empty() || mn.rfind("rex", 0) == 0 ||
                mn.find(".byte") != std::string::npos) {
                ++skipped;
                continue;
            }
            ++total;
            ++file_total;
            vajra::x86::Insn insn;
            vajra::x86::DecodeError err;
            const bool ok = vajra::x86::decode(bytes.data(), bytes.size(), insn, &err);
            if (!ok) {
                const std::string word = mn.substr(0, mn.find_first_of(" \t"));
                if (err == vajra::x86::DecodeError::Unsupported) {
                    ++refused[word];  // deliberate refusal, not a length bug
                    continue;
                }
                if (mismatches < 30) std::fprintf(stderr, "decode failed (%s): %s\n", vajra::x86::decode_error_name(err), line.c_str());
                ++mismatches;
            } else if (insn.length == 1 && bytes[0] == 0x9B && bytes.size() > 1) {
                // objdump prints WAIT (9B) fused with the following x87 instruction
                // (fstcw = wait; fnstcw). Architecturally they are two instructions.
                vajra::x86::Insn rest;
                if (!vajra::x86::decode(bytes.data() + 1, bytes.size() - 1, rest) || rest.length != bytes.size() - 1) {
                    if (mismatches < 30) std::fprintf(stderr, "fwait pair mismatch: %s\n", line.c_str());
                    ++mismatches;
                }
            } else if (insn.length != bytes.size()) {
                if (mismatches < 30)
                    std::fprintf(stderr, "length %u vs objdump %zu: %s\n", insn.length, bytes.size(), line.c_str());
                ++mismatches;
            }
        }
        ::pclose(p);
        std::printf("%-60s %9ld instructions\n", argv[f], file_total);
    }
    long refused_total = 0;
    for (const auto& [w, n] : refused) refused_total += n;
    std::printf("total %ld instructions, %ld mismatches, %ld refused as unsupported, %ld skipped (bad/data)\n", total,
                mismatches, refused_total, skipped);
    for (const auto& [w, n] : refused) std::printf("  refused: %-16s %ld\n", w.c_str(), n);
    if (total == 0) return 2;
    return mismatches == 0 ? 0 : 1;
}
