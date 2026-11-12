// Vajra Binary Core - system layer, platform-independent parts.
// SPDX-License-Identifier: MIT
#include <atomic>

#include "sys.hpp"

namespace vajra::sys {

namespace {
std::atomic<int> g_write_fault{0};
}  // namespace

void set_write_fault_countdown(int n) noexcept { g_write_fault.store(n, std::memory_order_relaxed); }

bool take_write_fault() noexcept {
    int v = g_write_fault.load(std::memory_order_relaxed);
    while (v > 0) {
        if (g_write_fault.compare_exchange_weak(v, v - 1, std::memory_order_relaxed)) return v == 1;
    }
    return false;
}

Result range_protection(const std::vector<MapEntry>& maps, std::uintptr_t addr, std::size_t len, int* prot) {
    std::uintptr_t cur = page_floor(addr);
    const std::uintptr_t hi = page_ceil(addr + len);
    int found = -1;
    for (const auto& m : maps) {
        if (m.end <= cur) continue;
        if (m.start > cur) break;  // hole
        if (found >= 0 && m.prot != found)
            return {Status::Unsupported, "range spans mappings with different protections"};
        found = m.prot;
        cur = m.end;
        if (cur >= hi) break;
    }
    if (found < 0 || cur < hi) return {Status::NotFound, "address range is not fully mapped"};
    *prot = found;
    return Result::ok();
}

}  // namespace vajra::sys
