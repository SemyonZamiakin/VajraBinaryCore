// Patch module used by test_agent: replaces agent_target() in the host and
// migrates the host's "Counter" objects from v1 to v2 (revertible). Host
// functions are found by name, which works for .so and .dll modules alike.
// SPDX-License-Identifier: MIT
#include <cstdint>

#include "vajra/vajra.hpp"

namespace {
struct CounterV1 {
    std::int32_t value;
};
struct CounterV2 {
    std::int64_t value;
    std::int64_t generation;
};
int patched_target(int x) { return x * 1000; }
}  // namespace

VAJRA_PATCH_ENTRY {
    if (ctx->heap == nullptr) {
        ctx->message = "no heap";
        return 1;
    }
    void* target = vajra::find_function("agent_target");
    if (!target) {
        ctx->message = "agent_target not found in the host";
        return 2;
    }
    const auto v1 = vajra::describe<CounterV1>("Counter", 1, {VAJRA_FIELD(CounterV1, value)});
    const auto v2 = vajra::describe<CounterV2>("Counter", 2,
                                               {VAJRA_FIELD(CounterV2, value), VAJRA_FIELD(CounterV2, generation)});
    vajra::MigrationPlan fwd(v1, v2);
    fwd.fill_int("generation", 2);
    vajra::MigrationPlan inv(v2, v1);
    inv.drop("generation");
    ctx->tx->hook(target, reinterpret_cast<void*>(&patched_target)).migrate(*ctx->heap, fwd, inv);
    ctx->message = "counter-v2";
    return 0;
}
