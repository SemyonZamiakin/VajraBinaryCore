// Vajra demo "arena": types and functions shared by the host program and its
// patch modules.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>

#include "vajra/vajra.hpp"

namespace arena {

// Layout of an entity in the shipped (v1) build.
struct EntityV1 {
    std::uint32_t id;
    std::int32_t hp;
    float x, y;
    float vx, vy;
    std::int32_t level;
    std::int32_t deaths;
    EntityV1* target;  // another entity; fixed up when entities move in memory
};

inline vajra::TypeDesc entity_v1() {
    return vajra::describe<EntityV1>(
        "Entity", 1,
        {VAJRA_FIELD(EntityV1, id), VAJRA_FIELD(EntityV1, hp), VAJRA_FIELD(EntityV1, x), VAJRA_FIELD(EntityV1, y),
         VAJRA_FIELD(EntityV1, vx), VAJRA_FIELD(EntityV1, vy), VAJRA_FIELD(EntityV1, level),
         VAJRA_FIELD(EntityV1, deaths), VAJRA_REF(EntityV1, target, "Entity")});
}

// Per-worker statistics, filled by entity_summary() (a patchable function).
struct Summary {
    double health = 0;
    std::int64_t deaths = 0;
    std::int64_t count = 0;
    std::int64_t refs_ok = 0;   // entities whose target is a live heap object
    std::int64_t idsum = 0;
    std::int32_t version = 0;   // layout version the summarising code understands
    std::int32_t sample_valid = 0;
    std::uint32_t sample_id = 0;
    std::int32_t sample_shield = -1;
    double sample_health = 0, sample_x = 0, sample_y = 0;
};

constexpr std::uint32_t kSampleId = 7;

}  // namespace arena

// The host exports its hot-patch targets (spawn_entity, tick_entity,
// damage_formula, entity_summary) by name; patch modules find them with
// vajra::find_function() or Transaction::hook("name", ...).
