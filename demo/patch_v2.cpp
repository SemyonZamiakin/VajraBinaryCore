// Vajra demo "arena" - patch module v2.
//
// Applied to a running arena with `vajractl <socket> apply libarena_patch_v2.so`.
// In one transaction it:
//   * migrates every Entity from layout v1 to v2: fields reordered, hp (int32)
//     becomes health (double), positions become double, the id widens to 64
//     bits and a new `shield` field starts at 50;
//   * replaces the four functions that know the layout (tick, spawn, summary)
//     and fixes the damage formula.
// The inverse plan makes the patch revertible (`vajractl <socket> revert p1`);
// reverting drops the shields and truncates health back to an integer.
// SPDX-License-Identifier: MIT
#include <cmath>

#include "arena_abi.hpp"

namespace {

struct EntityV2 {
    EntityV2* target;
    double health;
    double x, y;
    float vx, vy;
    std::uint64_t id;
    std::int32_t level;
    std::int32_t deaths;
    std::int32_t shield;
    std::int32_t pad;
};

vajra::TypeDesc entity_v2() {
    return vajra::describe<EntityV2>(
        "Entity", 2,
        {VAJRA_REF(EntityV2, target, "Entity"), VAJRA_FIELD(EntityV2, health), VAJRA_FIELD(EntityV2, x),
         VAJRA_FIELD(EntityV2, y), VAJRA_FIELD(EntityV2, vx), VAJRA_FIELD(EntityV2, vy), VAJRA_FIELD(EntityV2, id),
         VAJRA_FIELD(EntityV2, level), VAJRA_FIELD(EntityV2, deaths), VAJRA_FIELD(EntityV2, shield),
         VAJRA_FIELD(EntityV2, pad)});
}

constexpr std::int32_t kMaxShield = 50;

void* spawn_v2(vajra::Heap* heap, std::uint32_t id, void* target) {
    auto* e = static_cast<EntityV2*>(heap->allocate("Entity", 2));
    if (!e) return nullptr;
    e->id = id;
    e->health = 100;
    e->x = static_cast<double>((id * 37) % 100);
    e->y = static_cast<double>((id * 61) % 100);
    e->vx = static_cast<float>(static_cast<int>(id % 7) - 3) * 4.0f;
    e->vy = static_cast<float>(static_cast<int>(id % 5) - 2) * 4.0f;
    e->level = 1 + static_cast<std::int32_t>(id % 4);
    e->shield = kMaxShield;
    e->target = static_cast<EntityV2*>(target ? target : e);
    return e;
}

int damage_v2(int level) { return level + 3; }  // the fixed formula

void tick_v2(void* p, std::uint64_t tick) {
    auto* e = static_cast<EntityV2*>(p);
    e->x += e->vx * 0.01;
    e->y += e->vy * 0.01;
    if (e->x < 0 || e->x > 100) e->vx = -e->vx;
    if (e->y < 0 || e->y > 100) e->vy = -e->vy;
    if (tick % 25 == e->id % 25) {
        int dmg = damage_formula(e->level);  // goes through the (patched) host function
        const int absorbed = dmg < e->shield ? dmg : e->shield;
        e->shield -= absorbed;
        dmg -= absorbed;
        e->health -= dmg;
        if (e->health <= 0) {
            e->health = 100;
            ++e->deaths;
        }
    }
    if (tick % 100 == 0 && e->shield < kMaxShield) ++e->shield;
}

void summary_v2(const void* p, vajra::Heap* heap, arena::Summary* s) {
    const auto* e = static_cast<const EntityV2*>(p);
    s->version = 2;
    s->health += e->health;
    s->deaths += e->deaths;
    s->count += 1;
    s->idsum += static_cast<std::int64_t>(e->id);
    if (heap->owns(e->target)) s->refs_ok += 1;
    if (e->id == arena::kSampleId) {
        s->sample_valid = 1;
        s->sample_id = static_cast<std::uint32_t>(e->id);
        s->sample_health = e->health;
        s->sample_x = e->x;
        s->sample_y = e->y;
        s->sample_shield = e->shield;
    }
}

}  // namespace

VAJRA_PATCH_ENTRY {
    if (!ctx->heap) {
        ctx->message = "the agent has no heap";
        return 1;
    }
    vajra::MigrationPlan forward(arena::entity_v1(), entity_v2());
    forward.rename("hp", "health").fill_int("shield", kMaxShield);

    vajra::MigrationPlan inverse(entity_v2(), arena::entity_v1());
    inverse.rename("health", "hp").drop("shield").drop("pad").policy(vajra::ConvertPolicy::Saturate);

    ctx->tx->migrate(*ctx->heap, forward, inverse)
        .hook(&spawn_entity, &spawn_v2)
        .hook(&tick_entity, &tick_v2)
        .hook(&entity_summary, &summary_v2)
        .hook(&damage_formula, &damage_v2);
    ctx->message = "Entity v1 -> v2, 4 functions replaced";
    return 0;
}
