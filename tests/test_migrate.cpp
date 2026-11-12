// Type migration: descriptor validation, plan compilation, value conversion
// rules, pointer fix-ups (refs, roots, interior pointers, cross-type refs),
// failure atomicity and inverse migrations.
// SPDX-License-Identifier: MIT
#include <cmath>
#include <cstring>
#include <limits>
#include <map>

#include "check.hpp"
#include "vajra/vajra.hpp"

using namespace vajra;

namespace {

// ---------------------------------------------------------------- types
struct EntityV1 {
    std::uint32_t id;
    std::int32_t hp;
    float x, y;
    EntityV1* target;
    char name[8];
};
struct EntityV2 {  // fields reordered, hp -> double health, new shield, wider name, positions as double
    EntityV2* target;
    double health;
    double x, y;
    std::uint64_t id;
    std::int16_t shield;
    char name[16];
};
const TypeDesc kV1 = describe<EntityV1>("Entity", 1,
                                        {VAJRA_FIELD(EntityV1, id), VAJRA_FIELD(EntityV1, hp), VAJRA_FIELD(EntityV1, x),
                                         VAJRA_FIELD(EntityV1, y), VAJRA_REF(EntityV1, target, "Entity"),
                                         VAJRA_FIELD(EntityV1, name)});
const TypeDesc kV2 = describe<EntityV2>("Entity", 2,
                                        {VAJRA_REF(EntityV2, target, "Entity"), VAJRA_FIELD(EntityV2, health),
                                         VAJRA_FIELD(EntityV2, x), VAJRA_FIELD(EntityV2, y), VAJRA_FIELD(EntityV2, id),
                                         VAJRA_FIELD(EntityV2, shield), VAJRA_FIELD(EntityV2, name)});

struct Team {  // a different type that references entities
    EntityV1* leader;
    std::int32_t score;
    std::int32_t pad;
};
const TypeDesc kTeam = describe<Team>("Team", 1, {VAJRA_REF(Team, leader, "Entity"), VAJRA_FIELD(Team, score),
                                                  VAJRA_FIELD(Team, pad)});

MigrationPlan forward_plan() {
    MigrationPlan p(kV1, kV2);
    p.rename("hp", "health").fill_int("shield", 25);
    return p;
}
MigrationPlan inverse_plan() {
    MigrationPlan p(kV2, kV1);
    p.rename("health", "hp").drop("shield");
    return p;
}

// Helpers for single-field conversion checks.
template <class Src, class Dst>
Result convert_one(Src v, Dst& out, ConvertPolicy pol) {
    struct S { Src v; };
    struct D { Dst v; };
    const TypeDesc ts = describe<S>("T", 1, {VAJRA_FIELD(S, v)});
    const TypeDesc td = describe<D>("T", 2, {VAJRA_FIELD(D, v)});
    MigrationPlan p(ts, td);
    p.policy(pol);
    if (Result r = p.compile(); !r) return r;
    S s{v};
    D d{};
    Result r = p.convert_object(&s, &d, 0);
    out = d.v;
    return r;
}

}  // namespace

TEST(type_validation) {
    CHECK_OK(kV1.validate());
    CHECK_OK(kV2.validate());
    TypeDesc t = kV1;
    t.fields[1].offset = 2;  // overlaps id
    CHECK_STATUS(t.validate(), Status::InvalidArgument);
    t = kV1;
    t.fields[0].offset = t.size;  // out of bounds
    CHECK_STATUS(t.validate(), Status::InvalidArgument);
    t = kV1;
    t.fields[1].name = "id";
    CHECK_STATUS(t.validate(), Status::InvalidArgument);
    t = kV1;
    t.version = 0;
    CHECK_STATUS(t.validate(), Status::InvalidArgument);
    t = kV1;
    t.fields[4].ref_type.clear();
    CHECK_STATUS(t.validate(), Status::InvalidArgument);
    t = kV1;
    t.fields[0].size = 2;  // u32 kind with size 2
    CHECK_STATUS(t.validate(), Status::InvalidArgument);
    CHECK(kV1.field("name")->kind == FieldKind::Bytes);
    CHECK(kV1.field("x")->kind == FieldKind::F32);
    CHECK(kV1.field("target")->kind == FieldKind::Ref);
}

TEST(plan_compile_errors) {
    CHECK_OK(forward_plan().compile());
    CHECK_OK(inverse_plan().compile());
    // hp has no destination without the rename
    CHECK_STATUS(MigrationPlan(kV1, kV2).compile(), Status::InvalidArgument);
    CHECK_STATUS(MigrationPlan(kV1, kV2).rename("hp", "nope").compile(), Status::InvalidArgument);
    CHECK_STATUS(MigrationPlan(kV1, kV2).rename("nope", "health").compile(), Status::InvalidArgument);
    CHECK_STATUS(MigrationPlan(kV1, kV2).rename("hp", "health").rename("id", "health").compile(),
                 Status::InvalidArgument);
    CHECK_STATUS(MigrationPlan(kV1, kV2).rename("hp", "health").fill_int("health", 1).compile(),
                 Status::InvalidArgument);
    CHECK_STATUS(MigrationPlan(kV1, kV2).rename("hp", "health").drop("hp").compile(), Status::InvalidArgument);
    CHECK_STATUS(MigrationPlan(kV1, kV1).compile(), Status::InvalidArgument);  // same version
    CHECK_STATUS(MigrationPlan(kV1, kTeam).compile(), Status::InvalidArgument);  // different type name
    // kind incompatibility: Ref -> number
    TypeDesc bad = kV2;
    bad.fields[0].kind = FieldKind::U64;
    bad.fields[0].ref_type.clear();
    CHECK_STATUS(MigrationPlan(kV1, bad).rename("hp", "health").compile(), Status::InvalidArgument);
    // fill value that does not fit
    CHECK_STATUS(MigrationPlan(kV1, kV2).rename("hp", "health").fill_int("shield", 70000).compile(),
                 Status::InvalidArgument);
}

TEST(strict_integer_conversions) {
    std::int16_t i16 = 0;
    CHECK_OK((convert_one<std::int32_t, std::int16_t>(-32768, i16, ConvertPolicy::Strict)));
    CHECK_EQ(i16, -32768);
    CHECK_STATUS((convert_one<std::int32_t, std::int16_t>(40000, i16, ConvertPolicy::Strict)), Status::MigrationFailed);
    std::uint32_t u32 = 0;
    CHECK_STATUS((convert_one<std::int32_t, std::uint32_t>(-1, u32, ConvertPolicy::Strict)), Status::MigrationFailed);
    std::int64_t i64 = 0;
    CHECK_STATUS((convert_one<std::uint64_t, std::int64_t>(UINT64_MAX, i64, ConvertPolicy::Strict)),
                 Status::MigrationFailed);
    CHECK_OK((convert_one<std::uint64_t, std::int64_t>(INT64_MAX, i64, ConvertPolicy::Strict)));
    CHECK_EQ(i64, INT64_MAX);
    bool b = false;
    CHECK_OK((convert_one<std::int32_t, bool>(1, b, ConvertPolicy::Strict)));
    CHECK(b);
    CHECK_STATUS((convert_one<std::int32_t, bool>(2, b, ConvertPolicy::Strict)), Status::MigrationFailed);
}

TEST(strict_float_conversions) {
    double d = 0;
    CHECK_OK((convert_one<std::int64_t, double>(1ll << 53, d, ConvertPolicy::Strict)));
    CHECK_STATUS((convert_one<std::int64_t, double>((1ll << 53) + 1, d, ConvertPolicy::Strict)), Status::MigrationFailed);
    CHECK_STATUS((convert_one<std::int64_t, double>(INT64_MAX, d, ConvertPolicy::Strict)), Status::MigrationFailed);
    CHECK_OK((convert_one<std::int64_t, double>(INT64_MIN, d, ConvertPolicy::Strict)));  // -2^63 is exact
    std::int32_t i = 0;
    CHECK_OK((convert_one<double, std::int32_t>(3.0, i, ConvertPolicy::Strict)));
    CHECK_EQ(i, 3);
    CHECK_STATUS((convert_one<double, std::int32_t>(3.5, i, ConvertPolicy::Strict)), Status::MigrationFailed);
    CHECK_STATUS((convert_one<double, std::int32_t>(std::nan(""), i, ConvertPolicy::Strict)), Status::MigrationFailed);
    CHECK_STATUS((convert_one<double, std::int32_t>(2147483648.0, i, ConvertPolicy::Strict)), Status::MigrationFailed);
    CHECK_OK((convert_one<double, std::int32_t>(-2147483648.0, i, ConvertPolicy::Strict)));
    std::int64_t l = 0;
    CHECK_STATUS((convert_one<double, std::int64_t>(9223372036854775808.0, l, ConvertPolicy::Strict)),
                 Status::MigrationFailed);
    std::uint64_t u = 0;
    CHECK_STATUS((convert_one<double, std::uint64_t>(-0.5, u, ConvertPolicy::Strict)), Status::MigrationFailed);
    CHECK_OK((convert_one<double, std::uint64_t>(-0.0, u, ConvertPolicy::Strict)));
    float f = 0;
    CHECK_OK((convert_one<double, float>(0.1, f, ConvertPolicy::Strict)));  // rounding allowed
    CHECK(f == 0.1f);
    CHECK_STATUS((convert_one<double, float>(1e300, f, ConvertPolicy::Strict)), Status::MigrationFailed);
    CHECK_OK((convert_one<double, float>(std::numeric_limits<double>::infinity(), f, ConvertPolicy::Strict)));
    CHECK(std::isinf(f));
    CHECK_OK((convert_one<std::int32_t, float>(16777216, f, ConvertPolicy::Strict)));
    CHECK_STATUS((convert_one<std::int32_t, float>(16777217, f, ConvertPolicy::Strict)), Status::MigrationFailed);
}

TEST(saturating_conversions) {
    std::int8_t i8 = 0;
    CHECK_OK((convert_one<std::int32_t, std::int8_t>(1000, i8, ConvertPolicy::Saturate)));
    CHECK_EQ(i8, 127);
    CHECK_OK((convert_one<std::int32_t, std::int8_t>(-1000, i8, ConvertPolicy::Saturate)));
    CHECK_EQ(i8, -128);
    std::uint16_t u16 = 0;
    CHECK_OK((convert_one<std::int32_t, std::uint16_t>(-5, u16, ConvertPolicy::Saturate)));
    CHECK_EQ(u16, 0);
    std::int32_t i = 0;
    CHECK_OK((convert_one<double, std::int32_t>(std::nan(""), i, ConvertPolicy::Saturate)));
    CHECK_EQ(i, 0);
    CHECK_OK((convert_one<double, std::int32_t>(-3.9, i, ConvertPolicy::Saturate)));
    CHECK_EQ(i, -3);
    CHECK_OK((convert_one<double, std::int32_t>(std::numeric_limits<double>::infinity(), i, ConvertPolicy::Saturate)));
    CHECK_EQ(i, INT32_MAX);
    std::uint64_t u = 0;
    CHECK_OK((convert_one<double, std::uint64_t>(1e30, u, ConvertPolicy::Saturate)));
    CHECK_EQ(u, UINT64_MAX);
    float f = 0;
    CHECK_OK((convert_one<double, float>(-1e300, f, ConvertPolicy::Saturate)));
    CHECK(f == -std::numeric_limits<float>::max());
    bool b = false;
    CHECK_OK((convert_one<std::int32_t, bool>(42, b, ConvertPolicy::Saturate)));
    CHECK(b);
}

TEST(bytes_fields) {
    struct S8 { char s[8]; };
    struct S16 { char s[16]; };
    struct S4 { char s[4]; };
    const TypeDesc t8 = describe<S8>("B", 1, {VAJRA_FIELD(S8, s)});
    const TypeDesc t16 = describe<S16>("B", 2, {VAJRA_FIELD(S16, s)});
    const TypeDesc t4 = describe<S4>("B", 3, {VAJRA_FIELD(S4, s)});
    MigrationPlan grow(t8, t16);
    CHECK_OK(grow.compile());
    S8 a{};
    std::memcpy(a.s, "abcdefgh", 8);
    S16 b{};  // convert_object expects a zeroed destination
    CHECK_OK(grow.convert_object(&a, &b, 0));
    CHECK(std::memcmp(b.s, "abcdefgh\0\0\0\0\0\0\0\0", 16) == 0);
    MigrationPlan shrink(t8, t4);
    CHECK_OK(shrink.compile());
    S4 c{};
    CHECK_STATUS(shrink.convert_object(&a, &c, 0), Status::MigrationFailed);  // would lose "efgh"
    S8 z{};
    std::memcpy(z.s, "ab\0\0\0\0\0\0", 8);
    CHECK_OK(shrink.convert_object(&z, &c, 0));
    shrink.policy(ConvertPolicy::Saturate);
    CHECK_OK(shrink.compile());
    CHECK_OK(shrink.convert_object(&a, &c, 0));
    CHECK(std::memcmp(c.s, "abcd", 4) == 0);
}

TEST(object_view_access) {
    EntityV1 e{};
    e.id = 7;
    e.hp = -3;
    e.x = 1.5f;
    MigrationContext ctx;
    ObjectView v(kV1, &e, &ctx);
    CHECK_EQ(v.get_int("id"), 7);
    CHECK_EQ(v.get_int("hp"), -3);
    CHECK(v.get_double("x") == 1.5);
    CHECK(!ctx.failed());
    v.get_uint("hp");  // -3 is not representable as unsigned
    CHECK(ctx.failed());
    MigrationContext ctx2;
    ObjectView w(kV1, &e, &ctx2);
    w.set_int("hp", 100);
    CHECK_EQ(e.hp, 100);
    w.set_double("x", 2.25);
    CHECK(e.x == 2.25f);
    w.set_int("hp", 1ll << 40);  // does not fit i32
    CHECK(ctx2.failed());
    MigrationContext ctx3;
    ObjectView u(kV1, &e, &ctx3);
    u.get_int("missing");
    CHECK(ctx3.failed());
    MigrationContext ctx4;
    ObjectView n(kV1, &e, &ctx4);
    n.set_bytes("name", "hello world", 11);
    CHECK(std::memcmp(e.name, "hello wo", 8) == 0);
    CHECK(!ctx4.failed());
}

namespace {

struct World {
    Heap heap;
    std::vector<EntityV1*> entities;
    void* roots[8] = {};
    void* interior = nullptr;  // points at entities[2]->y
    Team* team = nullptr;

    explicit World(int requested) {
        const int n = requested < 8 ? 8 : requested;  // the fixture uses indexes up to 7
        heap.register_type(kV1);
        heap.register_type(kTeam);
        for (int i = 0; i < n; ++i) {
            auto* e = static_cast<EntityV1*>(heap.allocate("Entity", 1));
            e->id = static_cast<std::uint32_t>(1000 + i);
            e->hp = 100 - i;
            e->x = static_cast<float>(i) * 0.5f;
            e->y = static_cast<float>(-i);
            std::snprintf(e->name, sizeof e->name, "e%u", static_cast<unsigned>(i % 1000));
            entities.push_back(e);
        }
        for (int i = 0; i < n; ++i) entities[static_cast<std::size_t>(i)]->target = entities[static_cast<std::size_t>((i + 1) % n)];
        entities[3]->target = nullptr;
        for (int i = 0; i < 8 && i < n; ++i) roots[i] = entities[static_cast<std::size_t>(i)];
        heap.add_root_range(roots, 8);
        interior = &entities[2]->y;
        heap.add_root(&interior);
        team = static_cast<Team*>(heap.allocate("Team", 1));
        team->leader = entities[5];
        team->score = 42;
    }
};

}  // namespace

TEST(end_to_end_migration_and_inverse) {
    World w(10);
    std::map<std::uint32_t, EntityV1> snapshot;
    for (auto* e : w.entities) snapshot[e->id] = *e;

    Patch p;
    CHECK_OK(Transaction().migrate(w.heap, forward_plan(), inverse_plan()).commit(&p));
    CHECK_EQ(w.heap.version("Entity"), 2u);
    CHECK_EQ(w.heap.count("Entity"), 10u);
    CHECK(w.heap.allocate("Entity", 1) == nullptr);

    // Roots now point to v2 objects with converted values.
    for (int i = 0; i < 8; ++i) {
        auto* e = static_cast<EntityV2*>(w.roots[i]);
        CHECK(w.heap.owns(e));
        const EntityV1& old = snapshot[static_cast<std::uint32_t>(1000 + i)];
        CHECK_EQ(e->id, static_cast<std::uint64_t>(old.id));
        CHECK(e->health == static_cast<double>(old.hp));
        CHECK(e->x == static_cast<double>(old.x));
        CHECK(e->y == static_cast<double>(old.y));
        CHECK_EQ(e->shield, 25);
        CHECK(std::strcmp(e->name, old.name) == 0);
    }
    // The reference graph is preserved.
    for (int i = 0; i < 8; ++i) {
        auto* e = static_cast<EntityV2*>(w.roots[i]);
        if (i == 3) {
            CHECK(e->target == nullptr);
        } else if (i + 1 < 8) {
            CHECK(e->target == static_cast<EntityV2*>(w.roots[i + 1]));
        }
    }
    // Interior root follows its field to the new offset.
    CHECK(w.interior == &static_cast<EntityV2*>(w.roots[2])->y);
    // Cross-type reference fixed.
    auto* leader = reinterpret_cast<EntityV2*>(w.team->leader);
    CHECK(w.heap.owns(leader));
    CHECK_EQ(leader->id, 1005u);

    // Modify in v2, then revert to v1.
    static_cast<EntityV2*>(w.roots[0])->health = 55;
    CHECK_OK(p.revert());
    CHECK_EQ(w.heap.version("Entity"), 1u);
    auto* e0 = static_cast<EntityV1*>(w.roots[0]);
    CHECK_EQ(e0->hp, 55);
    CHECK_EQ(e0->id, 1000u);
    CHECK(e0->target == static_cast<EntityV1*>(w.roots[1]));
    CHECK(w.interior == &static_cast<EntityV1*>(w.roots[2])->y);
    CHECK_EQ(w.team->leader->id, 1005u);
    CHECK(w.heap.allocate("Entity", 1) != nullptr);
}

TEST(failure_changes_nothing) {
    World w(200);
    w.entities[150]->hp = 0;
    auto plan = forward_plan();
    plan.transform([](const ObjectView& from, ObjectView& to, MigrationContext& ctx) {
        if (from.get_int("hp") == 0) {
            ctx.fail("entity with hp 0");
            return false;
        }
        to.set_int("shield", from.get_int("hp") / 10);
        return true;
    });
    void* roots_before[8];
    std::memcpy(roots_before, w.roots, sizeof roots_before);
    const void* interior_before = w.interior;
    const Result r = Transaction().migrate(w.heap, plan).commit();
    CHECK_STATUS(r, Status::MigrationFailed);
    CHECK(r.message().find("hp 0") != std::string::npos);
    CHECK(std::memcmp(roots_before, w.roots, sizeof roots_before) == 0);
    CHECK(interior_before == w.interior);
    CHECK_EQ(w.heap.version("Entity"), 1u);
    CHECK(w.team->leader == w.entities[5]);
    for (std::size_t i = 0; i < w.entities.size(); ++i) {
        CHECK(w.heap.owns(w.entities[i]));
        CHECK_EQ(w.entities[i]->id, static_cast<std::uint32_t>(1000 + i));
    }
}

TEST(conversion_failure_names_the_object) {
    World w(5);
    MigrationPlan p(kV1, kV2);
    p.rename("hp", "shield").fill_double("health", 1.0);  // i32 -> i16
    w.entities[4]->hp = 40000;
    const Result r = Transaction().migrate(w.heap, p).commit();
    CHECK_STATUS(r, Status::MigrationFailed);
    CHECK(r.message().find("object #") != std::string::npos);  // index in heap order
    CHECK(r.message().find("40000") != std::string::npos);
    CHECK(r.message().find("'hp' -> 'shield'") != std::string::npos);
    w.entities[4]->hp = 4;
    CHECK_OK(Transaction().migrate(w.heap, p).commit());
    CHECK_EQ(static_cast<EntityV2*>(w.roots[4])->shield, 4);
    CHECK(static_cast<EntityV2*>(w.roots[4])->health == 1.0);
}

TEST(dangling_reference_is_refused) {
    World w(4);
    EntityV1 outside{};
    w.entities[1]->target = &outside;  // not a heap object
    CHECK_STATUS(Transaction().migrate(w.heap, forward_plan()).commit(), Status::MigrationFailed);
    CHECK_EQ(w.heap.version("Entity"), 1u);
}

TEST(interior_pointer_to_dropped_field_is_refused) {
    World w(4);
    MigrationPlan p(kV1, kV2);
    p.rename("hp", "health");
    p.drop("y");  // the interior root points at y
    CHECK_STATUS(Transaction().migrate(w.heap, p).commit(), Status::MigrationFailed);
    CHECK_EQ(w.heap.version("Entity"), 1u);
}

TEST(version_mismatch) {
    World w(2);
    CHECK_STATUS(Transaction().migrate(w.heap, inverse_plan()).commit(), Status::VersionMismatch);
    Heap empty;
    CHECK_STATUS(Transaction().migrate(empty, forward_plan()).commit(), Status::NotFound);
}

TEST(transform_computes_new_fields) {
    World w(3);
    auto plan = forward_plan();
    plan.transform([](const ObjectView& from, ObjectView& to, MigrationContext&) {
        to.set_int("shield", from.get_int("hp") * 2);
        return true;
    });
    CHECK_OK(Transaction().migrate(w.heap, plan).commit());
    CHECK_EQ(static_cast<EntityV2*>(w.roots[0])->shield, 200);
    CHECK_EQ(static_cast<EntityV2*>(w.roots[2])->shield, 196);
}

TEST(quarantine_keeps_old_objects) {
    World w(4);
    w.heap.set_quarantine(true);
    EntityV1* old0 = w.entities[0];
    CHECK_OK(Transaction().migrate(w.heap, forward_plan()).commit());
    CHECK_EQ(w.heap.quarantined(), w.entities.size());
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(old0);
    CHECK_EQ(bytes[0], 0xDD);
    CHECK(!w.heap.owns(old0));
    w.heap.release_quarantine();
    CHECK_EQ(w.heap.quarantined(), 0u);
}

TEST(heap_basics) {
    Heap h;
    CHECK_OK(h.register_type(kV1));
    CHECK_STATUS(h.register_type(kV1), Status::AlreadyApplied);
    CHECK(h.allocate("Entity", 2) == nullptr);
    CHECK(h.allocate("Nope", 1) == nullptr);
    void* a = h.allocate("Entity", 1);
    CHECK(a != nullptr);
    CHECK(reinterpret_cast<std::uintptr_t>(a) % alignof(EntityV1) == 0);
    CHECK(h.owns(a));
    CHECK_EQ(h.count("Entity"), 1u);
    int n = 0;
    h.for_each("Entity", [&](void*) { ++n; });
    CHECK_EQ(n, 1);
    CHECK(h.deallocate(a));
    CHECK(!h.deallocate(a));
    CHECK_EQ(h.count("Entity"), 0u);
    void* r = nullptr;
    h.add_root(&r);
    CHECK(h.remove_root(&r));
    CHECK(!h.remove_root(&r));
}

TEST_MAIN()
