// Vajra Binary Core - live type migration.
// SPDX-License-Identifier: MIT
#include "vajra/migrate.hpp"

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdlib>
#if defined(_WIN32)
#include <malloc.h>
#endif
#include <cstring>
#include <limits>
#include <set>

#include "migrate_job.hpp"

namespace vajra {

namespace {

// ------------------------------------------------------------ scalar conversion

struct Scalar {
    enum class Tag { Signed, Unsigned, Float, Bool, Pointer } tag = Tag::Signed;
    std::int64_t i = 0;
    std::uint64_t u = 0;
    double f = 0;
    bool b = false;
    std::uintptr_t p = 0;
};

template <class T>
T load(const std::uint8_t* p) {
    T v;
    std::memcpy(&v, p, sizeof v);
    return v;
}

template <class T>
void store(std::uint8_t* p, T v) {
    std::memcpy(p, &v, sizeof v);
}

Scalar read_scalar(FieldKind k, const std::uint8_t* p) {
    Scalar s;
    switch (k) {
        case FieldKind::I8: s.tag = Scalar::Tag::Signed; s.i = load<std::int8_t>(p); break;
        case FieldKind::I16: s.tag = Scalar::Tag::Signed; s.i = load<std::int16_t>(p); break;
        case FieldKind::I32: s.tag = Scalar::Tag::Signed; s.i = load<std::int32_t>(p); break;
        case FieldKind::I64: s.tag = Scalar::Tag::Signed; s.i = load<std::int64_t>(p); break;
        case FieldKind::U8: s.tag = Scalar::Tag::Unsigned; s.u = load<std::uint8_t>(p); break;
        case FieldKind::U16: s.tag = Scalar::Tag::Unsigned; s.u = load<std::uint16_t>(p); break;
        case FieldKind::U32: s.tag = Scalar::Tag::Unsigned; s.u = load<std::uint32_t>(p); break;
        case FieldKind::U64: s.tag = Scalar::Tag::Unsigned; s.u = load<std::uint64_t>(p); break;
        case FieldKind::F32: s.tag = Scalar::Tag::Float; s.f = static_cast<double>(load<float>(p)); break;
        case FieldKind::F64: s.tag = Scalar::Tag::Float; s.f = load<double>(p); break;
        case FieldKind::Bool: s.tag = Scalar::Tag::Bool; s.b = load<std::uint8_t>(p) != 0; break;
        case FieldKind::Ptr:
        case FieldKind::Ref: s.tag = Scalar::Tag::Pointer; s.p = load<std::uintptr_t>(p); break;
        case FieldKind::Bytes: break;
    }
    return s;
}

std::string scalar_text(const Scalar& s) {
    switch (s.tag) {
        case Scalar::Tag::Signed: return std::to_string(s.i);
        case Scalar::Tag::Unsigned: return std::to_string(s.u);
        case Scalar::Tag::Float: {
            char buf[64];
            std::snprintf(buf, sizeof buf, "%.17g", s.f);
            return buf;
        }
        case Scalar::Tag::Bool: return s.b ? "true" : "false";
        case Scalar::Tag::Pointer: return "pointer";
    }
    return "?";
}

bool is_signed_kind(FieldKind k) {
    return k == FieldKind::I8 || k == FieldKind::I16 || k == FieldKind::I32 || k == FieldKind::I64;
}
bool is_unsigned_kind(FieldKind k) {
    return k == FieldKind::U8 || k == FieldKind::U16 || k == FieldKind::U32 || k == FieldKind::U64;
}

std::int64_t signed_min(FieldKind k) {
    switch (k) {
        case FieldKind::I8: return INT8_MIN;
        case FieldKind::I16: return INT16_MIN;
        case FieldKind::I32: return INT32_MIN;
        default: return INT64_MIN;
    }
}
std::int64_t signed_max(FieldKind k) {
    switch (k) {
        case FieldKind::I8: return INT8_MAX;
        case FieldKind::I16: return INT16_MAX;
        case FieldKind::I32: return INT32_MAX;
        default: return INT64_MAX;
    }
}
std::uint64_t unsigned_max(FieldKind k) {
    switch (k) {
        case FieldKind::U8: return UINT8_MAX;
        case FieldKind::U16: return UINT16_MAX;
        case FieldKind::U32: return UINT32_MAX;
        default: return UINT64_MAX;
    }
}

void store_signed(FieldKind k, std::uint8_t* p, std::int64_t v) {
    switch (k) {
        case FieldKind::I8: store(p, static_cast<std::int8_t>(v)); break;
        case FieldKind::I16: store(p, static_cast<std::int16_t>(v)); break;
        case FieldKind::I32: store(p, static_cast<std::int32_t>(v)); break;
        default: store(p, v); break;
    }
}
void store_unsigned(FieldKind k, std::uint8_t* p, std::uint64_t v) {
    switch (k) {
        case FieldKind::U8: store(p, static_cast<std::uint8_t>(v)); break;
        case FieldKind::U16: store(p, static_cast<std::uint16_t>(v)); break;
        case FieldKind::U32: store(p, static_cast<std::uint32_t>(v)); break;
        default: store(p, v); break;
    }
}

constexpr double kTwo63 = 9223372036854775808.0;
constexpr double kTwo64 = 18446744073709551616.0;

// Exactly representable as double/float? (int64 / uint64 source)
bool exact_in_double(std::int64_t v, bool as_float) {
    const double d = as_float ? static_cast<double>(static_cast<float>(v)) : static_cast<double>(v);
    if (d >= kTwo63 || d < -kTwo63) return false;
    return static_cast<std::int64_t>(d) == v;
}
bool exact_in_double_u(std::uint64_t v, bool as_float) {
    const double d = as_float ? static_cast<double>(static_cast<float>(v)) : static_cast<double>(v);
    if (d >= kTwo64) return false;
    return static_cast<std::uint64_t>(d) == v;
}

// Writes `v` into a field of kind `k` at `p`. Returns an empty string on
// success, otherwise the reason.
std::string write_scalar(const Scalar& v, FieldKind k, std::uint8_t* p, ConvertPolicy pol) {
    const bool strict = pol == ConvertPolicy::Strict;
    if (k == FieldKind::Ptr || k == FieldKind::Ref) {
        if (v.tag != Scalar::Tag::Pointer) return "cannot store a number in a pointer field";
        store(p, v.p);
        return {};
    }
    if (v.tag == Scalar::Tag::Pointer) return "cannot store a pointer in a numeric field";

    if (is_signed_kind(k) || is_unsigned_kind(k)) {
        const bool dst_signed = is_signed_kind(k);
        const std::int64_t lo = dst_signed ? signed_min(k) : 0;
        const std::int64_t hi_s = dst_signed ? signed_max(k) : 0;
        const std::uint64_t hi_u = dst_signed ? static_cast<std::uint64_t>(hi_s) : unsigned_max(k);
        switch (v.tag) {
            case Scalar::Tag::Bool:
                if (dst_signed) store_signed(k, p, v.b ? 1 : 0);
                else store_unsigned(k, p, v.b ? 1u : 0u);
                return {};
            case Scalar::Tag::Signed:
                if (dst_signed) {
                    if (v.i < lo || v.i > hi_s) {
                        if (strict) return "value " + scalar_text(v) + " is out of range for " + field_kind_name(k);
                        store_signed(k, p, v.i < lo ? lo : hi_s);
                    } else {
                        store_signed(k, p, v.i);
                    }
                } else {
                    if (v.i < 0 || static_cast<std::uint64_t>(v.i) > hi_u) {
                        if (strict) return "value " + scalar_text(v) + " is out of range for " + field_kind_name(k);
                        store_unsigned(k, p, v.i < 0 ? 0 : hi_u);
                    } else {
                        store_unsigned(k, p, static_cast<std::uint64_t>(v.i));
                    }
                }
                return {};
            case Scalar::Tag::Unsigned:
                if (v.u > hi_u) {
                    if (strict) return "value " + scalar_text(v) + " is out of range for " + field_kind_name(k);
                    if (dst_signed) store_signed(k, p, hi_s);
                    else store_unsigned(k, p, hi_u);
                } else if (dst_signed) {
                    store_signed(k, p, static_cast<std::int64_t>(v.u));
                } else {
                    store_unsigned(k, p, v.u);
                }
                return {};
            case Scalar::Tag::Float: {
                const double d = v.f;
                const double dlo = static_cast<double>(lo);
                const double dhi_excl = dst_signed ? static_cast<double>(hi_s) + 1.0 : static_cast<double>(hi_u) + 1.0;
                if (std::isnan(d)) {
                    if (strict) return "NaN cannot be stored in an integer field";
                    if (dst_signed) store_signed(k, p, 0);
                    else store_unsigned(k, p, 0);
                    return {};
                }
                const double t = std::trunc(d);
                const bool in_range = d >= dlo && d < dhi_excl;
                if (strict && (t != d || !in_range))
                    return "value " + scalar_text(v) + " is not exactly representable as " + field_kind_name(k);
                if (dst_signed) {
                    std::int64_t r;
                    if (t < dlo) r = lo;
                    else if (t >= dhi_excl) r = hi_s;
                    else r = static_cast<std::int64_t>(t);
                    store_signed(k, p, r);
                } else {
                    std::uint64_t r;
                    if (t < 0) r = 0;
                    else if (t >= dhi_excl) r = hi_u;
                    else r = static_cast<std::uint64_t>(t);
                    store_unsigned(k, p, r);
                }
                return {};
            }
            case Scalar::Tag::Pointer:
                break;
        }
        return "unsupported conversion";
    }

    if (k == FieldKind::F32 || k == FieldKind::F64) {
        const bool as_float = k == FieldKind::F32;
        double d = 0;
        switch (v.tag) {
            case Scalar::Tag::Bool: d = v.b ? 1.0 : 0.0; break;
            case Scalar::Tag::Signed:
                if (strict && !exact_in_double(v.i, as_float))
                    return "value " + scalar_text(v) + " is not exactly representable as " + field_kind_name(k);
                d = static_cast<double>(v.i);
                break;
            case Scalar::Tag::Unsigned:
                if (strict && !exact_in_double_u(v.u, as_float))
                    return "value " + scalar_text(v) + " is not exactly representable as " + field_kind_name(k);
                d = static_cast<double>(v.u);
                break;
            case Scalar::Tag::Float: d = v.f; break;
            case Scalar::Tag::Pointer: return "unsupported conversion";
        }
        if (as_float) {
            if (std::isfinite(d) && (d > FLT_MAX || d < -FLT_MAX)) {
                if (strict) return "value " + scalar_text(v) + " overflows f32";
                d = d > 0 ? FLT_MAX : -FLT_MAX;
            }
            store(p, static_cast<float>(d));
        } else {
            store(p, d);
        }
        return {};
    }

    if (k == FieldKind::Bool) {
        bool b = false;
        switch (v.tag) {
            case Scalar::Tag::Bool: b = v.b; break;
            case Scalar::Tag::Signed:
                if (strict && v.i != 0 && v.i != 1) return "value " + scalar_text(v) + " is not a boolean";
                b = v.i != 0;
                break;
            case Scalar::Tag::Unsigned:
                if (strict && v.u > 1) return "value " + scalar_text(v) + " is not a boolean";
                b = v.u != 0;
                break;
            case Scalar::Tag::Float:
                if (strict && v.f != 0.0 && v.f != 1.0) return "value " + scalar_text(v) + " is not a boolean";
                b = !std::isnan(v.f) && v.f != 0.0;
                break;
            case Scalar::Tag::Pointer: return "unsupported conversion";
        }
        store<std::uint8_t>(p, b ? 1 : 0);
        return {};
    }
    return "unsupported destination kind";
}

bool kinds_compatible(const FieldDesc& from, const FieldDesc& to, std::string& why) {
    if (field_kind_is_numeric(from.kind) && field_kind_is_numeric(to.kind)) return true;
    if (from.kind == FieldKind::Ptr && to.kind == FieldKind::Ptr) return true;
    if (from.kind == FieldKind::Ref && to.kind == FieldKind::Ref) {
        if (from.ref_type == to.ref_type) return true;
        why = "reference target type changes from '" + from.ref_type + "' to '" + to.ref_type + "'";
        return false;
    }
    if (from.kind == FieldKind::Bytes && to.kind == FieldKind::Bytes) return true;
    why = std::string("cannot convert ") + field_kind_name(from.kind) + " to " + field_kind_name(to.kind);
    return false;
}

void* aligned_zeroed(std::size_t size, std::size_t align) {
    if (align < alignof(std::max_align_t)) align = alignof(std::max_align_t);
    const std::size_t rounded = (size + align - 1) / align * align;
#if defined(_WIN32)
    void* p = ::_aligned_malloc(rounded, align);
#else
    void* p = std::aligned_alloc(align, rounded);
#endif
    if (p) std::memset(p, 0, rounded);
    return p;
}

void aligned_release(void* p) noexcept {
#if defined(_WIN32)
    ::_aligned_free(p);
#else
    std::free(p);
#endif
}

}  // namespace

// ------------------------------------------------------------ ObjectView

void ObjectView::error(std::string msg) const {
    if (ctx_) ctx_->fail(std::move(msg));
}

namespace {
const FieldDesc* view_field(const TypeDesc& t, std::string_view name) { return t.field(name); }
}  // namespace

#define VAJRA_VIEW_GET(fn, ret, KIND)                                                            \
    ret ObjectView::fn(std::string_view field) const {                                             \
        const FieldDesc* f = view_field(*type_, field);                                            \
        if (!f) {                                                                                  \
            error("no field '" + std::string(field) + "' in " + type_->name);                     \
            return ret{};                                                                          \
        }                                                                                          \
        if (!field_kind_is_numeric(f->kind)) {                                                     \
            error("field '" + f->name + "' is not numeric");                                       \
            return ret{};                                                                          \
        }                                                                                          \
        std::uint8_t buf[8] = {};                                                                  \
        const std::string why =                                                                    \
            write_scalar(read_scalar(f->kind, data_ + f->offset), KIND, buf, ConvertPolicy::Strict); \
        if (!why.empty()) {                                                                        \
            error("field '" + f->name + "': " + why);                                              \
            return ret{};                                                                          \
        }                                                                                          \
        ret v;                                                                                     \
        std::memcpy(&v, buf, sizeof v);                                                            \
        return v;                                                                                  \
    }

VAJRA_VIEW_GET(get_int, std::int64_t, FieldKind::I64)
VAJRA_VIEW_GET(get_uint, std::uint64_t, FieldKind::U64)
VAJRA_VIEW_GET(get_double, double, FieldKind::F64)
#undef VAJRA_VIEW_GET

bool ObjectView::get_bool(std::string_view field) const {
    const FieldDesc* f = view_field(*type_, field);
    if (!f || !field_kind_is_numeric(f->kind)) {
        error("no numeric field '" + std::string(field) + "' in " + type_->name);
        return false;
    }
    std::uint8_t buf[1] = {};
    const std::string why = write_scalar(read_scalar(f->kind, data_ + f->offset), FieldKind::Bool, buf,
                                         ConvertPolicy::Strict);
    if (!why.empty()) {
        error("field '" + f->name + "': " + why);
        return false;
    }
    return buf[0] != 0;
}

void* ObjectView::get_ptr(std::string_view field) const {
    const FieldDesc* f = view_field(*type_, field);
    if (!f || (f->kind != FieldKind::Ptr && f->kind != FieldKind::Ref)) {
        error("no pointer field '" + std::string(field) + "' in " + type_->name);
        return nullptr;
    }
    return reinterpret_cast<void*>(load<std::uintptr_t>(data_ + f->offset));
}

namespace {
void view_set(const TypeDesc& t, std::uint8_t* data, std::string_view field, const Scalar& s, ConvertPolicy pol,
              const std::function<void(std::string)>& err) {
    const FieldDesc* f = t.field(field);
    if (!f) {
        err("no field '" + std::string(field) + "' in " + t.name);
        return;
    }
    if (f->kind == FieldKind::Bytes) {
        err("field '" + f->name + "' holds bytes; use set_bytes");
        return;
    }
    const std::string why = write_scalar(s, f->kind, data + f->offset, pol);
    if (!why.empty()) err("field '" + f->name + "': " + why);
}
}  // namespace

void ObjectView::set_int(std::string_view field, std::int64_t v) {
    Scalar s;
    s.tag = Scalar::Tag::Signed;
    s.i = v;
    view_set(*type_, data_, field, s, policy_, [this](std::string m) { error(std::move(m)); });
}
void ObjectView::set_uint(std::string_view field, std::uint64_t v) {
    Scalar s;
    s.tag = Scalar::Tag::Unsigned;
    s.u = v;
    view_set(*type_, data_, field, s, policy_, [this](std::string m) { error(std::move(m)); });
}
void ObjectView::set_double(std::string_view field, double v) {
    Scalar s;
    s.tag = Scalar::Tag::Float;
    s.f = v;
    view_set(*type_, data_, field, s, policy_, [this](std::string m) { error(std::move(m)); });
}
void ObjectView::set_bool(std::string_view field, bool v) {
    Scalar s;
    s.tag = Scalar::Tag::Bool;
    s.b = v;
    view_set(*type_, data_, field, s, policy_, [this](std::string m) { error(std::move(m)); });
}
void ObjectView::set_ptr(std::string_view field, void* v) {
    Scalar s;
    s.tag = Scalar::Tag::Pointer;
    s.p = reinterpret_cast<std::uintptr_t>(v);
    view_set(*type_, data_, field, s, policy_, [this](std::string m) { error(std::move(m)); });
}
void ObjectView::set_bytes(std::string_view field, const void* src, std::size_t n) {
    const FieldDesc* f = type_->field(field);
    if (!f || f->kind != FieldKind::Bytes) {
        error("no bytes field '" + std::string(field) + "' in " + type_->name);
        return;
    }
    const std::size_t c = std::min<std::size_t>(n, f->size);
    std::memcpy(data_ + f->offset, src, c);
    std::memset(data_ + f->offset + c, 0, f->size - c);
}

// ------------------------------------------------------------ MigrationPlan

MigrationPlan::MigrationPlan(TypeDesc from, TypeDesc to) : from_(std::move(from)), to_(std::move(to)) {}

MigrationPlan& MigrationPlan::rename(std::string old_field, std::string new_field) {
    renames_.emplace_back(std::move(old_field), std::move(new_field));
    compiled_ = false;
    return *this;
}
MigrationPlan& MigrationPlan::drop(std::string old_field) {
    drops_.push_back(std::move(old_field));
    compiled_ = false;
    return *this;
}
MigrationPlan& MigrationPlan::fill_int(std::string new_field, std::int64_t v) {
    FillValue f;
    f.tag = FillValue::Tag::Int;
    f.i = v;
    fills_.emplace_back(std::move(new_field), f);
    compiled_ = false;
    return *this;
}
MigrationPlan& MigrationPlan::fill_double(std::string new_field, double v) {
    FillValue f;
    f.tag = FillValue::Tag::Double;
    f.d = v;
    fills_.emplace_back(std::move(new_field), f);
    compiled_ = false;
    return *this;
}
MigrationPlan& MigrationPlan::fill_bool(std::string new_field, bool v) {
    FillValue f;
    f.tag = FillValue::Tag::Bool;
    f.b = v;
    fills_.emplace_back(std::move(new_field), f);
    compiled_ = false;
    return *this;
}
MigrationPlan& MigrationPlan::policy(ConvertPolicy p) {
    policy_ = p;
    compiled_ = false;
    return *this;
}
MigrationPlan& MigrationPlan::transform(MigrationTransform fn) {
    transforms_.push_back(std::move(fn));
    return *this;
}

Result MigrationPlan::compile() {
    if (compiled_) return Result::ok();
    ops_.clear();
    if (Result r = from_.validate(); !r) return r;
    if (Result r = to_.validate(); !r) return r;
    const std::string who = from_.name + " v" + std::to_string(from_.version) + " -> v" + std::to_string(to_.version);
    if (from_.name != to_.name) return {Status::InvalidArgument, "a migration cannot change the type name"};
    if (from_.version == to_.version) return {Status::InvalidArgument, who + ": versions must differ"};

    std::map<std::string, std::string> ren;
    std::set<std::string> ren_targets;
    for (const auto& [o, n] : renames_) {
        if (!from_.field(o)) return {Status::InvalidArgument, who + ": rename source '" + o + "' does not exist"};
        if (!to_.field(n)) return {Status::InvalidArgument, who + ": rename target '" + n + "' does not exist"};
        if (!ren.emplace(o, n).second) return {Status::InvalidArgument, who + ": field '" + o + "' renamed twice"};
        if (!ren_targets.insert(n).second)
            return {Status::InvalidArgument, who + ": two fields renamed to '" + n + "'"};
    }
    std::set<std::string> dropped;
    for (const auto& d : drops_) {
        if (!from_.field(d)) return {Status::InvalidArgument, who + ": dropped field '" + d + "' does not exist"};
        if (ren.count(d)) return {Status::InvalidArgument, who + ": field '" + d + "' is both renamed and dropped"};
        dropped.insert(d);
    }
    std::map<std::string, FillValue> fills;
    for (const auto& [n, v] : fills_) {
        if (!to_.field(n)) return {Status::InvalidArgument, who + ": filled field '" + n + "' does not exist"};
        if (!fills.emplace(n, v).second) return {Status::InvalidArgument, who + ": field '" + n + "' filled twice"};
    }

    auto dest_of = [&](const FieldDesc& f) -> std::string {
        if (auto it = ren.find(f.name); it != ren.end()) return it->second;
        if (dropped.count(f.name)) return {};
        return f.name;
    };

    // Every old field needs a destination or an explicit drop().
    for (const auto& f : from_.fields) {
        const std::string d = dest_of(f);
        if (!d.empty() && !to_.field(d))
            return {Status::InvalidArgument,
                    who + ": field '" + f.name + "' has no destination in the new version; use drop() or rename()"};
    }

    for (std::size_t j = 0; j < to_.fields.size(); ++j) {
        const FieldDesc& nf = to_.fields[j];
        std::size_t src = from_.fields.size();
        for (std::size_t i = 0; i < from_.fields.size(); ++i) {
            if (dest_of(from_.fields[i]) != nf.name) continue;
            if (src != from_.fields.size())
                return {Status::InvalidArgument, who + ": two old fields map to '" + nf.name + "'"};
            src = i;
        }
        const auto fill = fills.find(nf.name);
        if (src != from_.fields.size()) {
            if (fill != fills.end())
                return {Status::InvalidArgument, who + ": field '" + nf.name + "' has both a source and a fill value"};
            std::string why;
            if (!kinds_compatible(from_.fields[src], nf, why))
                return {Status::InvalidArgument, who + ": field '" + from_.fields[src].name + "' -> '" + nf.name +
                                                     "': " + why};
            Op op;
            op.kind = Op::Kind::Copy;
            op.src = src;
            op.dst = j;
            ops_.push_back(std::move(op));
        } else if (fill != fills.end()) {
            if (!field_kind_is_numeric(nf.kind))
                return {Status::InvalidArgument, who + ": fill value for non-numeric field '" + nf.name + "'"};
            Scalar s;
            switch (fill->second.tag) {
                case FillValue::Tag::Int: s.tag = Scalar::Tag::Signed; s.i = fill->second.i; break;
                case FillValue::Tag::Double: s.tag = Scalar::Tag::Float; s.f = fill->second.d; break;
                case FillValue::Tag::Bool: s.tag = Scalar::Tag::Bool; s.b = fill->second.b; break;
            }
            Op op;
            op.kind = Op::Kind::Fill;
            op.dst = j;
            op.fill.assign(nf.size, 0);
            const std::string why = write_scalar(s, nf.kind, op.fill.data(), policy_);
            if (!why.empty()) return {Status::InvalidArgument, who + ": fill value for '" + nf.name + "': " + why};
            ops_.push_back(std::move(op));
        }
        // else: zero-initialized
    }
    compiled_ = true;
    return Result::ok();
}

Result MigrationPlan::convert_object(const void* src_v, void* dst_v, std::size_t index) const {
    if (!compiled_) return {Status::Internal, "migration plan is not compiled"};
    const auto* src = static_cast<const std::uint8_t*>(src_v);
    auto* dst = static_cast<std::uint8_t*>(dst_v);
    for (const Op& op : ops_) {
        const FieldDesc& df = to_.fields[op.dst];
        if (op.kind == Op::Kind::Fill) {
            std::memcpy(dst + df.offset, op.fill.data(), df.size);
            continue;
        }
        const FieldDesc& sf = from_.fields[op.src];
        if (sf.kind == FieldKind::Bytes) {
            const std::size_t c = std::min(sf.size, df.size);
            std::memcpy(dst + df.offset, src + sf.offset, c);
            if (sf.size > df.size && policy_ == ConvertPolicy::Strict) {
                for (std::size_t i = c; i < sf.size; ++i)
                    if (src[sf.offset + i] != 0)
                        return {Status::MigrationFailed, "object #" + std::to_string(index) + " field '" + sf.name +
                                                             "': truncating non-zero bytes"};
            }
            continue;
        }
        const std::string why = write_scalar(read_scalar(sf.kind, src + sf.offset), df.kind, dst + df.offset, policy_);
        if (!why.empty())
            return {Status::MigrationFailed,
                    "object #" + std::to_string(index) + " field '" + sf.name + "' -> '" + df.name + "': " + why};
    }
    if (!transforms_.empty()) {
        MigrationContext ctx;
        ctx.index = index;
        const ObjectView from(from_, const_cast<std::uint8_t*>(src), &ctx, ConvertPolicy::Strict);
        ObjectView to(to_, dst, &ctx, policy_);
        for (const auto& t : transforms_) {
            const bool ok = t(from, to, ctx);
            if (!ok || ctx.failed())
                return {Status::MigrationFailed, "object #" + std::to_string(index) + ": transform failed" +
                                                     (ctx.message().empty() ? "" : ": " + ctx.message())};
        }
    }
    return Result::ok();
}

long MigrationPlan::map_offset(std::uint32_t old_offset) const noexcept {
    for (const Op& op : ops_) {
        if (op.kind != Op::Kind::Copy) continue;
        if (from_.fields[op.src].offset == old_offset) return static_cast<long>(to_.fields[op.dst].offset);
    }
    return -1;
}

// ------------------------------------------------------------ Heap

Heap::Heap() = default;

Heap::~Heap() {
    for (auto& [addr, info] : objects_) aligned_release(reinterpret_cast<void*>(addr));
    for (void* p : quarantine_list_) aligned_release(p);
}

Result Heap::register_type(const TypeDesc& type) {
    if (Result r = type.validate(); !r) return r;
    std::lock_guard<std::mutex> g(mu_);
    if (types_.count(type.name)) return {Status::AlreadyApplied, "type '" + type.name + "' is already registered"};
    auto ts = std::make_unique<TypeState>();
    ts->desc = type;
    types_.emplace(type.name, std::move(ts));
    return Result::ok();
}

void* Heap::allocate(std::string_view type, std::uint32_t version) {
    std::lock_guard<std::mutex> g(mu_);
    auto it = types_.find(type);
    if (it == types_.end() || it->second->desc.version != version) return nullptr;
    TypeState* ts = it->second.get();
    void* p = aligned_zeroed(ts->desc.size, ts->desc.align);
    if (!p) return nullptr;
    try {
        objects_.emplace(reinterpret_cast<std::uintptr_t>(p), ObjInfo{ts});
    } catch (...) {
        aligned_release(p);
        return nullptr;
    }
    ++ts->count;
    return p;
}

bool Heap::deallocate(void* p) {
    std::lock_guard<std::mutex> g(mu_);
    auto it = objects_.find(reinterpret_cast<std::uintptr_t>(p));
    if (it == objects_.end()) return false;
    --it->second.type->count;
    objects_.erase(it);
    aligned_release(p);
    return true;
}

std::uint32_t Heap::version(std::string_view type) const {
    std::lock_guard<std::mutex> g(mu_);
    auto it = types_.find(type);
    return it == types_.end() ? 0 : it->second->desc.version;
}

bool Heap::type_desc(std::string_view type, TypeDesc& out) const {
    std::lock_guard<std::mutex> g(mu_);
    auto it = types_.find(type);
    if (it == types_.end()) return false;
    out = it->second->desc;
    return true;
}

std::size_t Heap::count(std::string_view type) const {
    std::lock_guard<std::mutex> g(mu_);
    auto it = types_.find(type);
    return it == types_.end() ? 0 : it->second->count;
}

bool Heap::owns(const void* p) const {
    std::lock_guard<std::mutex> g(mu_);
    return objects_.count(reinterpret_cast<std::uintptr_t>(p)) != 0;
}

void Heap::add_root(void** slot) {
    std::lock_guard<std::mutex> g(mu_);
    if (std::find(roots_.begin(), roots_.end(), slot) == roots_.end()) roots_.push_back(slot);
}

void Heap::add_root_range(void** first, std::size_t n) {
    std::lock_guard<std::mutex> g(mu_);
    for (std::size_t i = 0; i < n; ++i)
        if (std::find(roots_.begin(), roots_.end(), first + i) == roots_.end()) roots_.push_back(first + i);
}

bool Heap::remove_root(void** slot) {
    std::lock_guard<std::mutex> g(mu_);
    auto it = std::find(roots_.begin(), roots_.end(), slot);
    if (it == roots_.end()) return false;
    roots_.erase(it);
    return true;
}

void Heap::for_each(std::string_view type, const std::function<void(void*)>& f) const {
    std::lock_guard<std::mutex> g(mu_);
    auto it = types_.find(type);
    if (it == types_.end()) return;
    const TypeState* ts = it->second.get();
    for (const auto& [addr, info] : objects_)
        if (info.type == ts) f(reinterpret_cast<void*>(addr));
}

void Heap::set_quarantine(bool on) {
    std::lock_guard<std::mutex> g(mu_);
    quarantine_ = on;
}

std::size_t Heap::quarantined() const {
    std::lock_guard<std::mutex> g(mu_);
    return quarantine_list_.size();
}

void Heap::release_quarantine() {
    std::vector<void*> list;
    {
        std::lock_guard<std::mutex> g(mu_);
        list.swap(quarantine_list_);
    }
    for (void* p : list) aligned_release(p);
}

// ------------------------------------------------------------ MigrationJob

namespace detail {

MigrationJob::~MigrationJob() {
    if (prepared_ && !committed_) abort();
}

bool MigrationJob::forward(std::uintptr_t v, std::uintptr_t& out, bool& bad) const {
    bad = false;
    auto it = std::upper_bound(olds_.begin(), olds_.end(), v);
    if (it == olds_.begin()) return false;
    --it;
    const std::uintptr_t base = *it;
    const std::uintptr_t off = v - base;
    if (off >= plan_.from().size) return false;
    const std::size_t idx = static_cast<std::size_t>(it - olds_.begin());
    if (off == 0) {
        out = news_[idx];
        return true;
    }
    const long nofs = plan_.map_offset(static_cast<std::uint32_t>(off));
    if (nofs < 0) {
        bad = true;
        return true;
    }
    out = news_[idx] + static_cast<std::uintptr_t>(nofs);
    return true;
}

Result MigrationJob::prepare() {
    const MigrationPlan& plan = plan_;
    const TypeDesc& from = plan.from();
    const TypeDesc& to = plan.to();
    auto tit = heap_.types_.find(from.name);
    if (tit == heap_.types_.end()) return {Status::NotFound, "type '" + from.name + "' is not registered in the heap"};
    ts_ = tit->second.get();
    if (!ts_->desc.same_layout(from))
        return {Status::VersionMismatch, "heap holds " + ts_->desc.name + " v" + std::to_string(ts_->desc.version) +
                                             ", the plan migrates from v" + std::to_string(from.version) +
                                             (ts_->desc.version == from.version ? " (layout differs)" : "")};
    // Reference fields of the new layout must name registered types.
    for (const auto& f : to.fields)
        if (f.kind == FieldKind::Ref && f.ref_type != to.name && !heap_.types_.count(f.ref_type))
            return {Status::NotFound, "reference field '" + f.name + "' names unknown type '" + f.ref_type + "'"};

    olds_.clear();
    news_.clear();
    writes_.clear();
    for (const auto& [addr, info] : heap_.objects_)
        if (info.type == ts_) olds_.push_back(addr);
    news_.reserve(olds_.size());
    prepared_ = true;

    for (std::size_t i = 0; i < olds_.size(); ++i) {
        void* p = aligned_zeroed(to.size, to.align);
        if (!p) {
            abort();
            return {Status::NoMemory, "cannot allocate migrated objects"};
        }
        news_.push_back(reinterpret_cast<std::uintptr_t>(p));
    }
    for (std::size_t i = 0; i < olds_.size(); ++i) {
        Result r = plan.convert_object(reinterpret_cast<const void*>(olds_[i]), reinterpret_cast<void*>(news_[i]), i);
        if (!r) {
            abort();
            return r;
        }
    }

    auto describe_target = [&](std::uintptr_t v, const std::string& ref_type) -> bool {
        // v points at a live, non-migrated heap object of type ref_type (start or field start)?
        auto it = heap_.objects_.upper_bound(v);
        if (it == heap_.objects_.begin()) return false;
        --it;
        const Heap::TypeState* t = it->second.type;
        if (t == ts_) return false;  // old object, handled by forward()
        const std::uintptr_t off = v - it->first;
        if (off >= t->desc.size || t->desc.name != ref_type) return false;
        if (off == 0) return true;
        for (const auto& f : t->desc.fields)
            if (f.offset == off) return true;
        return false;
    };

    // Reference fields inside the new objects.
    for (std::size_t i = 0; i < news_.size(); ++i) {
        auto* obj = reinterpret_cast<std::uint8_t*>(news_[i]);
        for (const auto& f : to.fields) {
            if (f.kind != FieldKind::Ref) continue;
            std::uintptr_t v;
            std::memcpy(&v, obj + f.offset, sizeof v);
            if (v == 0) continue;
            std::uintptr_t nv;
            bool bad;
            if (forward(v, nv, bad)) {
                if (bad || f.ref_type != to.name) {
                    abort();
                    return {Status::MigrationFailed, "object #" + std::to_string(i) + " field '" + f.name +
                                                         "': reference into a field that has no destination"};
                }
                std::memcpy(obj + f.offset, &nv, sizeof nv);
            } else if (!describe_target(v, f.ref_type)) {
                abort();
                return {Status::MigrationFailed, "object #" + std::to_string(i) + " field '" + f.name +
                                                     "': dangling or mistyped reference"};
            }
        }
    }

    // Root slots.
    for (void** slot : heap_.roots_) {
        std::uintptr_t v;
        std::memcpy(&v, slot, sizeof v);
        std::uintptr_t nv;
        bool bad;
        if (v != 0 && forward(v, nv, bad)) {
            if (bad) {
                abort();
                return {Status::MigrationFailed, "a root points into a field that has no destination"};
            }
            writes_.emplace_back(reinterpret_cast<std::uintptr_t>(slot), nv);
        }
    }

    // Reference fields of other types that point at migrated objects.
    for (const auto& [addr, info] : heap_.objects_) {
        if (info.type == ts_) continue;
        for (const auto& f : info.type->desc.fields) {
            if (f.kind != FieldKind::Ref || f.ref_type != from.name) continue;
            std::uintptr_t v;
            std::memcpy(&v, reinterpret_cast<const void*>(addr + f.offset), sizeof v);
            std::uintptr_t nv;
            bool bad;
            if (v != 0 && forward(v, nv, bad)) {
                if (bad) {
                    abort();
                    return {Status::MigrationFailed, "a " + info.type->desc.name + "." + f.name +
                                                         " reference points into a field that has no destination"};
                }
                writes_.emplace_back(addr + f.offset, nv);
            }
        }
    }

    new_desc_ = to;
    return Result::ok();
}

void MigrationJob::commit() noexcept {
    for (const auto& [slot, value] : writes_) std::memcpy(reinterpret_cast<void*>(slot), &value, sizeof value);
    for (std::size_t i = 0; i < olds_.size(); ++i) {
        auto node = heap_.objects_.extract(olds_[i]);
        node.key() = news_[i];
        heap_.objects_.insert(std::move(node));
    }
    std::swap(ts_->desc, new_desc_);
    committed_ = true;
}

void MigrationJob::abort() noexcept {
    for (std::uintptr_t p : news_) aligned_release(reinterpret_cast<void*>(p));
    news_.clear();
    writes_.clear();
    prepared_ = false;
}

void MigrationJob::finalize() noexcept {
    if (!committed_) return;
    std::vector<std::uintptr_t> olds;
    olds.swap(olds_);
    std::lock_guard<std::mutex> g(heap_.mu_);
    for (std::uintptr_t p : olds) {
        if (heap_.quarantine_) {
            std::memset(reinterpret_cast<void*>(p), 0xDD, new_desc_.size);  // new_desc_ now holds the old layout
            try {
                heap_.quarantine_list_.push_back(reinterpret_cast<void*>(p));
            } catch (...) {
                aligned_release(reinterpret_cast<void*>(p));
            }
        } else {
            aligned_release(reinterpret_cast<void*>(p));
        }
    }
    news_.clear();
}

}  // namespace detail

}  // namespace vajra
