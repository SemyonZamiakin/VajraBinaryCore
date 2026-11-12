// Vajra Binary Core - live type migration: field mapping plans and the heap
// that tracks migratable objects.
//
// A MigrationPlan turns objects of one TypeDesc version into another. Fields
// are matched by name; rename() maps differently named fields, fill() sets a
// value for new fields, drop() declares that an old field's data is discarded
// on purpose, and transform() runs custom code after the automatic mapping.
// Numeric fields convert between kinds under a ConvertPolicy; with Strict (the
// default) any value that would change aborts the whole migration and nothing
// is modified.
//
// Objects must live in a vajra::Heap so they can be found. Pointers to them are
// fixed up when they live in Ref fields of heap objects or in registered root
// slots (Heap::add_root). Pointers kept anywhere else are not updated.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "vajra/status.hpp"
#include "vajra/types.hpp"

namespace vajra {

enum class ConvertPolicy {
    // Fail if a value cannot be represented exactly. Exceptions: float rounding
    // when narrowing f64 to f32 is allowed (overflow to infinity is not).
    Strict,
    // Clamp integers to the destination range; float to int truncates toward
    // zero and clamps (NaN becomes 0); nonzero becomes true for bool.
    Saturate,
};

namespace detail {
class MigrationJob;
}

class MigrationContext {
public:
    std::size_t index = 0;  // object index within this migration
    void fail(std::string message) {
        failed_ = true;
        if (message_.empty()) message_ = std::move(message);
    }
    bool failed() const noexcept { return failed_; }
    const std::string& message() const noexcept { return message_; }

private:
    bool failed_ = false;
    std::string message_;
};

// Typed, name-based access to one object. Getters convert to the requested type
// under Strict rules; setters convert under the view's policy. A failed get/set
// marks the context as failed (which aborts the migration) and returns 0.
class ObjectView {
public:
    ObjectView(const TypeDesc& type, void* data, MigrationContext* ctx = nullptr,
               ConvertPolicy policy = ConvertPolicy::Strict)
        : type_(&type), data_(static_cast<std::uint8_t*>(data)), ctx_(ctx), policy_(policy) {}

    const TypeDesc& type() const noexcept { return *type_; }
    void* data() noexcept { return data_; }
    const void* data() const noexcept { return data_; }
    bool has(std::string_view field) const noexcept { return type_->field(field) != nullptr; }

    std::int64_t get_int(std::string_view field) const;
    std::uint64_t get_uint(std::string_view field) const;
    double get_double(std::string_view field) const;
    bool get_bool(std::string_view field) const;
    void* get_ptr(std::string_view field) const;  // Ptr or Ref

    void set_int(std::string_view field, std::int64_t v);
    void set_uint(std::string_view field, std::uint64_t v);
    void set_double(std::string_view field, double v);
    void set_bool(std::string_view field, bool v);
    void set_ptr(std::string_view field, void* v);  // for Ref: the *old* address; remapped afterwards
    // Bytes fields: copies min(n, size) bytes and zero-fills the rest.
    void set_bytes(std::string_view field, const void* src, std::size_t n);

private:
    void error(std::string msg) const;
    const TypeDesc* type_;
    std::uint8_t* data_;
    MigrationContext* ctx_;
    ConvertPolicy policy_;
};

using MigrationTransform = std::function<bool(const ObjectView& from, ObjectView& to, MigrationContext& ctx)>;

class MigrationPlan {
public:
    MigrationPlan(TypeDesc from, TypeDesc to);

    MigrationPlan& rename(std::string old_field, std::string new_field);
    MigrationPlan& drop(std::string old_field);
    MigrationPlan& fill_int(std::string new_field, std::int64_t v);
    MigrationPlan& fill_double(std::string new_field, double v);
    MigrationPlan& fill_bool(std::string new_field, bool v);
    MigrationPlan& policy(ConvertPolicy p);
    // Runs for each object after the field mapping. Return false (or call
    // ctx.fail) to abort the migration.
    MigrationPlan& transform(MigrationTransform fn);

    // Validates the plan. Called by Transaction::migrate; safe to call twice.
    Result compile();

    const TypeDesc& from() const noexcept { return from_; }
    const TypeDesc& to() const noexcept { return to_; }
    ConvertPolicy convert_policy() const noexcept { return policy_; }

    // Converts one object (old layout -> new layout, `dst` zeroed by caller).
    // Ref fields are written with their old values. Exposed for tests.
    Result convert_object(const void* src, void* dst, std::size_t index) const;

    // For a field offset inside an old object, the new offset of the same data,
    // or -1 if that data has no destination.
    long map_offset(std::uint32_t old_offset) const noexcept;

private:
    struct FillValue {
        enum class Tag { Int, Double, Bool } tag = Tag::Int;
        std::int64_t i = 0;
        double d = 0;
        bool b = false;
    };
    struct Op {
        enum class Kind { Copy, Fill } kind = Kind::Copy;
        std::size_t src = 0;  // index into from_.fields (Copy)
        std::size_t dst = 0;  // index into to_.fields
        std::vector<std::uint8_t> fill;  // pre-converted bytes (Fill)
    };

    TypeDesc from_;
    TypeDesc to_;
    ConvertPolicy policy_ = ConvertPolicy::Strict;
    std::vector<std::pair<std::string, std::string>> renames_;
    std::vector<std::string> drops_;
    std::vector<std::pair<std::string, FillValue>> fills_;
    std::vector<MigrationTransform> transforms_;
    std::vector<Op> ops_;
    bool compiled_ = false;
};

// Tracks objects of migratable types. Thread-safe; allocate/deallocate take an
// internal mutex. A migration holds that mutex while it runs.
class Heap {
public:
    Heap();
    ~Heap();  // frees all remaining objects
    Heap(const Heap&) = delete;
    Heap& operator=(const Heap&) = delete;

    // Registers the initial version of a type. Fails if the name exists.
    Result register_type(const TypeDesc& type);
    // Zero-initialized storage for the *current* version of `type`. Returns
    // nullptr if the type is unknown, `version` is not the current version
    // (stale code after a migration), or memory is exhausted.
    void* allocate(std::string_view type, std::uint32_t version);
    // Returns false if `p` is not an object of this heap.
    bool deallocate(void* p);

    std::uint32_t version(std::string_view type) const;  // 0 if unknown
    bool type_desc(std::string_view type, TypeDesc& out) const;
    std::size_t count(std::string_view type) const;
    bool owns(const void* p) const;

    // Root slots: pointer variables outside the heap that may point to heap
    // objects (or interior fields). They are rewritten by migrations.
    void add_root(void** slot);
    template <class T>
    void add_root(T** slot) { add_root(reinterpret_cast<void**>(slot)); }
    void add_root_range(void** first, std::size_t n);
    template <class T>
    void add_root_range(T** first, std::size_t n) { add_root_range(reinterpret_cast<void**>(first), n); }
    bool remove_root(void** slot);
    template <class T>
    bool remove_root(T** slot) { return remove_root(reinterpret_cast<void**>(slot)); }

    // Calls f(object) for every object of `type` with the heap locked. f must
    // not call back into this heap.
    void for_each(std::string_view type, const std::function<void(void*)>& f) const;

    // When enabled, migrated-away objects are filled with 0xDD and kept until
    // release_quarantine() instead of being freed, so stale pointers read
    // garbage instead of reused memory. Off by default.
    void set_quarantine(bool on);
    std::size_t quarantined() const;
    void release_quarantine();

private:
    friend class detail::MigrationJob;
    struct TypeState {
        TypeDesc desc;
        std::size_t count = 0;
    };
    struct ObjInfo {
        TypeState* type = nullptr;
    };

    mutable std::mutex mu_;
    std::map<std::string, std::unique_ptr<TypeState>, std::less<>> types_;
    std::map<std::uintptr_t, ObjInfo> objects_;
    std::vector<void**> roots_;
    bool quarantine_ = false;
    std::vector<void*> quarantine_list_;
};

}  // namespace vajra
