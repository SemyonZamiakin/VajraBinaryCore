// Vajra Binary Core - runtime type descriptions for live type migration.
//
// A TypeDesc describes the memory layout of one version of a struct: its name,
// version, size, alignment and fields (name, kind, offset, size). Layouts are
// declared next to the struct with offsetof, so they cannot drift from the
// compiled definition:
//
//   struct EntityV1 { std::uint32_t id; std::int32_t hp; float x, y; EntityV1* target; };
//   const vajra::TypeDesc kEntityV1 = vajra::describe<EntityV1>("Entity", 1, {
//       VAJRA_FIELD(EntityV1, id), VAJRA_FIELD(EntityV1, hp),
//       VAJRA_FIELD(EntityV1, x),  VAJRA_FIELD(EntityV1, y),
//       VAJRA_REF(EntityV1, target, "Entity")});
//
// Only trivially copyable, standard-layout structs can be described.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "vajra/status.hpp"

namespace vajra {

enum class FieldKind : std::uint8_t {
    I8, I16, I32, I64,
    U8, U16, U32, U64,
    F32, F64,
    Bool,
    Ptr,    // opaque pointer, copied verbatim
    Ref,    // pointer to an object managed by a vajra::Heap; fixed up on migration
    Bytes,  // opaque bytes (arrays, nested structs), copied verbatim
};

const char* field_kind_name(FieldKind k) noexcept;
std::size_t field_kind_size(FieldKind k) noexcept;  // 0 for Bytes
bool field_kind_is_numeric(FieldKind k) noexcept;  // integers, floats and bool

struct FieldDesc {
    std::string name;
    FieldKind kind = FieldKind::Bytes;
    std::uint32_t offset = 0;
    std::uint32_t size = 0;
    std::string ref_type;  // for Ref: name of the referenced type
};

struct TypeDesc {
    std::string name;
    std::uint32_t version = 0;
    std::uint32_t size = 0;
    std::uint32_t align = 1;
    std::vector<FieldDesc> fields;

    const FieldDesc* field(std::string_view n) const noexcept;
    // Checks names, bounds, overlap, kind sizes and alignment.
    Result validate() const;
    bool same_layout(const TypeDesc& o) const noexcept;
};

namespace detail {

template <class M>
constexpr FieldKind kind_of() {
    if constexpr (std::is_same_v<M, bool>) {
        return FieldKind::Bool;
    } else if constexpr (std::is_enum_v<M>) {
        return kind_of<std::underlying_type_t<M>>();
    } else if constexpr (std::is_integral_v<M>) {
        if constexpr (std::is_signed_v<M>) {
            return sizeof(M) == 1 ? FieldKind::I8
                 : sizeof(M) == 2 ? FieldKind::I16
                 : sizeof(M) == 4 ? FieldKind::I32
                                  : FieldKind::I64;
        } else {
            return sizeof(M) == 1 ? FieldKind::U8
                 : sizeof(M) == 2 ? FieldKind::U16
                 : sizeof(M) == 4 ? FieldKind::U32
                                  : FieldKind::U64;
        }
    } else if constexpr (std::is_same_v<M, float>) {
        return FieldKind::F32;
    } else if constexpr (std::is_same_v<M, double>) {
        return FieldKind::F64;
    } else if constexpr (std::is_pointer_v<M>) {
        return FieldKind::Ptr;
    } else {
        return FieldKind::Bytes;
    }
}

template <class M>
FieldDesc make_field(const char* name, std::size_t offset) {
    static_assert(std::is_trivially_copyable_v<M>, "fields must be trivially copyable");
    static_assert(!std::is_integral_v<M> || sizeof(M) <= 8, "integers wider than 64 bits are not supported");
    FieldDesc f;
    f.name = name;
    f.kind = kind_of<M>();
    f.offset = static_cast<std::uint32_t>(offset);
    f.size = static_cast<std::uint32_t>(sizeof(M));
    return f;
}

template <class M>
FieldDesc make_ref(const char* name, std::size_t offset, const char* type_name) {
    static_assert(std::is_pointer_v<M>, "VAJRA_REF requires a pointer member");
    FieldDesc f = make_field<M>(name, offset);
    f.kind = FieldKind::Ref;
    f.ref_type = type_name;
    return f;
}

}  // namespace detail

#define VAJRA_FIELD(T, member) ::vajra::detail::make_field<decltype(T::member)>(#member, offsetof(T, member))
#define VAJRA_REF(T, member, type_name) \
    ::vajra::detail::make_ref<decltype(T::member)>(#member, offsetof(T, member), type_name)

template <class T>
TypeDesc describe(std::string name, std::uint32_t version, std::vector<FieldDesc> fields) {
    static_assert(std::is_trivially_copyable_v<T>, "migratable types must be trivially copyable");
    static_assert(std::is_standard_layout_v<T>, "migratable types must be standard-layout");
    TypeDesc t;
    t.name = std::move(name);
    t.version = version;
    t.size = static_cast<std::uint32_t>(sizeof(T));
    t.align = static_cast<std::uint32_t>(alignof(T));
    t.fields = std::move(fields);
    return t;
}

}  // namespace vajra
