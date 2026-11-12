// Vajra Binary Core - type descriptions.
// SPDX-License-Identifier: MIT
#include "vajra/types.hpp"

#include <algorithm>
#include <set>

namespace vajra {

const char* field_kind_name(FieldKind k) noexcept {
    switch (k) {
        case FieldKind::I8: return "i8";
        case FieldKind::I16: return "i16";
        case FieldKind::I32: return "i32";
        case FieldKind::I64: return "i64";
        case FieldKind::U8: return "u8";
        case FieldKind::U16: return "u16";
        case FieldKind::U32: return "u32";
        case FieldKind::U64: return "u64";
        case FieldKind::F32: return "f32";
        case FieldKind::F64: return "f64";
        case FieldKind::Bool: return "bool";
        case FieldKind::Ptr: return "ptr";
        case FieldKind::Ref: return "ref";
        case FieldKind::Bytes: return "bytes";
    }
    return "?";
}

std::size_t field_kind_size(FieldKind k) noexcept {
    switch (k) {
        case FieldKind::I8: case FieldKind::U8: case FieldKind::Bool: return 1;
        case FieldKind::I16: case FieldKind::U16: return 2;
        case FieldKind::I32: case FieldKind::U32: case FieldKind::F32: return 4;
        case FieldKind::I64: case FieldKind::U64: case FieldKind::F64: return 8;
        case FieldKind::Ptr: case FieldKind::Ref: return sizeof(void*);
        case FieldKind::Bytes: return 0;
    }
    return 0;
}

bool field_kind_is_numeric(FieldKind k) noexcept {
    switch (k) {
        case FieldKind::Ptr: case FieldKind::Ref: case FieldKind::Bytes: return false;
        default: return true;
    }
}

const FieldDesc* TypeDesc::field(std::string_view n) const noexcept {
    for (const auto& f : fields)
        if (f.name == n) return &f;
    return nullptr;
}

Result TypeDesc::validate() const {
    if (name.empty()) return {Status::InvalidArgument, "type has no name"};
    const std::string who = name + " v" + std::to_string(version);
    if (version == 0) return {Status::InvalidArgument, who + ": version must be >= 1"};
    if (size == 0) return {Status::InvalidArgument, who + ": size is 0"};
    if (align == 0 || (align & (align - 1)) != 0) return {Status::InvalidArgument, who + ": alignment is not a power of two"};
    if (size % align != 0) return {Status::InvalidArgument, who + ": size is not a multiple of the alignment"};
    std::set<std::string> names;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> spans;
    for (const auto& f : fields) {
        if (f.name.empty()) return {Status::InvalidArgument, who + ": field without a name"};
        if (!names.insert(f.name).second) return {Status::InvalidArgument, who + ": duplicate field '" + f.name + "'"};
        if (f.size == 0) return {Status::InvalidArgument, who + ": field '" + f.name + "' has size 0"};
        const std::size_t ks = field_kind_size(f.kind);
        if (ks != 0 && ks != f.size)
            return {Status::InvalidArgument, who + ": field '" + f.name + "' size does not match its kind"};
        if (static_cast<std::uint64_t>(f.offset) + f.size > size)
            return {Status::InvalidArgument, who + ": field '" + f.name + "' lies outside the object"};
        if (f.kind == FieldKind::Ref && f.ref_type.empty())
            return {Status::InvalidArgument, who + ": reference field '" + f.name + "' has no target type"};
        if (f.kind != FieldKind::Ref && !f.ref_type.empty())
            return {Status::InvalidArgument, who + ": field '" + f.name + "' has a target type but is not a reference"};
        spans.emplace_back(f.offset, f.offset + f.size);
    }
    std::sort(spans.begin(), spans.end());
    for (std::size_t i = 1; i < spans.size(); ++i)
        if (spans[i].first < spans[i - 1].second) return {Status::InvalidArgument, who + ": fields overlap"};
    return Result::ok();
}

bool TypeDesc::same_layout(const TypeDesc& o) const noexcept {
    if (name != o.name || version != o.version || size != o.size || align != o.align ||
        fields.size() != o.fields.size())
        return false;
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const auto& a = fields[i];
        const auto& b = o.fields[i];
        if (a.name != b.name || a.kind != b.kind || a.offset != b.offset || a.size != b.size || a.ref_type != b.ref_type)
            return false;
    }
    return true;
}

}  // namespace vajra
