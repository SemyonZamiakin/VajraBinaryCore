// Vajra Binary Core - status codes.
// SPDX-License-Identifier: MIT
#include "vajra/status.hpp"

namespace vajra {

const char* status_name(Status s) noexcept {
    switch (s) {
        case Status::Ok: return "ok";
        case Status::InvalidArgument: return "invalid argument";
        case Status::Unsupported: return "unsupported";
        case Status::DecodeFailed: return "decode failed";
        case Status::RelocationFailed: return "relocation failed";
        case Status::OutOfRange: return "out of range";
        case Status::Busy: return "busy";
        case Status::Timeout: return "timeout";
        case Status::NoMemory: return "out of memory";
        case Status::ProtectFailed: return "protection change failed";
        case Status::WriteFailed: return "write failed";
        case Status::Mismatch: return "memory mismatch";
        case Status::NotFound: return "not found";
        case Status::AlreadyApplied: return "already applied";
        case Status::NotApplied: return "not applied";
        case Status::NotRevertible: return "not revertible";
        case Status::MigrationFailed: return "migration failed";
        case Status::VersionMismatch: return "version mismatch";
        case Status::IoError: return "I/O error";
        case Status::PermissionDenied: return "permission denied";
        case Status::Internal: return "internal error";
    }
    return "unknown";
}

std::string Result::to_string() const {
    std::string s = status_name(status_);
    if (!message_.empty()) {
        s += ": ";
        s += message_;
    }
    return s;
}

}  // namespace vajra
