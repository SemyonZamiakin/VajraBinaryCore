// Vajra Binary Core - status codes and results.
// SPDX-License-Identifier: MIT
#pragma once

#include <string>
#include <utility>

namespace vajra {

enum class Status : int {
    Ok = 0,
    InvalidArgument,  // bad pointer, empty name, inconsistent options
    Unsupported,      // valid request this engine refuses to handle safely
    DecodeFailed,     // instruction decoder could not decode the bytes
    RelocationFailed, // prologue cannot be relocated safely
    OutOfRange,       // rel32 target or near allocation out of +-2 GiB
    Busy,             // a thread kept executing inside bytes to be rewritten
    Timeout,          // threads did not reach a safe point in time
    NoMemory,
    ProtectFailed,    // mprotect failed
    WriteFailed,      // code/data write failed
    Mismatch,         // memory did not contain the expected bytes
    NotFound,
    AlreadyApplied,
    NotApplied,
    NotRevertible,
    MigrationFailed,  // a value did not convert or a transform failed
    VersionMismatch,  // live type version differs from the plan
    IoError,
    PermissionDenied,
    Internal,
};

const char* status_name(Status s) noexcept;

// A status plus a human-readable explanation. Cheap when Ok.
class Result {
public:
    Result() = default;
    Result(Status s) : status_(s) {}  // NOLINT(google-explicit-constructor)
    Result(Status s, std::string msg) : status_(s), message_(std::move(msg)) {}

    static Result ok() { return Result(); }

    bool is_ok() const noexcept { return status_ == Status::Ok; }
    explicit operator bool() const noexcept { return is_ok(); }
    Status status() const noexcept { return status_; }
    const std::string& message() const noexcept { return message_; }
    std::string to_string() const;

private:
    Status status_ = Status::Ok;
    std::string message_;
};

}  // namespace vajra
