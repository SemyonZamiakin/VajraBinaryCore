// Vajra Binary Core - one type migration inside a patch transaction (internal).
//
// Lifecycle, driven by the transaction engine while all mutator threads are
// parked at safe points and the heap mutex is held:
//   prepare()  - allocates and fills the new objects, plans every pointer
//                fix-up and validates everything. May fail; nothing visible
//                has changed at that point.
//   commit()   - applies the planned pointer writes and swaps the objects in
//                the heap. Cannot fail and does not allocate or free memory,
//                so it is safe while other threads are stopped by signal.
//   abort()    - frees the prepared objects (instead of commit).
//   finalize() - after the world is resumed: frees (or quarantines) the old
//                objects.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "vajra/migrate.hpp"

namespace vajra::detail {

class MigrationJob {
public:
    MigrationJob(Heap& heap, const MigrationPlan& plan) : heap_(heap), plan_(plan) {}
    ~MigrationJob();
    MigrationJob(const MigrationJob&) = delete;
    MigrationJob& operator=(const MigrationJob&) = delete;

    std::mutex& heap_mutex() { return heap_.mu_; }
    Heap& heap() { return heap_; }

    Result prepare();
    void commit() noexcept;
    void abort() noexcept;
    void finalize() noexcept;  // locks the heap itself
    std::size_t object_count() const noexcept { return olds_.size(); }

private:
    // Maps an address inside an old object to its new location. Returns false
    // if the address is not inside an old object; sets `bad` if it is, but at
    // an offset that has no destination.
    bool forward(std::uintptr_t v, std::uintptr_t& out, bool& bad) const;

    Heap& heap_;
    const MigrationPlan& plan_;
    Heap::TypeState* ts_ = nullptr;
    std::vector<std::uintptr_t> olds_;  // ascending
    std::vector<std::uintptr_t> news_;
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> writes_;  // slot address, new value
    TypeDesc new_desc_;
    bool prepared_ = false;
    bool committed_ = false;
};

}  // namespace vajra::detail
