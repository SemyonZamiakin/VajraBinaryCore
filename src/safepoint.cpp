// Vajra Binary Core - cooperative safe points.
// SPDX-License-Identifier: MIT
#include "vajra/safepoint.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>

#include "stop.hpp"
#include "sys.hpp"

namespace vajra {

namespace detail {

std::atomic<bool> g_safepoint_requested{false};

namespace {

enum class State { Running, Parked, Region };

struct Record {
    pid_t tid = 0;
    State state = State::Running;
};

struct Registry {
    std::mutex mu;
    std::condition_variable cv;
    std::vector<Record*> records;
    bool stopped = false;
    const Record* requester = nullptr;  // record of the stopping thread, if attached
    pid_t requester_tid = 0;
};

Registry& registry() {
    static Registry* r = new Registry;  // never destroyed: threads may detach during exit
    return *r;
}

thread_local Record* t_record = nullptr;

bool is_requester(const Registry& r) { return r.stopped && r.requester_tid == sys::raw_gettid(); }

// Parks the current (attached) thread while a stop is in progress. Called with the lock held.
void park_locked(Registry& r, std::unique_lock<std::mutex>& lk, State while_parked) {
    Record* rec = t_record;
    rec->state = while_parked;
    r.cv.notify_all();
    r.cv.wait(lk, [&] { return !r.stopped || is_requester(r); });
    rec->state = State::Running;
}

}  // namespace

void safepoint_slow() noexcept {
    Registry& r = registry();
    if (t_record == nullptr) return;
    std::unique_lock<std::mutex> lk(r.mu);
    if (!r.stopped || is_requester(r)) return;
    park_locked(r, lk, State::Parked);
    lk.unlock();
    sys::cpu_serialize();  // pick up code modified while parked
}

Result coop_stop(int timeout_ms) {
    Registry& r = registry();
    std::unique_lock<std::mutex> lk(r.mu);
    r.stopped = true;
    r.requester = t_record;
    r.requester_tid = sys::raw_gettid();
    g_safepoint_requested.store(true, std::memory_order_release);
    auto all_safe = [&] {
        for (const Record* rec : r.records)
            if (rec != r.requester && rec->state == State::Running) return false;
        return true;
    };
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    if (!r.cv.wait_until(lk, deadline, all_safe)) {
        std::size_t running = 0;
        pid_t example = 0;
        for (const Record* rec : r.records)
            if (rec != r.requester && rec->state == State::Running) {
                ++running;
                example = rec->tid;
            }
        r.stopped = false;
        r.requester = nullptr;
        r.requester_tid = 0;
        g_safepoint_requested.store(false, std::memory_order_release);
        r.cv.notify_all();
        return {Status::Timeout, std::to_string(running) + " attached thread(s) did not reach a safe point (e.g. tid " +
                                     std::to_string(example) + ")"};
    }
    return Result::ok();
}

void coop_resume() noexcept {
    Registry& r = registry();
    std::lock_guard<std::mutex> g(r.mu);
    r.stopped = false;
    r.requester = nullptr;
    r.requester_tid = 0;
    g_safepoint_requested.store(false, std::memory_order_release);
    r.cv.notify_all();
}

}  // namespace detail

using detail::registry;

void Safepoints::attach() {
    auto& r = registry();
    std::unique_lock<std::mutex> lk(r.mu);
    if (detail::t_record) return;
    auto* rec = new detail::Record;
    rec->tid = sys::raw_gettid();
    r.records.push_back(rec);
    detail::t_record = rec;
    if (r.stopped && !detail::is_requester(r)) detail::park_locked(r, lk, detail::State::Parked);
}

void Safepoints::detach() noexcept {
    auto& r = registry();
    std::lock_guard<std::mutex> g(r.mu);
    detail::Record* rec = detail::t_record;
    if (!rec) return;
    r.records.erase(std::remove(r.records.begin(), r.records.end(), rec), r.records.end());
    if (r.requester == rec) r.requester = nullptr;
    detail::t_record = nullptr;
    delete rec;
    r.cv.notify_all();
}

bool Safepoints::attached() noexcept { return detail::t_record != nullptr; }

std::size_t Safepoints::attached_count() noexcept {
    auto& r = registry();
    std::lock_guard<std::mutex> g(r.mu);
    return r.records.size();
}

void Safepoints::enter_region() noexcept {
    detail::Record* rec = detail::t_record;
    if (!rec) return;
    auto& r = registry();
    std::lock_guard<std::mutex> g(r.mu);
    rec->state = detail::State::Region;
    r.cv.notify_all();
}

void Safepoints::leave_region() noexcept {
    detail::Record* rec = detail::t_record;
    if (!rec) return;
    auto& r = registry();
    std::unique_lock<std::mutex> lk(r.mu);
    r.cv.wait(lk, [&] { return !r.stopped || detail::is_requester(r); });
    rec->state = detail::State::Running;
    lk.unlock();
    sys::cpu_serialize();
}

}  // namespace vajra
