// Vajra demo "arena": a long-running, game-like program holding live objects.
//
// Three worker threads tick entities at 100 Hz, a spawner adds one entity per
// second, and a reporter prints the world state every second. The program
// links Vajra and runs an agent, so `vajractl` can hot-patch it while it runs.
// It checks its own invariants on every report and exits non-zero if any
// failed.
//
//   arena --socket /tmp/arena.sock --seconds 30
// SPDX-License-Identifier: MIT
#include <signal.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "arena_abi.hpp"

using arena::EntityV1;
using arena::Summary;

namespace {

constexpr int kWorkers = 3;
constexpr int kInitial = 128;
constexpr int kMaxEntities = 192;

void* g_slots[kMaxEntities];            // roots: the only long-lived pointers to entities
std::atomic<int> g_count{0};
std::atomic<bool> g_quit{false};
std::atomic<long> g_errors{0};

struct WorkerState {
    std::mutex mu;
    Summary summary;
    std::uint64_t ticks = 0;
};
WorkerState g_workers[kWorkers];

void on_signal(int) { g_quit.store(true); }

}  // namespace

// ------------------------------------------------------------ v1 game code

extern "C" VAJRA_PATCHABLE void* spawn_entity(vajra::Heap* heap, std::uint32_t id, void* target) {
    auto* e = static_cast<EntityV1*>(heap->allocate("Entity", 1));
    if (!e) return nullptr;  // e.g. stale v1 code after a migration
    e->id = id;
    e->hp = 100;
    e->x = static_cast<float>((id * 37) % 100);
    e->y = static_cast<float>((id * 61) % 100);
    e->vx = static_cast<float>(static_cast<int>(id % 7) - 3) * 4.0f;
    e->vy = static_cast<float>(static_cast<int>(id % 5) - 2) * 4.0f;
    e->level = 1 + static_cast<std::int32_t>(id % 4);
    e->target = static_cast<EntityV1*>(target ? target : e);
    return e;
}

// v1 bug: damage grows far too fast with the level.
extern "C" VAJRA_PATCHABLE int damage_formula(int level) {
    int d = level * 9;
    __asm__ volatile("" : "+r"(d));
    return d;
}

extern "C" VAJRA_PATCHABLE void tick_entity(void* p, std::uint64_t tick) {
    auto* e = static_cast<EntityV1*>(p);
    e->x += e->vx * 0.01f;
    e->y += e->vy * 0.01f;
    if (e->x < 0 || e->x > 100) e->vx = -e->vx;
    if (e->y < 0 || e->y > 100) e->vy = -e->vy;
    if (tick % 25 == e->id % 25) {
        e->hp -= damage_formula(e->level);
        if (e->hp <= 0) {
            e->hp = 100;
            ++e->deaths;
        }
    }
}

extern "C" VAJRA_PATCHABLE void entity_summary(const void* p, vajra::Heap* heap, Summary* s) {
    const auto* e = static_cast<const EntityV1*>(p);
    s->version = 1;
    s->health += e->hp;
    s->deaths += e->deaths;
    s->count += 1;
    s->idsum += e->id;
    if (heap->owns(e->target)) s->refs_ok += 1;
    if (e->id == arena::kSampleId) {
        s->sample_valid = 1;
        s->sample_id = e->id;
        s->sample_health = e->hp;
        s->sample_x = e->x;
        s->sample_y = e->y;
        s->sample_shield = -1;  // v1 has no shields
    }
}

// ------------------------------------------------------------ threads

namespace {

void worker(int w, vajra::Heap* heap) {
    vajra::ScopedAttach attach;
    std::uint64_t tick = 0;
    while (!g_quit.load()) {
        vajra::Safepoints::poll();  // patches and migrations happen here
        Summary s;
        const int n = g_count.load(std::memory_order_acquire);
        for (int i = w; i < n; i += kWorkers) {
            tick_entity(g_slots[i], tick);
            entity_summary(g_slots[i], heap, &s);
        }
        ++tick;
        {
            std::lock_guard<std::mutex> g(g_workers[w].mu);
            g_workers[w].summary = s;
            g_workers[w].ticks = tick;
        }
        vajra::BlockingRegion idle;  // sleeping threads do not delay a patch
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void spawner(vajra::Heap* heap) {
    vajra::ScopedAttach attach;
    while (!g_quit.load()) {
        {
            vajra::BlockingRegion idle;
            for (int i = 0; i < 10 && !g_quit.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        vajra::Safepoints::poll();
        const int n = g_count.load();
        if (n >= kMaxEntities) continue;
        void* e = spawn_entity(heap, static_cast<std::uint32_t>(n), g_slots[0]);
        if (!e) {
            std::printf("ERROR: spawn_entity failed (stale code for the current layout?)\n");
            g_errors.fetch_add(1);
            continue;
        }
        g_slots[n] = e;
        g_count.store(n + 1, std::memory_order_release);
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::string socket_path = "arena.sock";
    int seconds = 0;  // 0: until SIGINT / SIGTERM
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!std::strcmp(argv[i], "--socket")) socket_path = argv[i + 1];
        else if (!std::strcmp(argv[i], "--seconds")) seconds = std::atoi(argv[i + 1]);
    }
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    vajra::Heap heap;
    if (vajra::Result r = heap.register_type(arena::entity_v1()); !r) {
        std::printf("register_type: %s\n", r.to_string().c_str());
        return 1;
    }
    for (int i = 0; i < kInitial; ++i) g_slots[i] = spawn_entity(&heap, static_cast<std::uint32_t>(i), nullptr);
    for (int i = 0; i < kInitial; ++i)  // each entity follows the next one
        static_cast<EntityV1*>(g_slots[i])->target = static_cast<EntityV1*>(g_slots[(i + 1) % kInitial]);
    g_count.store(kInitial);
    heap.add_root_range(g_slots, kMaxEntities);

    vajra::Agent agent;
    vajra::Agent::Options ao;
    ao.socket_path = socket_path;
    ao.heap = &heap;
    if (vajra::Result r = agent.start(ao); !r) {
        std::printf("agent: %s\n", r.to_string().c_str());
        return 1;
    }
    std::printf("arena: pid %d, %d entities, agent on %s\n", static_cast<int>(getpid()), kInitial,
                socket_path.c_str());

    std::vector<std::thread> threads;
    for (int w = 0; w < kWorkers; ++w) threads.emplace_back(worker, w, &heap);
    threads.emplace_back(spawner, &heap);

    // Reporter (main thread).
    const auto start = std::chrono::steady_clock::now();
    std::uint64_t last_ticks = 0;
    int reports = 0;
    long failures = 0;
    int last_version = 0;
    std::string versions;
    while (!g_quit.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));  // not attached: touches no entities
        const double t = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        Summary all;
        std::uint64_t ticks = 0;
        int version = 0;
        bool mixed = false;
        for (auto& w : g_workers) {
            std::lock_guard<std::mutex> g(w.mu);
            const Summary& s = w.summary;
            all.health += s.health;
            all.deaths += s.deaths;
            all.count += s.count;
            all.refs_ok += s.refs_ok;
            all.idsum += s.idsum;
            if (s.sample_valid) {
                all.sample_valid = 1;
                all.sample_id = s.sample_id;
                all.sample_health = s.sample_health;
                all.sample_x = s.sample_x;
                all.sample_y = s.sample_y;
                all.sample_shield = s.sample_shield;
            }
            if (version != 0 && s.version != version) mixed = true;
            version = s.version;
            ticks += w.ticks;
        }
        ++reports;
        // Invariants: every entity is accounted for exactly once, every target
        // reference points to a live object, and the simulation keeps running.
        const std::int64_t n = all.count;
        const bool ids_ok = all.idsum == n * (n - 1) / 2;
        const bool refs_ok = all.refs_ok == n;
        const bool running = ticks > last_ticks;
        // Right after a patch, workers that have not ticked yet still report the
        // old layout version; that is expected and not a failure.
        const bool ok = ids_ok && refs_ok && running && n >= kInitial;
        if (!ok) ++failures;
        if (!mixed && version != last_version) {
            versions += versions.empty() ? "" : " -> ";
            versions += "v" + std::to_string(version);
            last_version = version;
        }
        last_ticks = ticks;
        char shield[16];
        if (all.sample_shield >= 0) std::snprintf(shield, sizeof shield, "%d", all.sample_shield);
        else std::snprintf(shield, sizeof shield, "-");
        std::printf("[%5.1fs] layout v%d  ticks %6llu  entities %3lld  total health %8.0f  deaths %5lld  "
                    "#%u hp %5.1f pos (%5.1f,%5.1f) shield %s  %s%s\n",
                    t, version, static_cast<unsigned long long>(ticks), static_cast<long long>(n), all.health,
                    static_cast<long long>(all.deaths), all.sample_id, all.sample_health, all.sample_x, all.sample_y,
                    shield, ok ? "ok" : "INVARIANT FAILED", mixed ? " (layout change in progress)" : "");
        if (seconds > 0 && t >= seconds) g_quit.store(true);
    }
    for (auto& th : threads) th.join();
    agent.stop();
    const long errors = g_errors.load();
    std::printf("arena: %d reports, layouts %s, invariant failures %ld, errors %ld\n", reports, versions.c_str(),
                failures, errors);
    return failures == 0 && errors == 0 ? 0 : 1;
}
