// Vajra Binary Core - stop-the-world, Linux implementation (real-time signal).
// SPDX-License-Identifier: MIT
#include "stop.hpp"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include <atomic>
#include <climits>
#include <cstring>
#include <string>

#include "sys.hpp"

namespace vajra::detail {

namespace {

constexpr int kMaxThreads = 8192;

struct Slot {
    std::atomic<int> tid{0};
    std::atomic<std::uintptr_t> pc{0};
    std::atomic<std::uintptr_t> sp{0};
};

Slot g_slots[kMaxThreads];
std::atomic<std::uint32_t> g_slot_next{0};
std::atomic<std::uint32_t> g_arrived{0};
std::atomic<std::uint32_t> g_departed{0};
std::atomic<std::uint32_t> g_release{0};
std::atomic<std::uint32_t> g_gen{0};
std::atomic<bool> g_active{false};
std::atomic<int> g_inflight{0};
std::atomic<int> g_signal{0};
std::size_t g_stopped = 0;

// Stopper-only state (the stopper is serialized by the patch mutex).
pid_t g_known[kMaxThreads];
bool g_known_dead[kMaxThreads];
int g_known_count = 0;
pid_t g_listed[kMaxThreads];
alignas(8) char g_dirbuf[32768];

static_assert(sizeof(std::atomic<std::uint32_t>) == sizeof(std::uint32_t), "futex word layout");

const volatile std::uint32_t* word(const std::atomic<std::uint32_t>& a) {
    return reinterpret_cast<const volatile std::uint32_t*>(&a);
}

void stop_handler(int, siginfo_t* si, void* ucv) {
    const int saved_errno = errno;
    g_inflight.fetch_add(1, std::memory_order_seq_cst);
    if (si != nullptr && si->si_code == SI_QUEUE && si->si_pid == sys::raw_getpid() &&
        g_active.load(std::memory_order_seq_cst) &&
        static_cast<std::uint32_t>(si->si_value.sival_int) == g_gen.load(std::memory_order_seq_cst)) {
        const std::uint32_t gen = static_cast<std::uint32_t>(si->si_value.sival_int);
        const auto* uc = static_cast<const ucontext_t*>(ucv);
        const std::uint32_t idx = g_slot_next.fetch_add(1, std::memory_order_relaxed);
        if (idx < static_cast<std::uint32_t>(kMaxThreads)) {
            g_slots[idx].pc.store(static_cast<std::uintptr_t>(uc->uc_mcontext.gregs[REG_RIP]),
                                  std::memory_order_relaxed);
            g_slots[idx].sp.store(static_cast<std::uintptr_t>(uc->uc_mcontext.gregs[REG_RSP]),
                                  std::memory_order_relaxed);
            g_slots[idx].tid.store(sys::current_tid(), std::memory_order_release);
        }
        g_arrived.fetch_add(1, std::memory_order_acq_rel);
        sys::raw_futex_wake(word(g_arrived), INT_MAX);
        for (;;) {
            const std::uint32_t r = g_release.load(std::memory_order_acquire);
            if (r == gen) break;
            sys::raw_futex_wait(word(g_release), r, -1);
        }
        sys::cpu_serialize();  // code may have been modified by another core
        g_departed.fetch_add(1, std::memory_order_acq_rel);
        sys::raw_futex_wake(word(g_departed), INT_MAX);
    }
    g_inflight.fetch_sub(1, std::memory_order_seq_cst);
    errno = saved_errno;
}

// Formats "/proc/self/task/<tid>/stat" without allocating.
void task_stat_path(pid_t tid, char* out) {
    const char prefix[] = "/proc/self/task/";
    std::memcpy(out, prefix, sizeof prefix - 1);
    char digits[16];
    int n = 0;
    unsigned v = static_cast<unsigned>(tid);
    do {
        digits[n++] = static_cast<char>('0' + v % 10);
        v /= 10;
    } while (v != 0);
    char* p = out + sizeof prefix - 1;
    while (n > 0) *p++ = digits[--n];
    std::memcpy(p, "/stat", 6);
}

// True if the thread no longer exists or is a zombie (signal-safe).
bool thread_dead(pid_t tid) {
    char path[64];
    task_stat_path(tid, path);
    const long fd = sys::raw_syscall(SYS_openat, AT_FDCWD, reinterpret_cast<long>(path), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fd == -ENOENT || fd == -ESRCH;
    char buf[512];
    const long n = sys::raw_syscall(SYS_read, fd, reinterpret_cast<long>(buf), sizeof buf - 1);
    sys::raw_syscall(SYS_close, fd);
    if (n <= 0) return n == -ESRCH;
    buf[n] = 0;
    const char* close_paren = nullptr;
    for (long i = 0; i < n; ++i)
        if (buf[i] == ')') close_paren = buf + i;
    if (!close_paren || close_paren + 2 >= buf + n) return false;
    const char state = close_paren[2];
    return state == 'Z' || state == 'X' || state == 'x';
}

// Lists thread ids of this process into g_listed (signal-safe). Returns count or -errno.
int list_tasks() {
    const long fd = sys::raw_syscall(SYS_openat, AT_FDCWD, reinterpret_cast<long>("/proc/self/task"),
                                     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return static_cast<int>(fd);
    int count = 0;
    for (;;) {
        const long n = sys::raw_syscall(SYS_getdents64, fd, reinterpret_cast<long>(g_dirbuf), sizeof g_dirbuf);
        if (n < 0) {
            sys::raw_syscall(SYS_close, fd);
            return static_cast<int>(n);
        }
        if (n == 0) break;
        long pos = 0;
        while (pos < n) {
            // struct linux_dirent64 { u64 ino; s64 off; u16 reclen; u8 type; char name[]; }
            const char* rec = g_dirbuf + pos;
            unsigned short reclen;
            std::memcpy(&reclen, rec + 16, sizeof reclen);
            const char* name = rec + 19;
            if (reclen == 0) break;
            pos += reclen;
            if (name[0] < '0' || name[0] > '9') continue;
            long v = 0;
            for (const char* c = name; *c >= '0' && *c <= '9'; ++c) v = v * 10 + (*c - '0');
            if (count < kMaxThreads) g_listed[count] = static_cast<pid_t>(v);
            ++count;
        }
    }
    sys::raw_syscall(SYS_close, fd);
    return count;
}

bool known(pid_t tid) {
    for (int i = 0; i < g_known_count; ++i)
        if (g_known[i] == tid) return true;
    return false;
}

bool arrived(pid_t tid) {
    const std::uint32_t n = g_slot_next.load(std::memory_order_acquire);
    const std::uint32_t lim = n < static_cast<std::uint32_t>(kMaxThreads) ? n : static_cast<std::uint32_t>(kMaxThreads);
    for (std::uint32_t i = 0; i < lim; ++i)
        if (g_slots[i].tid.load(std::memory_order_acquire) == tid) return true;
    return false;
}

void release_and_drain() noexcept {
    const std::uint32_t gen = g_gen.load(std::memory_order_relaxed);
    g_release.store(gen, std::memory_order_release);
    sys::raw_futex_wake(word(g_release), INT_MAX);
    g_active.store(false, std::memory_order_seq_cst);
    for (;;) {
        const std::uint32_t d = g_departed.load(std::memory_order_acquire);
        const std::uint32_t a = g_arrived.load(std::memory_order_acquire);
        if (d >= a && g_inflight.load(std::memory_order_seq_cst) == 0) break;
        sys::raw_futex_wait(word(g_departed), d, 1000000L);
    }
    g_stopped = 0;
}

}  // namespace

Result set_stop_signal_impl(int sig) {
    if (sig < SIGRTMIN || sig > SIGRTMAX) return {Status::InvalidArgument, "stop signal must be a real-time signal"};
    struct sigaction cur;
    if (::sigaction(sig, nullptr, &cur) != 0) return {Status::InvalidArgument, "invalid signal"};
    g_signal.store(sig);
    return Result::ok();
}

int stop_signal_impl() noexcept {
    int s = g_signal.load();
    return s != 0 ? s : SIGRTMIN + 7;
}

Result install_stop_handler() {
    const int sig = stop_signal_impl();
    struct sigaction old;
    if (::sigaction(sig, nullptr, &old) != 0) return {Status::Internal, "sigaction query failed"};
    if ((old.sa_flags & SA_SIGINFO) && old.sa_sigaction == stop_handler) return Result::ok();
    if (!(old.sa_flags & SA_SIGINFO) && (old.sa_handler == SIG_DFL || old.sa_handler == SIG_IGN)) {
        struct sigaction sa;
        std::memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = stop_handler;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigfillset(&sa.sa_mask);
        if (::sigaction(sig, &sa, nullptr) != 0) return {Status::Internal, "cannot install the stop signal handler"};
        return Result::ok();
    }
    return {Status::Unsupported, "signal " + std::to_string(sig) +
                                     " already has a handler; choose another with vajra::set_stop_signal()"};
}

Result world_stop(int timeout_ms) {
    const int sig = stop_signal_impl();
    const pid_t self = sys::current_tid();
    const pid_t pid = sys::raw_getpid();
    std::uint32_t gen = g_gen.load() + 1;
    if (gen == 0) gen = 1;

    for (auto& s : g_slots) s.tid.store(0, std::memory_order_relaxed);
    g_slot_next.store(0);
    g_arrived.store(0);
    g_departed.store(0);
    g_release.store(0);
    g_known_count = 0;
    g_gen.store(gen, std::memory_order_seq_cst);
    g_active.store(true, std::memory_order_seq_cst);

    const std::uint64_t deadline = sys::monotonic_ns() + static_cast<std::uint64_t>(timeout_ms) * 1000000ull;
    Status fail = Status::Ok;
    long fail_detail = 0;
    int dead_count = 0;

    for (;;) {
        const int listed = list_tasks();
        if (listed < 0) {
            fail = Status::IoError;
            fail_detail = -listed;
            break;
        }
        if (listed > kMaxThreads) {
            fail = Status::Unsupported;
            fail_detail = listed;
            break;
        }
        bool added = false;
        bool retry = false;
        for (int i = 0; i < listed && fail == Status::Ok; ++i) {
            const pid_t tid = g_listed[i];
            if (tid == self || known(tid)) continue;
            siginfo_t info;
            std::memset(&info, 0, sizeof info);
            info.si_signo = sig;
            info.si_code = SI_QUEUE;
            info.si_pid = pid;
            info.si_uid = static_cast<uid_t>(sys::raw_syscall(SYS_getuid));
            info.si_value.sival_int = static_cast<int>(gen);
            const long rc = sys::raw_syscall(SYS_rt_tgsigqueueinfo, pid, tid, sig, reinterpret_cast<long>(&info));
            if (rc == -ESRCH) continue;  // exited meanwhile
            if (rc == -EAGAIN) {         // queued-signal limit; try again next round
                retry = true;
                continue;
            }
            if (rc < 0) {
                fail = Status::Internal;
                fail_detail = -rc;
                break;
            }
            g_known[g_known_count] = tid;
            g_known_dead[g_known_count] = false;
            ++g_known_count;
            added = true;
        }
        if (fail != Status::Ok) break;

        // Wait for every signalled thread to arrive (or die).
        for (;;) {
            const std::uint32_t a = g_arrived.load(std::memory_order_acquire);
            if (static_cast<int>(a) >= g_known_count - dead_count) break;
            if (sys::monotonic_ns() > deadline) {
                fail = Status::Timeout;
                for (int i = 0; i < g_known_count; ++i)
                    if (!g_known_dead[i] && !arrived(g_known[i])) {
                        fail_detail = g_known[i];
                        break;
                    }
                break;
            }
            sys::raw_futex_wait(word(g_arrived), a, 1000000L);  // 1 ms
            for (int i = 0; i < g_known_count; ++i) {
                if (g_known_dead[i] || arrived(g_known[i])) continue;
                if (thread_dead(g_known[i])) {
                    g_known_dead[i] = true;
                    ++dead_count;
                }
            }
        }
        if (fail != Status::Ok) break;
        if (!added && !retry) break;  // a rescan found no new thread: everyone is parked
        if (retry && sys::monotonic_ns() > deadline) {
            fail = Status::Timeout;
            break;
        }
    }

    if (fail != Status::Ok) {
        release_and_drain();  // resume before allocating the message
        switch (fail) {
            case Status::Timeout:
                return {Status::Timeout, fail_detail != 0
                                             ? "thread " + std::to_string(fail_detail) +
                                                   " did not reach the stop handler (signal blocked or thread stuck)"
                                             : "threads did not reach the stop handler in time"};
            case Status::Unsupported:
                return {Status::Unsupported, "too many threads (" + std::to_string(fail_detail) + ")"};
            default:
                return {fail, std::string("stopping threads failed: ") + std::strerror(static_cast<int>(fail_detail))};
        }
    }
    const std::uint32_t n = g_slot_next.load(std::memory_order_acquire);
    g_stopped = n < static_cast<std::uint32_t>(kMaxThreads) ? n : static_cast<std::uint32_t>(kMaxThreads);
    return Result::ok();
}

void world_resume() noexcept { release_and_drain(); }

std::size_t world_stopped_count() noexcept { return g_stopped; }

StoppedThread world_stopped_thread(std::size_t i) noexcept {
    StoppedThread t;
    if (i >= g_stopped) return t;
    t.tid = g_slots[i].tid.load(std::memory_order_acquire);
    t.pc = g_slots[i].pc.load(std::memory_order_relaxed);
    t.sp = g_slots[i].sp.load(std::memory_order_relaxed);
    return t;
}

}  // namespace vajra::detail
