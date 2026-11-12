// Vajra Binary Core - stop-the-world, Windows implementation.
//
// Threads are enumerated with NtGetNextThread (a system call that needs no
// user-mode heap or loader lock), suspended with SuspendThread, and their
// context read with GetThreadContext, which also waits until the suspension
// has actually taken effect. Enumeration repeats until a full pass finds no
// new thread, so threads created by not-yet-suspended threads are caught.
// SPDX-License-Identifier: MIT
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>

#include "stop.hpp"
#include "sys.hpp"

namespace vajra::detail {

namespace {

using NtGetNextThreadFn = LONG(NTAPI*)(HANDLE process, HANDLE thread, ACCESS_MASK access, ULONG attributes,
                                       ULONG flags, PHANDLE next);

constexpr int kMaxThreads = 8192;
NtGetNextThreadFn g_next_thread = nullptr;

struct Entry {
    HANDLE handle;
    DWORD tid;
    std::uintptr_t pc;
    std::uintptr_t sp;
};
Entry g_threads[kMaxThreads];
std::size_t g_count = 0;

bool known(DWORD tid) {
    for (std::size_t i = 0; i < g_count; ++i)
        if (g_threads[i].tid == tid) return true;
    return false;
}

void resume_all() noexcept {
    for (std::size_t i = 0; i < g_count; ++i) {
        ::ResumeThread(g_threads[i].handle);
        ::CloseHandle(g_threads[i].handle);
    }
    g_count = 0;
}

}  // namespace

Result set_stop_signal_impl(int) { return {Status::Unsupported, "Windows does not use a stop signal"}; }
int stop_signal_impl() noexcept { return 0; }

Result install_stop_handler() {
    if (g_next_thread) return Result::ok();
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
        g_next_thread = reinterpret_cast<NtGetNextThreadFn>(
            reinterpret_cast<void*>(::GetProcAddress(ntdll, "NtGetNextThread")));
    if (!g_next_thread) return {Status::Unsupported, "NtGetNextThread is not available (Windows Vista or newer required)"};
    return Result::ok();
}

Result world_stop(int) {
    if (Result r = install_stop_handler(); !r) return r;
    const DWORD self = ::GetCurrentThreadId();
    const HANDLE process = ::GetCurrentProcess();
    const ACCESS_MASK access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION;
    g_count = 0;
    Status fail = Status::Ok;
    DWORD fail_detail = 0;

    for (;;) {
        bool added = false;
        HANDLE cursor = nullptr;
        bool cursor_kept = false;
        for (;;) {
            HANDLE next = nullptr;
            const LONG st = g_next_thread(process, cursor, access, 0, 0, &next);
            if (cursor && !cursor_kept) ::CloseHandle(cursor);
            cursor = nullptr;
            if (st != 0) break;  // STATUS_NO_MORE_ENTRIES (or an error): end of this pass
            cursor = next;
            cursor_kept = false;
            const DWORD tid = ::GetThreadId(next);
            if (tid == 0 || tid == self || known(tid)) continue;
            if (g_count == static_cast<std::size_t>(kMaxThreads)) {
                fail = Status::Unsupported;
                break;
            }
            if (::SuspendThread(next) == static_cast<DWORD>(-1)) continue;  // exiting thread
            CONTEXT ctx;
            ZeroMemory(&ctx, sizeof ctx);
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (!::GetThreadContext(next, &ctx)) {
                // A thread that cannot report its context could be anywhere: refuse.
                ::ResumeThread(next);
                fail = Status::Internal;
                fail_detail = tid;
                break;
            }
            g_threads[g_count++] = {next, tid, static_cast<std::uintptr_t>(ctx.Rip),
                                    static_cast<std::uintptr_t>(ctx.Rsp)};
            cursor_kept = true;
            added = true;
        }
        if (cursor && !cursor_kept) ::CloseHandle(cursor);
        if (fail != Status::Ok || !added) break;  // a full pass found no new thread
    }

    if (fail != Status::Ok) {
        resume_all();  // before building any message
        if (fail == Status::Unsupported) return {Status::Unsupported, "too many threads"};
        return {Status::Internal, "cannot read the context of thread " + std::to_string(fail_detail)};
    }
    return Result::ok();
}

void world_resume() noexcept { resume_all(); }

std::size_t world_stopped_count() noexcept { return g_count; }

StoppedThread world_stopped_thread(std::size_t i) noexcept {
    StoppedThread t;
    if (i >= g_count) return t;
    t.tid = static_cast<long>(g_threads[i].tid);
    t.pc = g_threads[i].pc;
    t.sp = g_threads[i].sp;
    return t;
}

}  // namespace vajra::detail
