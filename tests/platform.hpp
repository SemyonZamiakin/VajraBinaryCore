// Small portability helpers for the tests.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdio>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

namespace testplat {

// Sleeps without taking user-mode locks other threads may hold (usable while
// the world is stopped).
inline void raw_sleep_ms(int ms) {
#if defined(_WIN32)
    ::Sleep(static_cast<DWORD>(ms));
#else
    struct timespec ts{0, static_cast<long>(ms) * 1000 * 1000};
    ::syscall(SYS_nanosleep, &ts, nullptr);
#endif
}

inline long current_tid() {
#if defined(_WIN32)
    return static_cast<long>(::GetCurrentThreadId());
#else
    return static_cast<long>(::syscall(SYS_gettid));
#endif
}

// Address of a C runtime function (bypasses compiler builtins).
inline void* crt_function(const char* name) {
#if defined(_WIN32)
    HMODULE crt = ::LoadLibraryA("msvcrt.dll");
    return crt ? reinterpret_cast<void*>(::GetProcAddress(crt, name)) : nullptr;
#else
    return ::dlsym(RTLD_DEFAULT, name);
#endif
}

// Runs a command, returns its output; *status receives the exit code.
inline std::string run(const std::string& cmd, int* status = nullptr) {
    std::string out;
#if defined(_WIN32)
    // cmd.exe strips one level of outer quotes.
    FILE* p = ::_popen(("\"" + cmd + "\"").c_str(), "r");
#else
    FILE* p = ::popen(cmd.c_str(), "r");
#endif
    if (!p) return out;
    char buf[512];
    while (std::fgets(buf, sizeof buf, p)) out += buf;
#if defined(_WIN32)
    const int st = ::_pclose(p);
    if (status) *status = st;
#else
    const int st = ::pclose(p);
    if (status) *status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
#endif
    return out;
}

inline std::string quote(const std::string& s) { return "\"" + s + "\""; }

}  // namespace testplat
