// Minimal self-contained test harness (no external dependencies).
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace check {

struct Case {
    const char* name;
    void (*fn)();
};

inline std::vector<Case>& cases() {
    static std::vector<Case> c;
    return c;
}
inline int& failures() {
    static int f = 0;
    return f;
}
inline const char*& current() {
    static const char* c = "";
    return c;
}

struct Registrar {
    Registrar(const char* name, void (*fn)()) { cases().push_back({name, fn}); }
};

inline void report(const char* file, int line, const std::string& what) {
    ++failures();
    std::fprintf(stderr, "  FAIL %s (%s:%d): %s\n", current(), file, line, what.c_str());
}

inline int run_all(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int ran = 0;
    for (const auto& c : cases()) {
        if (filter && !std::strstr(c.name, filter)) continue;
        current() = c.name;
        const int before = failures();
        c.fn();
        ++ran;
        std::fprintf(stderr, "%s %s\n", failures() == before ? "  ok  " : "  FAIL", c.name);
    }
    std::fprintf(stderr, "%d test(s), %d failure(s)\n", ran, failures());
    return failures() == 0 && ran > 0 ? 0 : 1;
}

}  // namespace check

#define TEST(name)                                                    \
    static void name();                                               \
    static ::check::Registrar name##_registrar(#name, &name);         \
    static void name()

#define CHECK(cond)                                                                    \
    do {                                                                               \
        if (!(cond)) ::check::report(__FILE__, __LINE__, "CHECK(" #cond ") failed");  \
    } while (0)

#define CHECK_EQ(a, b)                                                                              \
    do {                                                                                            \
        const auto va_ = (a);                                                                       \
        const auto vb_ = (b);                                                                       \
        if (!(va_ == vb_))                                                                          \
            ::check::report(__FILE__, __LINE__,                                                     \
                            std::string(#a " == " #b " failed: ") + std::to_string(va_) + " vs " +  \
                                std::to_string(vb_));                                               \
    } while (0)

#define CHECK_OK(expr)                                                                           \
    do {                                                                                         \
        const ::vajra::Result r_ = (expr);                                                       \
        if (!r_.is_ok()) ::check::report(__FILE__, __LINE__, #expr " -> " + r_.to_string());     \
    } while (0)

#define CHECK_STATUS(expr, st)                                                                     \
    do {                                                                                           \
        const ::vajra::Result r_ = (expr);                                                         \
        if (r_.status() != (st))                                                                   \
            ::check::report(__FILE__, __LINE__,                                                    \
                            #expr " -> " + r_.to_string() + " (expected " + ::vajra::status_name(st) + ")"); \
    } while (0)

#define TEST_MAIN() \
    int main(int argc, char** argv) { return ::check::run_all(argc, argv); }
