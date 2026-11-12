// Shared library called through the PLT/GOT (Linux) or the IAT (Windows) by test_got.
// SPDX-License-Identifier: MIT
#if defined(_WIN32)
#define TESTLIB_API extern "C" __declspec(dllexport)
#else
#define TESTLIB_API extern "C" __attribute__((visibility("default")))
#endif

TESTLIB_API int testlib_value(int x) { return x + 1; }
TESTLIB_API int testlib_other(int x) { return x * 2; }
