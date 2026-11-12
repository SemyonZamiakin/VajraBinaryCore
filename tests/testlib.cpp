// Shared library called through the PLT/GOT by test_got.
// SPDX-License-Identifier: MIT
extern "C" __attribute__((visibility("default"))) int testlib_value(int x) { return x + 1; }
extern "C" __attribute__((visibility("default"))) int testlib_other(int x) { return x * 2; }
