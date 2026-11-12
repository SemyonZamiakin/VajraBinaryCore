// Vajra Binary Core - umbrella header.
// SPDX-License-Identifier: MIT
#pragma once

#include "vajra/agent.hpp"
#include "vajra/migrate.hpp"
#include "vajra/options.hpp"
#include "vajra/patch.hpp"
#include "vajra/relocate.hpp"
#include "vajra/safepoint.hpp"
#include "vajra/status.hpp"
#include "vajra/types.hpp"
#include "vajra/x86.hpp"

// Marks a function as a hot-patch target: never inlined, never cloned or
// specialised by inter-procedural optimisation, and visible by name (symbol
// table on Linux, export table on Windows) so patch modules can find it.
#if defined(_WIN32)
#define VAJRA_EXPORT_SYMBOL __declspec(dllexport)
#else
#define VAJRA_EXPORT_SYMBOL __attribute__((visibility("default")))
#endif
#if defined(__clang__)
#define VAJRA_PATCHABLE VAJRA_EXPORT_SYMBOL __attribute__((noinline, used))
#else
#define VAJRA_PATCHABLE VAJRA_EXPORT_SYMBOL __attribute__((noinline, noipa, used))
#endif
