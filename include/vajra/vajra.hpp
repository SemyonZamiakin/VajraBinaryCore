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
// specialised by inter-procedural optimisation, and kept in the symbol table
// with its size, which the hook engine needs to verify the function body.
#if defined(__clang__)
#define VAJRA_PATCHABLE __attribute__((noinline, used, visibility("default")))
#else
#define VAJRA_PATCHABLE __attribute__((noinline, noipa, used, visibility("default")))
#endif
