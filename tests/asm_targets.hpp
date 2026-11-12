// Declarations for asm_targets.S (Linux) / asm_targets_win.S (Windows).
// SPDX-License-Identifier: MIT
#pragma once

extern "C" {
int asm_rip(int x);
int asm_jcc(int x);
int asm_call(int x);
int asm_loopback(int n);
int asm_short();
#if defined(_WIN32)
int asm_window();
#else
long asm_block(long nr);
#endif
extern int asm_rip_data;
}
