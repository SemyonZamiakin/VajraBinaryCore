// Declarations for asm_targets.S.
// SPDX-License-Identifier: MIT
#pragma once

extern "C" {
int asm_rip(int x);
int asm_jcc(int x);
int asm_call(int x);
int asm_loopback(int n);
int asm_short();
long asm_block(long nr);
extern int asm_rip_data;
}
