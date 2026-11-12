/* Hand-written hook targets for Windows x64 (Microsoft calling convention:
   first argument in ecx). The .seh_proc / .seh_endproc directives give every
   function a .pdata entry, which is where Vajra reads function bounds on
   Windows. Same functions as asm_targets.S, minus asm_block, plus asm_window.
   SPDX-License-Identifier: MIT */
    .intel_syntax noprefix
    .text

/* int asm_rip(int x): asm_rip_data + x. Prologue is a RIP-relative load. */
    .globl asm_rip
    .def asm_rip; .scl 2; .type 32; .endef
    .p2align 4
    .seh_proc asm_rip
asm_rip:
    .seh_endprologue
    mov eax, DWORD PTR [rip + asm_rip_data]
    add eax, ecx
    ret
    .seh_endproc

/* int asm_jcc(int x): x == 0 ? 100 : x + 1. Prologue: test, je rel8, lea. */
    .globl asm_jcc
    .def asm_jcc; .scl 2; .type 32; .endef
    .p2align 4
    .seh_proc asm_jcc
asm_jcc:
    .seh_endprologue
    test ecx, ecx
    je 1f
    lea eax, [rcx + 1]
    ret
1:  mov eax, 100
    ret
    .seh_endproc

/* int asm_call(int x): 1000 + x. Prologue: call rel32. */
    .globl asm_call
    .def asm_call; .scl 2; .type 32; .endef
    .p2align 4
    .seh_proc asm_call
asm_call:
    .seh_endprologue
    call asm_helper
    add eax, ecx
    ret
    .seh_endproc

    .def asm_helper; .scl 3; .type 32; .endef
    .seh_proc asm_helper
asm_helper:
    .seh_endprologue
    mov eax, 1000
    ret
    .seh_endproc

/* int asm_loopback(int n): branches back into the first 5 bytes: refused. */
    .globl asm_loopback
    .def asm_loopback; .scl 2; .type 32; .endef
    .p2align 4
    .seh_proc asm_loopback
asm_loopback:
    .seh_endprologue
    xor eax, eax
2:  add eax, 1
    cmp eax, ecx
    jl 2b
    ret
    .seh_endproc

/* int asm_short(void): 0. Only 3 bytes long, followed by int3 padding. */
    .globl asm_short
    .def asm_short; .scl 2; .type 32; .endef
    .p2align 4
    .seh_proc asm_short
asm_short:
    .seh_endprologue
    xor eax, eax
    ret
    .seh_endproc
    .byte 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc

/* int asm_window(void): 7. Five nops first; the busy test parks a suspended
   thread at asm_window+2, inside the bytes a hook overwrites. */
    .globl asm_window
    .def asm_window; .scl 2; .type 32; .endef
    .p2align 4
    .seh_proc asm_window
asm_window:
    .seh_endprologue
    nop
    nop
    nop
    nop
    nop
    mov eax, 7
    ret
    .seh_endproc

    .data
    .globl asm_rip_data
    .p2align 2
asm_rip_data:
    .long 5
