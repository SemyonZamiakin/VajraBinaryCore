/* Hand-written hook targets with prologues the relocator must handle (or refuse).
   SPDX-License-Identifier: MIT */
    .intel_syntax noprefix
    .text

/* int asm_rip(int x): returns asm_rip_data + x. Prologue is a RIP-relative load. */
    .globl asm_rip
    .type asm_rip, @function
    .p2align 4
asm_rip:
    mov eax, DWORD PTR [rip + asm_rip_data]
    add eax, edi
    ret
    .size asm_rip, .-asm_rip

/* int asm_jcc(int x): x == 0 ? 100 : x + 1. Prologue: test, je rel8, lea. */
    .globl asm_jcc
    .type asm_jcc, @function
    .p2align 4
asm_jcc:
    test edi, edi
    je 1f
    lea eax, [rdi + 1]
    ret
1:  mov eax, 100
    ret
    .size asm_jcc, .-asm_jcc

/* int asm_call(int x): 1000 + x. Prologue: call rel32 (returns after the patch). */
    .globl asm_call
    .type asm_call, @function
    .p2align 4
asm_call:
    call asm_helper
    add eax, edi
    ret
    .size asm_call, .-asm_call

    .type asm_helper, @function
asm_helper:
    mov eax, 1000
    ret
    .size asm_helper, .-asm_helper

/* int asm_loopback(int n): the loop branches back to +2, inside the bytes a
   hook would overwrite. Hooking must be refused. */
    .globl asm_loopback
    .type asm_loopback, @function
    .p2align 4
asm_loopback:
    xor eax, eax
2:  add eax, 1
    cmp eax, edi
    jl 2b
    ret
    .size asm_loopback, .-asm_loopback

/* int asm_short(void): 0. Only 3 bytes long, followed by int3 padding. */
    .globl asm_short
    .type asm_short, @function
    .p2align 4
asm_short:
    xor eax, eax
    ret
    .size asm_short, .-asm_short
    .byte 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc

/* long asm_block(long nr): performs syscall nr. While blocked in the syscall
   the thread's PC is asm_block+4, inside the first 5 bytes. */
    .globl asm_block
    .type asm_block, @function
    .p2align 4
asm_block:
    mov eax, edi
    syscall
    ret
    .size asm_block, .-asm_block

    .data
    .globl asm_rip_data
    .p2align 2
asm_rip_data:
    .long 5

    .section .note.GNU-stack,"",@progbits
