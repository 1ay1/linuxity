// In-guest handler entry, aarch64. Position independent.
    .section .lx_header, "a"
    .globl lx_ig_header
    .balign 8
lx_ig_header:
    .quad 0x4c5846505441424c
    .word 1
    .word lx_ig_common - lx_ig_header
    .word lx_ig_guard_start - lx_ig_header
    .word lx_ig_guard_end - lx_ig_header
    .word lx_ig_fault_ret - lx_ig_header
    .word 0

    .text
    .balign 4
    .globl lx_ig_base
lx_ig_base:
    adr x0, lx_ig_header
    ret

// long lx_ig_gate(long nr, long a0, long a1, long a2, long a3, const uint64_t key[2])
    .globl lx_ig_gate
    .type lx_ig_gate, %function
lx_ig_gate:
    mov x8, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    ldp x4, x5, [x5]
    svc #0
    ret

// long lx_ig_on_stack(long (*fn)(void*), void* arg, void* top)
    .globl lx_ig_on_stack
lx_ig_on_stack:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov sp, x2
    mov x3, x0
    mov x0, x1
    blr x3
    mov sp, x29
    ldp x29, x30, [sp], #16
    ret

// Called by `blr x16` from a stub that saved x16 and x30; x8 = nr. Keeps
// every register a syscall keeps. Returns x0 = result and x16 = 1, or
// x16 = 0 (x0 untouched) to make the stub run the real syscall.
    .globl lx_ig_common
    .type lx_ig_common, %function
lx_ig_common:
    sub sp, sp, #176
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x17, x18, [sp, #128]
    mrs x9, nzcv
    stp x9, x30, [sp, #144]
    mov x0, sp
    mov x1, x8
    bl lx_ig_handle
    mov x16, #0
    mov x9, #0x8000000000000000
    cmp x0, x9
    b.eq 1f
    str x0, [sp, #0]
    mov x16, #1
1:  ldp x9, x30, [sp, #144]
    msr nzcv, x9
    ldp x17, x18, [sp, #128]
    ldp x14, x15, [sp, #112]
    ldp x12, x13, [sp, #96]
    ldp x10, x11, [sp, #80]
    ldp x8, x9, [sp, #64]
    ldp x6, x7, [sp, #48]
    ldp x4, x5, [sp, #32]
    ldp x2, x3, [sp, #16]
    ldp x0, x1, [sp, #0]
    add sp, sp, #176
    ret

// Guest memory is touched only in here (see the x86-64 file).
lx_ig_guard_start:
    .globl lx_ig_copy
lx_ig_copy:
    cbz x2, 2f
1:  ldrb w3, [x1], #1
    strb w3, [x0], #1
    subs x2, x2, #1
    b.ne 1b
2:  mov x0, #0
    ret
    .globl lx_ig_strcpy
lx_ig_strcpy:
    mov x3, #0
1:  cmp x3, x2
    b.hs 2f
    ldrb w4, [x1, x3]
    strb w4, [x0, x3]
    cbz w4, 2f
    add x3, x3, #1
    b 1b
2:  mov x0, x3
    ret
lx_ig_guard_end:
lx_ig_fault_ret:
    mov x0, #-14
    ret

    .section .note.GNU-stack, "", %progbits
