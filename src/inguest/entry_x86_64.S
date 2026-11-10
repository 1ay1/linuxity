// In-guest handler entry, x86-64. Position independent; the blob runs at
// whatever address the guest's mmap gave it.
    .section .lx_header, "a"
    .globl lx_ig_header
lx_ig_header:
    .quad 0x4c5846505441424c
    .long 1
    .long lx_ig_common - lx_ig_header
    .long lx_ig_guard_start - lx_ig_header
    .long lx_ig_guard_end - lx_ig_header
    .long lx_ig_fault_ret - lx_ig_header
    .long 0

    .text
// void* lx_ig_base(void): where the blob (and so the region) starts
    .globl lx_ig_base
lx_ig_base:
    lea lx_ig_header(%rip), %rax
    ret

// long lx_ig_gate(long nr, long a0, long a1, long a2, long a3, const uint64_t key[2])
// a3 is the 4th syscall argument (r10); the key goes in the 5th and 6th.
    .globl lx_ig_gate
    .type lx_ig_gate, @function
lx_ig_gate:
    push %r12
    mov %r9, %r12
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8, %r10
    mov 0(%r12), %r8
    mov 8(%r12), %r9
    syscall
    pop %r12
    ret

// long lx_ig_on_stack(long (*fn)(void*), void* arg, void* top)
    .globl lx_ig_on_stack
lx_ig_on_stack:
    push %rbp
    mov %rsp, %rbp
    mov %rdx, %rsp
    mov %rdi, %rax
    mov %rsi, %rdi
    call *%rax
    mov %rbp, %rsp
    pop %rbp
    ret

// Called from a stub with the red zone skipped and eax = nr. Keeps every
// register a syscall keeps. Returns rax = result and rcx = 1, or rcx = 0
// (rax = nr again) to make the stub run the real syscall.
    .globl lx_ig_common
    .type lx_ig_common, @function
lx_ig_common:
    pushfq
    push %rax
    push %rdi
    push %rsi
    push %rdx
    push %r10
    push %r8
    push %r9
    push %rbx
    cld
    mov %rsp, %rbx
    and $-16, %rsp
    lea 8(%rbx), %rdi
    mov 56(%rbx), %esi
    call lx_ig_handle
    mov %rbx, %rsp
    movabs $0x8000000000000000, %rcx
    cmp %rcx, %rax
    je 1f
    mov %rax, 56(%rsp)
    mov $1, %ecx
    jmp 2f
1:  xor %ecx, %ecx
2:  pop %rbx
    pop %r9
    pop %r8
    pop %r10
    pop %rdx
    pop %rsi
    pop %rdi
    pop %rax
    popfq
    ret

// Guest memory is touched only in here. A fault inside makes the supervisor
// resume at lx_ig_fault_ret, which the C side treats as "fall back".
// Neither routine touches the stack before its ret.
lx_ig_guard_start:
// long lx_ig_copy(void* dst, const void* src, unsigned long n): 0
    .globl lx_ig_copy
lx_ig_copy:
    test %rdx, %rdx
    jz 2f
1:  movb (%rsi), %al
    movb %al, (%rdi)
    inc %rsi
    inc %rdi
    dec %rdx
    jnz 1b
2:  xor %eax, %eax
    ret
// long lx_ig_strcpy(char* dst, const char* src, unsigned long max):
// the length without the NUL, or max if there is no NUL in max bytes
    .globl lx_ig_strcpy
lx_ig_strcpy:
    xor %eax, %eax
1:  cmp %rdx, %rax
    jae 2f
    movb (%rsi,%rax), %cl
    movb %cl, (%rdi,%rax)
    test %cl, %cl
    jz 2f
    inc %rax
    jmp 1b
2:  ret
lx_ig_guard_end:
lx_ig_fault_ret:
    mov $-14, %rax
    ret

    .section .note.GNU-stack, "", @progbits
