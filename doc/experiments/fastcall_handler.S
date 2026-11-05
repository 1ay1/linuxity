// tools/fastcall/handler.S -- the in-guest syscall fast path (aarch64, EL1).
//
// Installed at VBAR_EL1 + 0x400 (lower EL, AArch64, synchronous), so every
// guest `svc` lands here IN THE GUEST. Whatever this code answers itself,
// the host never sees: ~28 ns, against ~1050 ns for a VM exit.
//
// Assembled by tools/fastcall/build.py and embedded as bytes, so nothing is
// hand-encoded. (A hand-written `add x16, x16, x8, lsl #7` that should have
// been `lsl #4` once cost an afternoon: the table lookup silently missed and
// every call took the slow path, which looks exactly like "the fast handler
// never runs".)
//
// REGISTER BUDGET -- the rule that makes this safe. We run on the guest's
// own register file. x16/x17 (IP0/IP1) are ours: the procedure-call
// standard lets a linker veneer clobber them across any call, so no guest
// code holds a live value there at an `svc`. Everything else belongs to the
// guest. x0..x5 carry the syscall ARGUMENTS -- readable, never written,
// except x0, which is also the return value and so is written LAST.
// SP is the guest's: no pushes, no red-zone use.
//
// Anything this handler does not understand falls through to `hvc #8`,
// which is the original stub: the host then services the call exactly as
// before, having lost only a few cycles.

        .text
        .globl _fast_begin
_fast_begin:
        mrs     x16, esr_el1
        lsr     x16, x16, #26
        cmp     x16, #0x15              // EC == SVC64?
        b.ne    Lslow
        cmp     x8, #512                // in table range?
        b.hs    Lslow

        // x17 = &table[nr]; build.py patches the movz/movk with the table's
        // guest-physical address.
        .globl _fast_table_imm
_fast_table_imm:
        movz    x16, #0
        movk    x16, #0, lsl #16
        add     x17, x16, x8, lsl #4
        ldr     x16, [x17, #8]          // entry.live
        cbz     x16, Lslow

        cmp     x16, #1
        b.ne    Lmask

        // ---- live == 1: a constant -----------------------------------
        ldr     x16, [x17]              // entry.value
        mov     x0, x16
        eret

        // ---- live == 2: rt_sigprocmask -------------------------------
        // rt_sigprocmask(how=x0, set=x1, oset=x2, sigsetsize=x3).
        //
        // A read-modify-write of one 64-bit word plus up to two guest memory
        // accesses; no host state is touched. The host re-reads the mask
        // from this scratch word on its next trap, and only the guest can
        // have changed it meanwhile.
        //
        // entry.value is the scratch address. Registers after this point:
        //   x16 = &scratch   x17 = working mask
        //   x0/x1/x2/x3 stay the guest's arguments until the very end.
Lmask:
        cmp     x16, #2
        b.ne    Lslow
        cmp     x3, #8                  // Linux requires sigsetsize == 8
        b.ne    Lslow
        ldr     x16, [x17]              // &scratch.sig_mask
        ldr     x17, [x16]              // the current mask

        cbz     x2, Lno_old
        str     x17, [x2]               // *oset = current
Lno_old:
        cbz     x1, Ldone               // set == NULL -> query only
        ldr     x1, [x1]                // the requested set (x1 now dead)

        cmp     x0, #2
        b.hi    Lslow                   // how > SIG_SETMASK: host says EINVAL
        cbz     x0, Lblock              // 0 = SIG_BLOCK
        cmp     x0, #1
        b.eq    Lunblock                // 1 = SIG_UNBLOCK
        mov     x17, x1                 // 2 = SIG_SETMASK
        b       Lclamp
Lblock:
        orr     x17, x17, x1
        b       Lclamp
Lunblock:
        bic     x17, x17, x1
Lclamp:
        // SIGKILL (9) and SIGSTOP (19) are never blockable: bits 8 and 18.
        // 0x40100 is not a valid logical/mov immediate, so build it.
        movz    x1, #0x0100
        movk    x1, #0x4, lsl #16
        bic     x17, x17, x1
        str     x17, [x16]
Ldone:
        mov     x0, #0
        eret

Lslow:
        hvc     #8
        .globl _fast_end
_fast_end:
