# Parked experiment: rt_sigprocmask on the in-guest fast path

The identity fast path (`include/linuxity/runtime/hvf_fastcall.hpp`) is
live and works: getpid/gettid/getuid/sched_yield answer inside the guest
in ~30 ns instead of ~1050 ns for a VM exit.

Extending it to `rt_sigprocmask` — worth ~7% of all syscalls in a real
workload — is **parked**. The files here are that attempt, kept because
the assembly and the build step are correct and worth resuming from, not
because they work.

## What happens

With the handler installed, `tests/test_hvf_run` hangs: the guest spins
inside `hv_vcpu_run`, which never returns, before the guest's first
syscall. Bisected precisely — the commit before is clean, the commit
itself hangs — and reproduced from a clean build tree both ways.

## Two real bugs found and fixed, which were NOT enough

1. **Vector slot overflow.** An ARM vector slot is `0x80` bytes = 32
   instructions. The handler is 43, so writing it at `VBAR+0x400`
   overran into slot 9 (IRQ); the first interrupt jumped into the middle
   of it. Fix: put the body after the 16 slots at `VBAR+0x800` and leave
   a single `b` in slot 8. Verified: slot 9 holds its stub again.

2. **Stale icache.** `attach()` invalidated only `16 * 0x80` bytes — up
   to exactly where the body now starts — so the CPU could execute stale
   bytes at `VBAR+0x800`. Fix: invalidate the slots *and* the body.

Both are applied in the diff that still hangs, so there is at least one
more fault.

## Dead ends, recorded so they are not repeated

Three standalone probes each had their own bug and sent me the wrong way.
Anyone resuming this should distrust a fresh probe until it reproduces a
**known-good** case first:

* A probe that resumed with `PC = PC + 4` after the stub's `hvc` walked
  into the zeros past the handler. The runtime resumes with
  `PC = ELR_EL1`, `CPSR = SPSR_EL1` (see `write_return`).
* A probe using `HvfCpu::set_entry` sets `CPSR = 0` — EL0t with
  interrupts **unmasked**. With no timer configured the guest takes an
  endless interrupt at vector 4. That probe hung even with the original
  unmodified `hvc` stub, which is the tell.
* Single-stepping with `MDSCR_EL1.SS` makes every instruction raise a
  debug exception, so the resulting trace (`EC=0x21`, instruction abort)
  was an artifact of the stepping, not the handler.

## What is NOT the cause

* The dispatch table's address, which sits inside the private area and
  does not overlap the L2 or L3 arrays (checked at 512 MiB and 2 GiB).
* Page permissions: the L3 descriptor for the vector page has
  `PXN=0, UXN=0, AF=1`, and `SCTLR_EL1.WXN` is clear, so EL1 may fetch
  from it.
* The branch encoding in slot 8: `0x14000100` decodes to `b 0x800`.

## Where to resume

The handler faults or loops somewhere after slot 8 branches to it. The
next step is a way to observe EL1 execution that does **not** perturb it
— the debug-exception route above does. One option is to have the
handler store a progress marker to its scratch page at each step and
read that from the host after the hang, since the scratch is plain
memory and costs nothing to write.
