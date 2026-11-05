# Guest-side tests

These are built and run INSIDE the guest (they need a Linux aarch64
toolchain, which the rootfs provides), so they are not part of the host
`ctest` suite. Build and run them with:

    L="./build-mac/linuxity --root /tmp/archarm --persist /tmp/hvx/persist"
    $L /usr/bin/bash -c 'cd /root && gcc -O2 -o sec fastcall_security.c && ./sec'

`fastcall_security.c` — the in-guest syscall fast path (hvf_fastcall.hpp)
keeps its dispatch table and handler in the hypervisor-private, EL1-only
area. This asserts a guest at EL0 can neither READ nor WRITE any of it
(vectors, L1/L2 page tables, the table itself), and that a syscall the
table does not publish still traps to the host. Prints `SECURITY OK`.

`syscall_latency.c` — per-syscall cost, fast path vs trapping path. On an
M1 the identity calls answer in ~28 ns with no VM exit, clock_gettime
reads the vDSO in ~19 ns, and a trapping syscall costs ~1050 ns.
