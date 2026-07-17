# linuxity vs. the state of the art — techniques worth stealing, done the linuxity way

A study of the three reference "run a foreign Linux userland without root / on the
wrong kernel" projects, and how their techniques map onto linuxity. The guiding
principle stays: **linuxity is an ABI implementation — the guest runs natively on
the host CPU and the runtime IS the kernel-substitute. Not a VM, not emulation.**

## The three references

| Project | Model | Relationship to linuxity |
|---------|-------|--------------------------|
| **proot** (termux's `proot-distro` engine) | ptrace + native execution; syscalls trapped and their path/id args rewritten | **Same model as linuxity.** Proven running full Arch/Debian/Ubuntu unprivileged. The direct roadmap source. |
| **ish** | x86→host instruction emulation in a JIT (a real usermode CPU) | The OPPOSITE philosophy — emulation. Validates that linuxity's native path is faster; nothing to copy, only to out-perform. |
| **termux-exec** | `LD_PRELOAD` shim that rewrites `execve`/shebang paths in userspace | linuxity does the same rewriting IN the trap (kernel-substitute), which is cleaner: no preload, works for static binaries, can't be bypassed. Its `inspectFileHeader` (ONE read → static/dynamic/foreign ELF or shebang, with foreign-ISA detection) is worth mirroring — **DONE** (loader/interp.hpp `inspect_file_header` + `read_elf_machine`). |
| **proot-distro** | termux's distro manager: bootstraps a rootfs then launches proot with the right binds + DNS/hosts seeding | The launch-hygiene layer. Its DNS-seeding (a fresh rootfs has no working resolv.conf) is the one load-bearing UX bit — **DONE** the modern way: linuxity binds the HOST's live resolv.conf when the rootfs's is unusable, never mutating the rootfs (proot-distro hardcodes 8.8.8.8 to disk). |

Conclusion: **proot is the north star.** It has already solved, at scale, every
problem linuxity is working through. We adopt its *techniques* but keep linuxity's
modern C++23, its overlay namespace, its cgroup-backed resource governance, and its
coherent tiny pid namespace (which proot does NOT have — proot leaks host pids).

## Technique inventory (proot) → linuxity status / plan

1. **seccomp-BPF trap filtering** — proot installs a BPF filter that returns
   `SECCOMP_RET_TRACE` only for the ~90 syscalls it must intercept (path-carrying,
   id, exec, wait4, ioctl-on-Android, uname, statfs, …) and `SECCOMP_RET_ALLOW`
   for everything else, which then runs with ZERO ptrace overhead.
   - **DONE** (runtime/seccomp_filter.hpp). linuxity installs a classic-BPF
     filter (kTrappedX86_64) in the guest that RET_TRACEs only the intercepted
     syscalls; the tracer arms PTRACE_O_TRACESECCOMP and drives every task with
     PTRACE_CONT, so non-intercepted syscalls (read/write/mmap/futex/lseek/…)
     run natively. Measured ~140× on a 2M-syscall microbenchmark (0.35s vs 50s).
     Correctness is unchanged: `run_seccomp` proves the fast path is byte-for-
     byte equivalent to the PTRACE_SYSCALL fallback, and LINUXITY_NO_SECCOMP=1
     forces that fallback (also used when the host lacks CONFIG_SECCOMP_FILTER).
   - Bootstrap subtlety solved: execve/execveat/gettid/tgkill/tkill/close are
     deliberately LEFT NATIVE — a trapped syscall in the window between filter
     install and the tracer arming TRACESECCOMP would ENOSYS-fail and abort the
     launch. Exec is still observed via PTRACE_EVENT_EXEC; guest binaries are
     loaded by the real ld.so through the (filtered, translated) openat.
   - clone/fork/wait pid translation is preserved under the fast path:
     resume_after_event() steps a mid-serviced clone to its EXIT stop even
     across the intervening fork event, so $!/jobs stay coherent.

2. **fake_id0** — proot's most complete "fake root": a coherent uid-0 world where
   chmod/chown/access/setuid/capset/stat all agree, backed by a shadow
   ownership/mode db so a package manager's `install -o root -g root -m 4755`
   round-trips. **DONE — and better than proot.** linuxity's `MetaStore`
   (kernel/meta_store.hpp) keeps a per-path (mode,uid,gid) overlay: chmod/chown/
   fchmod/fchown RECORD the guest-intended values, and stat/lstat/statx/
   newfstatat OVERLAY them onto the host inode result. Ownership round-trips
   even though the host process is unprivileged; setuid/sticky/0000 modes
   round-trip even when the host drops them. Where proot scatters a
   `.proot-meta-file.<name>` SIDECAR beside every touched file (polluting the
   guest tree, needing filter-everywhere), linuxity keeps ONE consolidated
   `.linuxity-meta` journal in the overlay upper layer — never guest-visible,
   persists+replays across runs, with tombstones so unlink/rename stay accurate.
   Verified: real Arch bash `chmod 4755 f; chown 1000:1000 f; stat f` →
   `4755 1000:1000`. Regression: tests/test_run_meta.cpp.

3. **link2symlink** — emulate hardlinks as symlinks on filesystems (or overlays)
   that can't hardlink. linuxity's overlay upper is a normal fs so `link(2)`
   works today; keep this in the back pocket for exotic backing stores.

4. **bindings / mounts** (`path/binding.c`) — proot's `-b host:guest` bind model.
   linuxity's `mount_host` / `mount_virtual` already generalizes this; the
   `--root` overlay is the common case. **DONE:** `--bind host[:guest]` (main.cpp)
   is a thin wrapper over FileNamespace::mount_host, registered after the rootfs
   so a deeper/explicit bind wins by longest-prefix and can even shadow a rootfs
   dir. Writes land on the real host files (a true bind, no overlay). Verified
   read + write-back on the real Arch shell. Regression: tests/test_run_bind.cpp.

5. **shebang + ldso rewriting** (`execve/shebang.c`, `ldso.c`) — DONE in linuxity
   (path_exec + exec_through_interp). termux-exec's `inspectFileHeader` refinement
   is now folded in: loader/interp.hpp `inspect_file_header()` classifies a
   program in ONE read (static / dynamic / foreign ELF / shebang-with-arg /
   non-exec), and `read_elf_machine()` gives the exec path a cheap foreign-ISA
   guard. A wrong-arch binary (aarch64 on x86-64) is REFUSED cleanly — ENOEXEC
   from the in-guest path, a clear CLI diagnostic from `main`, instead of a
   cryptic loader crash. Regression: tests/test_interp.cpp, run_foreign_exec.

6. **DNS / launch hygiene** (proot-distro `helpers/rootfs.py`) — DONE, modernized.
   A freshly extracted rootfs often ships no usable `/etc/resolv.conf`, breaking
   `pacman -Sy`/`apt update`. proot-distro overwrites it with hardcoded 8.8.8.8;
   linuxity instead binds the HOST's LIVE resolv.conf over the guest path only
   when the rootfs's own has no nameserver — DNS tracks the host (VPN/corporate
   resolver) and the pristine rootfs is never mutated. Opt out: LINUXITY_NO_DNS=1.

7. **ioctl / tty job control** — proot only traps ioctl on Android. linuxity
   virtualizes the tty job-control ioctls (TIOCGPGRP/TIOCSPGRP/TIOCGSID) so a
   guest shell owns its tty and doesn't spin. DONE.

8. **pid namespace coherence** — proot LEAKS host pids (its `$!` shows host pids;
   documented behavior). linuxity translates fork/clone/wait4 pids both ways so
   the guest lives in one tiny pid space (root == 1). **linuxity is already ahead
   of proot here.**

## Order of attack

1. seccomp-BPF acceleration (perf — unlocks heavy workloads). ✓ DONE
2. shadow perms db for fake_id0-grade chmod/chown round-tripping (correctness). ✓ DONE
3. `--bind` flag over FileNamespace (ergonomics). ✓ DONE
4. single-read file-header inspection + foreign-arch refusal (termux-exec). ✓ DONE
5. host-resolv.conf DNS provisioning (proot-distro). ✓ DONE
