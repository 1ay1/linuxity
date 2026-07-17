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
| **termux-exec** | `LD_PRELOAD` shim that rewrites `execve`/shebang paths in userspace | linuxity does the same rewriting IN the trap (kernel-substitute), which is cleaner: no preload, works for static binaries, can't be bypassed. |

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
   round-trips. linuxity already presents a root-owned world (stat scrubbed to
   uid/gid 0, chown a no-op, privilege drops accepted), which covers apk/pacman
   today. Gap vs proot: no shadow perms db, so `stat` after a guest `chmod 0755`
   reports the host mode, not the guest-intended mode. Track a per-path
   mode/owner overlay if a package's post-install verification needs it.

3. **link2symlink** — emulate hardlinks as symlinks on filesystems (or overlays)
   that can't hardlink. linuxity's overlay upper is a normal fs so `link(2)`
   works today; keep this in the back pocket for exotic backing stores.

4. **bindings / mounts** (`path/binding.c`) — proot's `-b host:guest` bind model.
   linuxity's `mount_host` / `mount_virtual` already generalizes this; the
   `--root` overlay is the common case. A future `--bind host:guest` flag would
   be a thin wrapper over the existing FileNamespace.

5. **shebang + ldso rewriting** (`execve/shebang.c`, `ldso.c`) — DONE in linuxity
   (path_exec + exec_through_interp).

6. **ioctl / tty job control** — proot only traps ioctl on Android. linuxity
   virtualizes the tty job-control ioctls (TIOCGPGRP/TIOCSPGRP/TIOCGSID) so a
   guest shell owns its tty and doesn't spin. DONE.

7. **pid namespace coherence** — proot LEAKS host pids (its `$!` shows host pids;
   documented behavior). linuxity translates fork/clone/wait4 pids both ways so
   the guest lives in one tiny pid space (root == 1). **linuxity is already ahead
   of proot here.**

## Order of attack

1. seccomp-BPF acceleration (perf — unlocks heavy workloads). ✓ DONE
2. shadow perms db for fake_id0-grade chmod/chown round-tripping (correctness).
3. `--bind` flag over FileNamespace (ergonomics).
