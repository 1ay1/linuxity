# linuxity — User Manual

A practical, task-oriented guide to running real Linux userlands under
`linuxity`. If you want the *why* and the internals, read
[`ARCHITECTURE.md`](ARCHITECTURE.md); this document is the *how*.

> **What linuxity is, in one line:** it runs native Linux ELF binaries directly
> on your CPU at full speed while a userspace runtime — not a VM, not an
> emulator — services their system calls. `--root <dir>` turns an extracted
> distro rootfs into the guest `/`, unprivileged, with no chroot and no
> `/dev/kvm`.

---

## Table of contents

1. [Requirements](#1-requirements)
2. [Install & build](#2-install--build)
3. [Quick start](#3-quick-start)
4. [Getting a rootfs](#4-getting-a-rootfs)
5. [Command-line reference](#5-command-line-reference)
6. [Environment variables](#6-environment-variables)
7. [Common tasks (cookbook)](#7-common-tasks-cookbook)
8. [Resource limits](#8-resource-limits)
9. [Bind mounts](#9-bind-mounts)
10. [Networking & DNS](#10-networking--dns)
11. [Users, permissions & fake-root](#11-users-permissions--fake-root)
12. [Package managers](#12-package-managers)
13. [How it behaves — the guest's view](#13-how-it-behaves--the-guests-view)
14. [Performance](#14-performance)
15. [Troubleshooting](#15-troubleshooting)
16. [Limitations & scope](#16-limitations--scope)
17. [FAQ](#17-faq)

---

## 1. Requirements

| Requirement | Detail |
|---|---|
| **OS / kernel** | Linux. The native trap backend uses `ptrace(2)`; the fast path additionally uses `seccomp` BPF filtering (`CONFIG_SECCOMP_FILTER`). Without seccomp, linuxity falls back to a slower `PTRACE_SYSCALL` mode automatically. |
| **Host CPU / ISA** | Same ISA as the guest binaries. On an **x86-64** host you run **x86-64** rootfs binaries. A foreign-arch binary is refused with a clear error (there is no cross-emulator built in). |
| **Compiler** | A C++23 toolchain (`std::expected`, concepts). Tested with **GCC 16**. |
| **Build tools** | CMake + Ninja (or Make). |
| **Privileges** | **None required.** Everything is unprivileged: no root, no chroot, no `mount(2)`. |

Optional, only for the precise resource-limit path:

- **cgroup v2** with delegated controllers, or `systemd-run --user` available
  (linuxity re-execs through it to obtain a delegated scope). Without it,
  limits fall back to `setrlimit` (coarser but still enforced).

---

## 2. Install & build

```sh
git clone <this-repo> linuxity && cd linuxity
cmake -S . -B build -G Ninja
cmake --build build
```

The runnable binary is `./build/linuxity`. Run the test suite (optional):

```sh
ctest --test-dir build
```

> Two tests (`run_multiproc`, `run_shebang`) can fail inside restrictive
> sandboxes that forbid nested `ptrace`. They pass on a normal Linux host.

Put it on your `PATH` if you like:

```sh
sudo install -m755 build/linuxity /usr/local/bin/linuxity   # optional
```

---

## 3. Quick start

Run a native host binary under the runtime (no rootfs — the guest shares the
host filesystem, but `/proc`, `/sys`, identity and `uname` are virtualized):

```sh
linuxity /usr/bin/uname -a
#   -> Linux linuxity 6.6.0-linuxity #1 linuxity portable Linux ABI x86_64
linuxity /usr/bin/id
#   -> uid=0(root) gid=0(root) ...          (identity is virtualized)
```

Run a whole **distro** by pointing `--root` at an extracted rootfs:

```sh
linuxity --root ./alpine-rootfs /bin/sh
linuxity --root /tmp/arch/root.x86_64 /usr/bin/bash
```

Inside that shell you have the distro's real `/bin`, `/usr`, package manager and
libraries; the guest believes it is `root` on a machine called `linuxity`, and
it cannot see or touch your host filesystem.

---

## 4. Getting a rootfs

A "rootfs" is just an extracted distro tree (the same tarballs Docker, LXC,
proot-distro and WSL use). A few easy sources:

**Alpine (tiny, musl):**

```sh
mkdir alpine-rootfs
curl -L https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.0-x86_64.tar.gz \
  | tar -xz -C alpine-rootfs
linuxity --root alpine-rootfs /bin/sh
```

**Arch (glibc, pacman):**

```sh
mkdir -p arch/root.x86_64
curl -L https://geo.mirror.pkgbuild.com/iso/latest/archlinux-bootstrap-x86_64.tar.zst \
  | tar --use-compress-program=unzstd -x -C arch
linuxity --root arch/root.x86_64 /usr/bin/bash
```

**From a Docker image (any distro):**

```sh
mkdir mydistro
docker create --name tmp debian:stable
docker export tmp | tar -x -C mydistro
docker rm tmp
linuxity --root mydistro /bin/bash
```

> Extract with an ISA that matches your host (x86-64 rootfs on an x86-64 host).
> A foreign-arch rootfs is detected and refused, not silently mis-run.

---

## 5. Command-line reference

```
linuxity [OPTIONS] <program> [args...]
```

`<program>` is a path **in the guest namespace** (e.g. `/bin/sh`), and
everything after it is passed to the guest verbatim. Options must come *before*
the program.

| Option | Argument | Meaning |
|---|---|---|
| `--root` | `<dir>` | Mount an extracted distro rootfs as the guest `/`. Every guest path is translated to the real host path under `<dir>`; `/proc`, `/sys`, `/dev` are synthesized. Guest **writes** go to a copy-on-write overlay — the rootfs on disk stays pristine. |
| `--bind`, `-b` | `host[:guest]` | Expose a real host directory inside the guest tree at `guest` (default: the same path). Writes land on the real host files. Repeatable. See [§9](#9-bind-mounts). |
| `--cpus` | `<N>` | Bound CPU to N cores' worth (e.g. `1.5`). See [§8](#8-resource-limits). |
| `--memory`, `-m` | `<SZ>` | Hard memory ceiling, e.g. `512M`, `2G`. |
| `--memory-swap` | `<SZ>` | Combined memory+swap ceiling. |
| `--pids` | `<N>` | Max number of tasks in the guest tree (a fork-bomb guard). |
| `--cpuset` | `<LIST>` | Pin the guest to specific CPUs, e.g. `0-1` or `0,2,4`. |

Size suffixes for `--memory`/`--memory-swap`: `K`, `M`, `G` (powers of 1024).

Running with **no program** (or bad flags) prints usage and exits `2`.

Examples:

```sh
linuxity --root ./fs /bin/sh
linuxity --root ./fs --memory 512M --cpus 2 /usr/bin/make -j4
linuxity --root ./fs --bind $HOME/src:/src --bind /tmp/out:/out /usr/bin/gcc ...
linuxity /usr/bin/htop            # no rootfs: host tree + virtual /proc,/sys
```

---

## 6. Environment variables

These tune the runtime (set them in the environment you launch `linuxity`
from; the guest does **not** see them as special):

| Variable | Effect |
|---|---|
| `LINUXITY_NO_SECCOMP=1` | Force the slow `PTRACE_SYSCALL` drive mode instead of the seccomp fast path. Useful for debugging or on kernels without `CONFIG_SECCOMP_FILTER` (which is auto-detected anyway). |
| `LINUXITY_NO_DNS=1` | Disable the automatic host-`resolv.conf` binding (see [§10](#10-networking--dns)). The guest then sees only the rootfs's own `/etc/resolv.conf`. |
| `LINUXITY_TRACE=<path>` | Write a per-syscall dispatch log (what was virtualized / forwarded / redirected / injected, and the return value) to `<path>` if it looks like a path, else stderr. Invaluable for debugging a program that misbehaves under linuxity. |
| `LINUXITY_DELEGATED=1` | **Internal.** Set automatically when linuxity re-execs itself through `systemd-run` for a delegated cgroup scope. You should not set this yourself. |

The guest **inherits your environment** (so `PATH`, `TERM`, `HOME`, `LANG`
behave), while identity/credential syscalls stay virtualized.

Trace example:

```sh
LINUXITY_TRACE=/tmp/lx.log linuxity --root ./fs /bin/ls /etc
less /tmp/lx.log
#   [lx] nr=257 -> REDIRECT /abs/host/path/etc ret=3 ...
#   [lx] nr=217 -> VIRT ret=... (getdents on a virtual dir)
```

---

## 7. Common tasks (cookbook)

**Open an interactive shell in a distro:**

```sh
linuxity --root ./fs /bin/bash        # or /bin/sh, /bin/ash
```

**Run one command and exit:**

```sh
linuxity --root ./fs /usr/bin/cat /etc/os-release
linuxity --root ./fs /bin/sh -c 'ls -la /usr/bin | head'
```

**Pipelines, loops, job control** all work — they run as a real forked process
tree inside the namespace:

```sh
linuxity --root ./fs /bin/sh -c 'seq 1 100 | grep 7 | wc -l'
linuxity --root ./fs /bin/bash -c 'sleep 30 & echo "bg pid $!"; jobs; kill %1'
```

**Build software inside the guest, sources on the host:**

```sh
linuxity --root ./fs --bind $PWD:/build /bin/sh -c 'cd /build && make'
```

**Run a process/hardware monitor** (reads linuxity's synthesized `/proc`,`/sys`):

```sh
linuxity --root ./fs /usr/bin/htop
linuxity --root ./fs /usr/bin/top -b -n1
linuxity --root ./fs /usr/bin/free -m
```

**Inspect the virtual world:**

```sh
linuxity --root ./fs /bin/cat /proc/version     # Linux version 6.6.0-linuxity ...
linuxity --root ./fs /bin/cat /proc/cpuinfo     # linuxity's machine
linuxity --root ./fs /bin/cat /proc/self/status # Pid: 1, Uid: 0
```

---

## 8. Resource limits

linuxity is an ABI translator, not a hypervisor — the guest draws memory and
CPU straight from the host's global pool at native speed. But because the guest
is an ordinary host process tree, you can **cgroup it like any other process**:

```sh
linuxity --root ./fs --memory 512M --cpus 2 --pids 256 --cpuset 0-1 /usr/bin/make -j4
```

Two numbers are kept **equal**:

- **Belief** — what the guest *reads* (`sysinfo`, `/proc/meminfo`,
  `/proc/cpuinfo`, `sched_getaffinity`), derived from the limits you set. So a
  program that sizes caches to "half of RAM" or spawns "one worker per CPU"
  shapes itself to the bound it will actually be held to. `--memory 512M`
  makes `MemTotal: 524288 kB`; `--cpus 2` makes `nproc` report `2`.
- **Enforced reality** — what the host kernel actually lets it consume.

**How enforcement is applied (best-effort, graceful fallback):**

1. **cgroup v2** — a `payload` cgroup gets `memory.max` / `cpu.max` /
   `pids.max` / `cpuset.cpus`. If your session's controllers aren't delegated
   (the common unprivileged case), linuxity re-execs itself through
   `systemd-run --user --scope` to obtain a delegated scope. This is the
   precise, kernel-enforced bound.
2. **`setrlimit`** — where no cgroup can be created, `RLIMIT_AS` bounds address
   space as a coarser memory ceiling.

With **no** limit flags the guest is fully unbounded at native speed.

> `--pids` is intentionally *not* mapped to `RLIMIT_NPROC` (which counts the
> whole login session, not just the guest tree) — it uses `pids.max` when a
> cgroup is available.

---

## 9. Bind mounts

`--bind host[:guest]` exposes a real host directory in the guest tree — like
proot's `-b` or bubblewrap's `--bind`, but riding linuxity's path-translation
namespace (no privilege, no real `mount(2)`).

```sh
# expose ~/project as /work in the guest:
linuxity --root ./fs --bind ~/project:/work /bin/bash
#   -> /work IS ~/project; writes land on the real host files (a true bind)

# same guest and host path — just drop the ":guest" part:
linuxity --root ./fs --bind /opt/toolchain /bin/bash

# multiple binds:
linuxity --root ./fs -b ~/src:/src -b /tmp/artifacts:/out /bin/sh
```

**Semantics:**

- The bound directory is host-backed and **writable in place** — the whole
  point is to share a live host directory, so writes are not copied into the
  overlay; they hit the real files.
- Binds are registered **after** the rootfs, so a deeper or explicit bind wins
  by longest-prefix and can even **shadow** a rootfs directory (e.g.
  `--bind ~/etc-override:/etc`).
- `guest` must be an absolute path.

---

## 10. Networking & DNS

Networking is **fully native**: socket, DNS, TLS and HTTP syscalls are
forwarded to the host kernel, so throughput and latency are bare-metal and the
guest uses your host's real network.

**DNS just works out of the box.** A freshly extracted rootfs frequently ships
`/etc/resolv.conf` empty, absent, or as a dangling symlink, which would break
`pacman -Sy`, `apt update`, `curl`, etc. So when `--root` is used and the
rootfs's own `/etc/resolv.conf` has no usable `nameserver` line, linuxity
**binds the host's live `/etc/resolv.conf`** over the guest path:

```
linuxity: bind /etc/resolv.conf -> host (rootfs had no DNS)
```

This means DNS tracks whatever your host actually uses (VPN, split-horizon,
corporate resolver), and the **pristine rootfs is never modified**. If the
rootfs already has a working resolv.conf, linuxity leaves it alone.

Opt out (use only the rootfs's own resolv.conf):

```sh
LINUXITY_NO_DNS=1 linuxity --root ./fs /bin/sh
```

---

## 11. Users, permissions & fake-root

The guest believes it is **root (uid 0)** on a **root-owned filesystem**, even
though the linuxity process itself is unprivileged and the rootfs on disk is
owned by whoever unpacked it.

- `id` / `whoami` report `uid=0(root)`.
- `ls -la` shows `root root` for rootfs entries.
- `chmod` / `chown` **round-trip through `stat`** — this is the fake-root
  contract most tools depend on:

```sh
linuxity --root ./fs /bin/bash -c \
  'touch /tmp/z; chmod 4755 /tmp/z; chown 1000:1000 /tmp/z; stat -c "%a %u:%g" /tmp/z'
#   -> 4755 1000:1000
```

The setuid bit and the non-root owner come back correctly even though the real
inode never changed owner and the unprivileged host would have dropped the
setuid bit. linuxity records the guest-intended `(mode, uid, gid)` in a shadow
metadata journal (`.linuxity-meta`, kept in the overlay upper layer — never
visible to the guest) and overlays it onto every `stat`/`lstat`/`statx`. The
record persists across runs and travels correctly across `rename`/`unlink`.

This is what lets `tar -p`, `install -o root -g root -m 4755`, `useradd`,
package post-install verification, and similar tools work unprivileged.

---

## 12. Package managers

Package managers work end to end — reading their installed DB through the
namespace, downloading, extracting, writing files, `chmod`/`chown`ing them, and
running post-install scriptlets — all into the copy-on-write overlay, never
touching the pristine rootfs.

**Alpine `apk`:**

```sh
linuxity --root ./alpine /sbin/apk add --no-cache curl
linuxity --root ./alpine /usr/bin/curl --version
```

**Arch `pacman` (including from the network):**

```sh
linuxity --root ./arch /usr/bin/pacman -Q            # list installed
linuxity --root ./arch /usr/bin/pacman -Qi bash      # package details
linuxity --root ./arch /usr/bin/pacman -Sy which --noconfirm   # download + install
linuxity --root ./arch /usr/bin/pacman -U ./pkg.pkg.tar.zst    # local package
```

The freshly-installed binaries then run under the same guest. Package sandboxes
(pacman 7's `DownloadUser` / Landlock / seccomp) are accepted as no-ops because
linuxity's namespace already confines the guest.

---

## 13. How it behaves — the guest's view

What the guest sees, and why it is coherent:

- **`uname`** reports `Linux linuxity 6.6.0-linuxity ... x86_64` — linuxity's
  identity, not the host kernel's.
- **`/proc`** is fully synthesized from linuxity's process table:
  `/proc/{stat,meminfo,cpuinfo,uptime,loadavg,version,cmdline,mounts,sys/...}`
  and the per-process tree `/proc/<pid>/{stat,status,cmdline,maps,task/<tid>/}`.
  init is pid 1, uid 0.
- **`/sys`** is synthesized: CPU topology, cpufreq, hwmon temperatures, a
  virtual block device, cgroup v2 stubs.
- **`/dev`** is populated: `/dev/null`, `/dev/zero`, `/dev/urandom` redirect to
  the host's real character devices (native semantics), and
  `/dev/std{in,out,err}` map to `/proc/self/fd/{0,1,2}`.
- **The process tree is real.** Forks, execs, waits, pipelines and background
  jobs all run as genuine host processes; the runtime traces the whole tree.
- **Pids are coherent and small.** `getpid`/`getppid`/`$!`/`jobs`/`wait` all
  speak linuxity's own tiny pid namespace (root = 1) — not host pids.
- **Signals reach the right task.** `kill`/`kill -9`/`kill -0` on a guest pid
  are delivered to the correct traced task; handlers actually run.
- **`/proc/self/exe`**, `cwd`, `root` resolve to guest paths, so a program that
  locates its own binary sees `/bin/foo`, not the host path.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the mechanism behind each of these.

---

## 14. Performance

Guest **instructions run natively on the CPU** — there is no interpretation or
JIT. The only overhead is at the *syscall boundary*, and even there:

- A **seccomp BPF filter** traps only the ~90 syscalls linuxity must intercept
  (path-carrying, identity, exec, wait, ioctl, uname, …). Everything else
  (`read`, `write`, `mmap`, `futex`, `lseek`, arithmetic-only code, …) runs
  with **zero** ptrace overhead.
- Measured **~140×** faster than the fallback on a 2-million-syscall
  microbenchmark (0.35 s vs 50 s).

If the host lacks `CONFIG_SECCOMP_FILTER`, linuxity automatically uses the
`PTRACE_SYSCALL` fallback (correct, just slower). You can force it with
`LINUXITY_NO_SECCOMP=1` for debugging.

**Rule of thumb:** CPU-bound work runs at bare-metal speed; syscall-heavy work
pays a small trap cost only on the intercepted subset.

---

## 15. Troubleshooting

**`ptrace` errors / "runtime error" / tests hang in a sandbox.**
Nested `ptrace` may be blocked inside another sandbox (some CI containers,
another `ptrace`-based tool). Run on a normal Linux host, or check
`/proc/sys/kernel/yama/ptrace_scope`.

**A program misbehaves — figure out which syscall.**

```sh
LINUXITY_TRACE=/tmp/lx.log linuxity --root ./fs /path/to/program
# then inspect /tmp/lx.log: each line is nr=<num> -> <fate> ret=<val>
```

**"foreign-architecture binary" error.**
Your rootfs (or the named binary) is built for a different ISA than the host.
linuxity runs code natively and has no cross-emulator — use a rootfs for the
host's ISA. (See [§4](#4-getting-a-rootfs).)

**Networking / package install can't resolve names.**
Ensure DNS is available. linuxity auto-binds the host resolv.conf when the
rootfs's is unusable (see [§10](#10-networking--dns)); if you set
`LINUXITY_NO_DNS=1`, provide a working `/etc/resolv.conf` in the rootfs.

**A dynamic binary fails to load libraries.**
Make sure the rootfs is a complete tree (its `ld.so` and `/lib*` present).
Extract full distro tarballs, not partial ones.

**Writes seem to "vanish" after exit.**
Guest writes go to a **copy-on-write overlay** in a per-run scratch dir
(`/tmp/linuxity-upper-<pid>`), leaving the rootfs pristine. Use `--bind` to
write to a directory you control if you need writes to persist on the host.

**Force the slow, most-compatible mode** (rules out a seccomp fast-path issue):

```sh
LINUXITY_NO_SECCOMP=1 linuxity --root ./fs /bin/sh
```

---

## 16. Limitations & scope

- **Same-ISA only.** No built-in cross-architecture emulation; a foreign-arch
  binary is refused. (Cross-ISA would plug in behind the same ABI at the ISA
  boundary but is not part of the core.)
- **Linux host only** for the native trap backend (`ptrace` + `seccomp`).
- **Interactive Ctrl-C to a foreground process group** uses a virtualized
  job-control model (the guest shell owns its tty and settles at the prompt);
  genuine terminal-driven foreground-group signal delivery is a deliberate
  non-goal for now.
- **Heavily-threaded `futex`/`epoll`-bound programs** have growing but not yet
  exhaustive coverage.
- Some `/proc` counters are static snapshots rather than live-advancing.

None of these affect the common case: running a distro shell, building
software, and using the package manager.

---

## 17. FAQ

**Is this a virtual machine?**
No. There is no VM, no `/dev/kvm`, no guest kernel. Guest instructions run on
your real CPU; linuxity is a userspace re-implementation of the *kernel/user
contract* that services syscalls.

**Is it an emulator like QEMU or iSH?**
No. Those interpret/JIT foreign instructions. linuxity runs **native** code —
it only intercepts syscalls. That's why it is fast.

**Do I need root?**
No. Everything is unprivileged — no root, no chroot, no `mount(2)`.

**Does the guest see my host files?**
With `--root`, no: the guest lives entirely in the rootfs. Without `--root`,
the guest shares the host tree (but `/proc`, `/sys`, `/dev`, identity and
`uname` are still virtualized). `--bind` selectively shares host directories.

**Can I run Docker images?**
You can run their *filesystem* (`docker export | tar -x` → `--root`). linuxity
is not a container orchestrator; it runs the userland, not the Docker engine.

**How is this different from proot / proot-distro?**
Same "ptrace + native execution, no root" model. linuxity is modern C++23 with
a copy-on-write overlay namespace, cgroup-backed resource limits, a coherent
tiny pid namespace (proot leaks host pids), a consolidated shadow-perms journal
(proot scatters per-file sidecars), and host-tracking DNS (proot-distro
hardcodes 8.8.8.8 to disk).

**How is it different from termux-exec?**
termux-exec is an `LD_PRELOAD` shim that rewrites exec in userspace. linuxity
does the equivalent rewriting *inside the kernel-substitute*, which also works
for static binaries and can't be bypassed.

---

*See also: [`README.md`](../README.md) (overview & design),
[`ARCHITECTURE.md`](ARCHITECTURE.md) (internals),
[`reference-study.md`](reference-study.md) (how techniques map from
proot/termux).*
