# The syscall layer: one implementation, three hosts

Status: design, agreed scope. Written before the refactor so the target is
reviewable. The measurements are from `9b63deb..HEAD`.

## The problem, measured

There are **three** syscall implementations in the tree:

| | lines | syscall cases | names syscalls by |
|---|---|---|---|
| `abi/syscall.hpp` | 2093 | 123 | `Sysno::read` (generated SSOT) |
| `runtime/windows/sys.hpp` | 751 | 71 | `SYS_read` / raw `case 0:` |
| `runtime/darwin/trap.hpp` | 4455 | 14 | `Sysno::` (2) + ad-hoc |

**46 syscalls are implemented twice** — once portable, once in Windows:

```
access chdir close dup dup2 exit exit_group faccessat faccessat2 fcntl
fstatfs getcwd getdents64 getegid geteuid getgid getpgrp getpid getppid
gettid getuid ioctl lseek lstat mkdir newfstatat open openat readlink
readlinkat rename rmdir rt_sigaction rt_sigprocmask sched_getaffinity
setgid setpgid setsid set_tid_address setuid sigaltstack stat statfs
uname unlink unlinkat
```

Nothing about Hyper-V makes `getpid` or `d_ino` mean something different.
This is accidental duplication, and it has already produced real bugs.

### What the duplication cost us

`linux_dirent64` — a frozen kernel ABI struct — is hand-encoded in three
places, with three different behaviours:

| | `d_ino` | `d_type` |
|---|---|---|
| `abi/syscall.hpp` | real host inode | real `DT_*` |
| `darwin/trap.hpp` | real host inode | real `DT_*` |
| `windows/sys.hpp` | **`pos + 1`** | **`DT_UNKNOWN`** |

The positional `d_ino` is a live bug: libalpm enumerates
`/var/lib/pacman/local`, stats each entry, and matches `st_ino` against the
`d_ino` it saw. A counter fails every comparison, so `pacman -Q` lists
nothing while the DB is intact. I fixed it in the portable layer; **Windows
still has it**, plus the `DT_UNKNOWN` bug, because the fix had nowhere
central to land.

`do_uname` is likewise duplicated (`abi/syscall.hpp:1943`,
`windows/sys.hpp:702`), each with its own `"linuxity"` string.

## Why it happened

The portable dispatcher's default is `return fwd()` — forward to the host
kernel. That works on Linux, where there IS a Linux kernel underneath. On
macOS and Windows there isn't, so `read`/`write`/`mmap`/`futex` have to be
*implemented*, not forwarded. Windows' answer was a second dispatcher, and
once it existed, 46 syscalls that had nothing to do with that problem
drifted into it too.

So the axis was wrong. The question isn't "which host am I on", it's:

> **Does this syscall need host facilities, or is it pure policy over state
> linuxity already owns?**

## The design

Three layers, split on that question. Each syscall is implemented **once**.

```
abi/
  sysno.hpp        identity: the ONLY way to name a syscall (generated)
  outcome.hpp      the fate sum type (done)
  wire/            kernel ABI struct encoders. pure functions, no host code.
    dirent64.hpp     encode_dirent64(ino, off, type, name) -> bytes
    utsname.hpp      one "linuxity" uname
    stat.hpp         struct stat / statx / statfs
    sysinfo.hpp
  syscall.hpp      THE dispatcher. every syscall, every host.

kernel/            policy over state we own (vfs, pids, creds). host-free.

runtime/
  backend.hpp      the trap contract (done)
  hostcalls.hpp    NEW: the host-facility contract (read/write/mmap/clock...)
  linux/           ptrace + seccomp. hostcalls = forward to the real kernel.
  darwin/          HVF.          hostcalls = Darwin syscalls.
  windows/         WHP.          hostcalls = Win32.
```

### Rule 1 — `Sysno` is the only syscall name

`windows/sys.hpp`'s `case SYS_read:` and `case 0:` become `case Sysno::read`.
Raw numbers bypass the generated SSOT, which is exactly how a mistyped number
routes one syscall to another's handler — the one bug class here that yields
plausible wrong answers instead of errors.

### Rule 2 — a kernel struct is encoded exactly once

Every `abi/wire/` encoder is a `constexpr` pure function from values to
bytes. No `DIR*`, no `HANDLE`, no `hv_*`. Field offsets are pinned by
`static_assert` for both ABIs, so it is testable without a VM and a layout
mistake fails the build.

A backend supplies **values**, never layout: "here are this directory's
entries as `(name, ino, type)`". `readdir` vs `FindNextFileW` is the only
genuinely host-specific part. `DT_UNKNOWN` stops being a per-backend
decision, because backends no longer write the byte.

### Rule 3 — one dispatcher, parameterised by host facilities

`abi::Syscalls` gains a `HostCalls` type parameter: the thin set of things
that genuinely need the host.

```cpp
template <class T>
concept HostCalls = requires(T h) {
    { h.read(Fd{}, std::span<std::byte>{}) } -> std::same_as<Result<std::size_t>>;
    { h.write(Fd{}, std::span<const std::byte>{}) } -> std::same_as<Result<std::size_t>>;
    { h.mmap(/*...*/) }       -> std::same_as<Result<UAddr>>;
    { h.clock_now(ClockId{}) } -> std::same_as<Result<Timespec>>;
    // ...
};
```

- **Linux** implements it by *forwarding* to the real kernel (the current
  `fwd()` path), so nothing regresses.
- **darwin/windows** implement it with Darwin syscalls / Win32.

Then `getpid`, `uname`, `getdents64`, `stat`, the credential and path
syscalls — all 46 — exist once, in `abi/syscall.hpp`, and every host gets the
same answer. A backend implements only what it uniquely must: how to trap
(`SyscallTrap`) and how to reach its host (`HostCalls`).

## Enforcement

Design rules that aren't checked decay. `tools/check_layout.sh` gains:

1. No file outside `abi/wire/` may write `d_reclen` or `memcpy` into a
   guest dirent buffer. *(This grep alone would have caught the Windows
   inode bug.)*
2. No file outside `abi/` may `switch` on a raw syscall number.
3. `abi/wire/` must not include any platform header or backend.
4. Every backend `static_assert`s both `SyscallTrap` and `HostCalls`.

## Order of work

Each step leaves the tree compiling and green.

1. `abi/wire/dirent64.hpp` — one encoder, three call sites deleted. Fixes
   the Windows `d_ino` and `DT_UNKNOWN` bugs as a side effect. Provable on
   Linux today.
2. `abi/wire/utsname.hpp` — deletes the duplicate `do_uname`.
3. Layout rules 1 and 3, so the regression can't come back.
4. `runtime/hostcalls.hpp` + the Linux implementation (forwarding). No
   behaviour change; this is the seam.
5. Migrate Windows' 46 duplicated cases onto the portable dispatcher,
   deleting them from `windows/sys.hpp`.
6. Rule 2 (no raw syscall numbers outside `abi/`) once step 5 lands.

Steps 1-4 are verifiable on this host. Steps 5-6 touch Windows-only code
that cannot be compiled here, so they need a Windows build before being
trusted — the static_asserts will catch shape errors, not behaviour.
