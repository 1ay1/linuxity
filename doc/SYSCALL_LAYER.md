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

1. **DONE** (`2bc7191`) `abi/wire/dirent64.hpp` — one encoder, three call
   sites deleted. Fixed the Windows `d_ino` and `DT_UNKNOWN` bugs as a side
   effect. Darwin's duplicate `DType`/`dirent_reclen`/`dtype_from_mode` folded
   in. Layout rules added for both.

2. **DONE** `abi/wire/errno_map.hpp` — one host-errno table. This found a
   second live bug: `PosixHost::read`/`write` returned `EIO` for *every*
   failure, and `from_errno` mapped six values and sent the rest to `EIO`. A
   guest saw "I/O error" for a full disk (`ENOSPC`), a closed pipe (`EPIPE`)
   and a would-block (`EAGAIN`) — precisely the errors programs branch on.

3. **DONE** `runtime/hostcalls.hpp` + `runtime/posix_hostcalls.hpp` — the
   seam, with its reference implementation. `HostCalls` has no capability
   tier on purpose: a host that cannot read an fd cannot run a guest, so
   every member is required and a gap is a build error. `HostMemory` is
   separate because Linux forwards `mmap` to the real kernel and has no use
   for it. `test_hostcalls` pins the contract (including a negative test that
   a partial host FAILS it) and the errno regressions.

4. **REVISED, and the original plan was wrong.** Step 4 was "migrate the
   portable dispatcher's host-touching paths onto `HostCalls`". Measuring it
   first showed there are none:

   ```
   grep -E '::(read|write|open|close|clock_gettime|getentropy)\(' abi/syscall.hpp
   -> no matches
   ```

   The portable dispatcher reaches the outside world only through
   `k_.files()` (73 sites), `k_.procs()` (2) and `k_.machine()` (2) — all
   subsystem concepts. It is ALREADY host-free, which is why Linux works by
   returning `fwd()` and never calling a host primitive itself.

   So `HostCalls` has exactly one real consumer: a backend with no Linux
   kernel under it, which must IMPLEMENT what Linux forwards. That is why
   `posix_hostcalls.hpp` was still worth building — it is the reference
   implementation and the compile-time proof of the contract — but there is
   nothing in `abi/` to migrate onto it. Step 4 is therefore complete as
   written, with no dispatcher change.

5. **NEXT, and now measured.** `windows/sys.hpp` is 775 lines:

   | | lines | verdict |
   |---|---|---|
   | genuine Win32 host I/O | **13** | irreplaceable; belongs in a backend |
   | hardcoded policy answers | **50** | duplicates `abi/`, and is WRONG |
   | path / fd / dirent plumbing | ~700 | duplicates `kernel/` + `abi/` |

   Thirteen lines of that file have any business existing. The rest is a
   reimplementation, and a worse one: `getpid`/`gettid`/`getppid` return a
   hardcoded `1`, so on Windows **every process sees pid 1** while the
   portable dispatcher has returned real per-task guest pids all along.

   The migration is therefore: route `WhpTrap` through `abi::Syscalls` with a
   `WhpHostCalls` supplying those 13 lines' worth of primitives, and delete
   the rest. That is the step that cannot be compile-verified on this host.

6. No raw syscall numbers outside `abi/` — as a layout rule — once 5 lands.

Steps 1-4 are verifiable on this host. Steps 5-6 touch Windows-only code that
cannot be compiled here, so they need a Windows build before being trusted:
the static_asserts catch shape errors, not behaviour.

## Bugs this has found so far

Every one was a consequence of the duplication, not a coincidence:

| bug | found by | status |
|---|---|---|
| `pacman -Q` lists 0 of 139 packages (positional `d_ino`) | running Arch | fixed |
| Windows `d_type` always `DT_UNKNOWN` | unifying the encoder | fixed |
| every host error collapsed to `EIO` | unifying the errno table | fixed |
| Windows `getpid`/`gettid`/`getppid` hardcoded to 1 | reading the second dispatcher | step 5 |
| `rewinddir()` returns 0 entries on a merged dir | running Arch | open |

## Open bug: `_dl_get_origin` abort during pacman extraction

Found after the `lseek`/`d_ino` fixes, and worth writing down precisely
because it is a PRE-EXISTING bug those fixes merely made REACHABLE.

```
installing jq...
Fatal glibc error: dl-origin.c:42 (_dl_get_origin): assertion failed: linkval[0] == '/'
error: command terminated by signal 11: Segmentation fault
```

Verified against `9b63deb` (before any of this work): the original code aborts
the transaction EARLIER, with `could not create directory
/var/lib/pacman/local/<pkg>/: File exists`, so it never reaches this point.
Same commit sees **0** packages from `pacman -Q`; current HEAD sees **141**. So
this is strictly forward progress that uncovered a deeper fault, not a
regression.

What is ruled out, each tested directly under linuxity:

* `readlink("/proc/self/exe")` is correct and absolute — in the main process,
  in a `fork`+`exec` child, and from a `#!` script.
* `/proc/self/cwd` and `/proc/self/root` are correct and absolute.
* Relative symlink targets (`/bin -> usr/bin`, `/usr/bin/awk -> gawk`) are
  correct: real symlinks genuinely are relative, and glibc only asserts on the
  `/proc/self/exe` result.
* Every hook `Exec` runs clean standalone (`ldconfig -r .`, `locale-gen`,
  `iconvconfig`, `update-ca-trust`, `systemd-sysusers`).
* `chroot("/")` + `chdir("/")` then readlink is still absolute.
* Not pacman's sandbox: `--disable-sandbox` aborts identically.
* Not the hooks at all — `--debug` shows the abort BEFORE any `running hook`
  line, i.e. during libalpm's own extraction.

So the failing `readlink` happens inside libalpm's extraction child, in a state
the above probes do not reproduce. The next step is to catch the actual
`readlink` argument and return value at the moment of the abort (trace the
path string, not just the fate), rather than guessing which path it is.

Not a blocker for the syscall-layer work, and tracked here so it is not
rediscovered from scratch.

## The abi/wire layer, as it stands

Ten headers. Each is the ONE definition of a piece of guest ABI, with its
values verified against real kernel headers and its traps asserted.

| header | owns | was |
|---|---|---|
| `dirent64.hpp` | `linux_dirent64` encoder, `DType` | 3 encoders, divergent |
| `errno_map.hpp` | host errno → guest `Errno` | 3+, all lossy |
| `stat.hpp` | `struct stat`/`statx` offsets, `S_IF*`, perm mask | 3 / 3 / 6 |
| `open_flags.hpp` | `O_*` + the writable() test | 3 (octal/hex/constexpr) |
| `mmap.hpp` | `PROT_*`, `MAP_*` | 4 |
| `at_flags.hpp` | `AT_*`, `AT_FDCWD` | 7 |
| `fd_flags.hpp` | `*_CLOEXEC`, `*_NONBLOCK` | 5, **two values** |
| `time.hpp` | `timespec`/`timeval`, normalize, ms rounding | 3 |
| `iovec.hpp` | `struct iovec`, `IOV_MAX` | 2 |
| `path.hpp` | `.`/`..` normalization | 2, **different algorithms** |

### How the remaining duplication was found

Name-based grepping kept missing copies. Two shapes found the rest:

1. `constexpr k[A-Z]... =` **inside a function body** — a constant cheap to
   retype gets retyped at the point of use. This found the fifth `kCloexec`,
   the second `AT_FDCWD`, and the `S_IF*` triple.
2. A bare octal/hex literal in a **mask or comparison** — `& 0x100`,
   `& 07777`. This found the two raw `AT_SYMLINK_NOFOLLOW` sites whose own
   comments named the constant, so no name search could see them.

### What is deliberately NOT shared

Checked, and left alone on purpose:

* `GuestRegs` — darwin's is the aarch64 register set, windows' is x86-64.
  Verified the fields genuinely differ (`x0`/`x8`/`sp` vs `rax`/`rdi`).
* `LinuxStat` — the layouts really do differ per ABI; both `static_assert`
  against `stat.hpp` instead.
* `Dirent` — `abi/wire`'s is the ABI record, `vfs/inode`'s is a VFS entry
  (`name` + `Ino` + `FileType`). Same noun, different concepts.
* Host→guest flag TRANSLATION (`open_flags()`, `error_to_errno`) stays in
  each backend: Darwin's `O_CREAT` is `0x200`, Win32 has no `O_*` at all.
  Only the guest-side definition is shared.
* Five single-use literals (`MSG_CMSG_CLOEXEC`, `CSIZE`, `makedev`'s field
  split, and `cpsr`'s NZCV mask — which is a CPU register, not guest ABI).
  One use is not duplication, and a header per literal is ceremony.

## The fd table: shared, but not yet adopted

`runtime/darwin/fd.hpp` (250 lines) and `runtime/windows/fd.hpp` (279) each
carry a full `FdTable`, and the overlapping half is line-for-line identical:

```
install()          lowest-free-slot scan, grow, EMFILE at the cap
close()            drop the slot, EBADF if unknown
dup()/dup2()       share the same file via shared_ptr
cloexec/set_cloexec
on_exec()          drop every slot whose cloexec bit is set
```

Only two things genuinely differ: the handle type (`int` vs `HANDLE`) and the
per-slot extra state (Darwin tracks an eventfd `peer`; Windows tracks append
mode, tty-ness, the guest path, a `DirCursor`).

`runtime/shared/fd_slots.hpp` is that logic as a template over exactly those
two axes — `FdSlots<File, Extra>` — with `test_fd_slots` covering it: lowest-free
allocation, hole filling, dup sharing the file by reference, dup carrying the
extra payload, `dup2(fd,fd)` not clearing cloexec, the EMFILE cap, and
`on_exec` dropping exactly the right slots.

**It is not wired into either backend yet, and that is deliberate.** Adoption
means rewriting 33 `slots_` sites in `darwin/fd.hpp` and 34 in
`windows/fd.hpp` — 67 edits in two files that **cannot be compiled on a Linux
host**. The shared header is written, compiled and tested; substituting it
blind would trade a verified duplication for an unverified rewrite of the fd
layer, which is the subsystem where a mistake shows up as a guest reading the
wrong file much later.

Writing it first was still worth it: the test immediately caught a real bug in
my own `reserve_low_fds`, which resized the table to 3 instead of installing
entries. An empty slot is still *free*, so the lowest-free scan would have
handed out fd 0 and a guest's `open()` would have returned 1 — writing its
data into stdout. That function is now deliberately absent from the shared
layer, because both backends reserve the low fds by **opening real host
descriptors** (`/dev/null` for 0..8), which is a host operation.

### Adoption checklist, for a host that can build it

1. On macOS: make `darwin::FdTable` hold `FdSlots<HostFd, DarwinExtra>` where
   `DarwinExtra { std::shared_ptr<HostFd> peer; }`. Keep `export_table` /
   `import_table` (the fork handoff) in the backend — they serialize host
   state. Build and run the `hvf_run` test.
2. On Windows: `FdSlots<WinFd, WinExtra>` with
   `WinExtra { bool append, is_tty; std::string path; std::unique_ptr<DirCursor> dir; }`.
   The move-only `dir` is already handled: `dup()`/`dup_to()` take the new
   slot's `Extra` by value rather than copying the source's, so a move-only
   `Extra` instantiates (verified by compiling exactly that shape). That also
   forces the right answer for directory fds — a dup'd dir fd needs its OWN
   cursor, since a shared one would let two fds consume each other's entries.
   Pass the path binding through explicitly; let the cursor default to fresh.
3. Delete the duplicated halves; `test_fd_slots` already covers the behaviour.


## Correction: there are not three dispatchers

I spent several rounds describing "three syscall dispatchers" with 30
syscalls implemented three times. That framing was wrong, and tracing the
actual control flow is what corrected it.

**darwin drives the portable dispatcher.** `src/main_macos.cpp` constructs
`runtime::Cpu loop{trap, ...}`, so `abi::Syscalls::dispatch()` decides every
fate and hands `HvfTrap` an already-translated path via `redirect()`. Its 277
`case S::` labels live in `service()`, reached only through `forward()` /
`redirect()` — they are the **FORWARD implementation**: the work a Linux host
gets free from its kernel and macOS has to emulate. That is not duplication,
it is the thing the `Outcome` sum type was built to express.

**windows is the real duplicate.** `src/main_windows.cpp` runs its own
hand-rolled loop (`sys.service(f)` at line 400), bypassing `runtime::Cpu` and
`abi::Syscalls` entirely. Its 72 cases *are* a second dispatcher.

So the remaining work is one backend, not three, and the fix is the one
already written down as step 5: route `WhpTrap` through `runtime::Cpu` with
`WhpHostCalls` supplying the host primitives.

### What the overlap actually was

Of the 30 "three-way" syscalls, only one family wanted the same answer
everywhere, and it is now shared in `abi/identity.hpp`:
getpid/gettid/getppid/getuid/geteuid/getgid/getegid.

The rest failed the test deliberately:

| family | why not shared |
|---|---|
| sessions (`getpgrp`, `setsid`, …) | darwin has a real pgid/sid table; a shared flat answer would make it WORSE |
| lifecycle (`exit`, `exit_group`) | portable forwards, darwin unwinds one thread, windows ends the VM — three different acts |
| `setuid`/`setgid` | belong to the dispatcher's wider credential group (`setreuid`/`setresuid`/`setgroups`/`setfsuid`); lifting two of that set out would re-create the problem |
| path/fd ops | the translation is ALREADY shared — the dispatcher does it and passes a host path down. Only the host call differs, which is what a backend is for. |

The test for `abi/identity.hpp` is: an answer belongs there only when every
backend should give the same one. I wrote a `flat_session_answer()` helper,
found nothing could use it without losing fidelity, and deleted it — dead
shared code is worse than none.
