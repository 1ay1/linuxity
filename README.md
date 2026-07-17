# linuxity

A **portable, type-theoretic implementation of the Linux userspace ABI**.

Not a VM. Not instruction emulation. `linuxity` is a userspace
re-implementation of the Linux kernel/user contract: guest ELF binaries run
**directly on the host CPU at native speed** while the runtime *is the
kernel* — it services their syscalls.

The distro you install is decoupled from the instruction set:

| | what it is | runs at |
|---|---|---|
| **the environment** | an Arch / Alpine / Debian rootfs — files, `/proc`, the package manager, the ABI contract | — |
| **the guest code** | ELF binaries in that rootfs | **native CPU speed** |
| **the ISA** | whatever the host is (x86-64 here) | native — no emulation |

So on an x86-64 host you install the **x86-64 build** of the distro and every
instruction runs bare on the CPU — no VM, no `/dev/kvm`, no interpreter. A
*foreign*-arch rootfs is the only case that needs a binary-translation
backend (FEX / Rosetta-style), and that plugs in behind the same ABI at the
ISA boundary — it is not the core.

```
            Linux program (AArch64 ELF)
                      │
             Linux syscall ABI            ← abi/syscall.hpp
                      │
        ┌──────────────────────────┐
        │        Kernel            │      ← the *product* of subsystems
        │  VFS · Process · Memory  │      ← kernel/subsystem.hpp (concepts)
        │  IPC · Net · /proc · …   │
        └──────────────────────────┘
             │        │        │
          PosixHost  Darwin   Windows      ← host/host.hpp (a tiny concept)
             │        │        │
          Linux    macOS/iOS  Windows
```

The guest **only ever talks to the runtime**, never the host OS.

## The design, in types

| Idea | Encoded as |
|------|-----------|
| A syscall is a total function `Args → Errno + Value` | `Result<T> = std::expected<T, Errno>` |
| errno can't be confused with a value/fd/pid | `enum class Errno`, strong `Id<Tag>` newtypes |
| `read` / `write` / `open` / `mount` are one subsystem | `concept Vfs` |
| the kernel is the *product* of subsystems | `concept IsKernel = Vfs && Process && Memory` |
| the host is a swappable primitive layer | `concept Host` (static polymorphism, zero vtables) |
| a guest pointer must never be dereferenced un-validated | `UAddr` / `UserPtr<T>` — un-dereferenceable by construction |
| do-notation / `?` for error propagation | `LX_TRY(expr)` |

Because subsystems and the host are **concepts**, the syscall dispatcher and
the whole runtime are written *once, generically*, and instantiated against:
the production kernel, a host-free `MockKernel` in tests, or a future
JIT-backed kernel — with no virtual dispatch in the hot path.

## Layout

- `include/linuxity/abi/`    — `result.hpp`, `types.hpp`, `syscall.hpp`
- `include/linuxity/kernel/` — `subsystem.hpp` (concepts), `authority.hpp` (the host-authority boundary), `kernel.hpp`
- `include/linuxity/vfs/`    — `inode.hpp` (FileSystem concept), `tmpfs.hpp` (in-memory backend), `vfs.hpp` (mount table + path resolution)
- `include/linuxity/host/`   — `host.hpp` (the concept), `posix_host.hpp` (Linux/Darwin backend)
- `src/main.cpp`             — wires host → kernel → ABI, issues guest syscalls
- `tests/`                   — host-free type-algebra, authority, and VFS tests

## Build

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build

# run a NATIVE Linux binary under the runtime (native speed, no VM):
./build/linuxity /path/to/binary [args...]

# ...including real distro binaries with the dynamic linker:
./build/linuxity /usr/bin/uname -a
#   -> Linux linuxity 6.6.0-linuxity #1 linuxity portable Linux ABI x86_64
./build/linuxity /usr/bin/id
#   -> uid=0(root) gid=0(root) ...      (identity VIRTUALIZED by linuxity)

# mount an extracted distro rootfs as the guest '/':
./build/linuxity --root ./alpine-rootfs /bin/sh
```

Requires a C++23 compiler (`std::expected`, concepts). Tested with GCC 16.
Native execution uses a `ptrace` trap backend on Linux/x86-64: the guest runs
its own instructions on the CPU; each syscall is either **virtualized** by
linuxity's subsystems or **forwarded** to the host kernel acting on the guest.

## Status

**Real native Linux binaries — including dynamically-linked distro programs —
run under the runtime today.** `/bin/echo`, `/usr/bin/id`, `/usr/bin/uname`,
`date` all execute natively on the CPU while linuxity services their
syscalls. Two proofs of the model:

- `uname -a` reports **`Linux linuxity 6.6.0-linuxity`** (not the host
  kernel) — we intercept `uname`, synthesize linuxity's identity, and
  `copy_out` into the guest buffer.
- `id` / `whoami` report **`uid=0(root)`** — our virtualized `getuid`/`getgid`
  return the virtual world's root, not the host user.

Memory (`mmap`/`brk`/`mprotect`) and host-resource syscalls are forwarded so
native libc and the dynamic linker reach `main()`; identity, credentials,
lifecycle, and `uname` are virtualized. In place and proven by tests:

- the type algebra, subsystem concept lattice, and authority boundary;
- a real **VFS** (mount table, path resolution) with **tmpfs** and a
  **HostFs** backend that mounts a real on-disk rootfs directory as `/`;
- an **ELF64 loader** (PT_LOAD, .bss zero-fill, PT_INTERP) into a typed guest
  **address space**, plus SysV AMD64 **stack/auxv** init;
- an arch-neutral **syscall dispatcher** (per-arch tables → canonical `Sysno`)
  with a **virtualize-vs-forward** classifier, driven by a concept-based
  **trap** loop and a real `ptrace` backend.

The road ahead: virtualize the file path through the VFS (so `--root` needs
no privilege and `/proc` is synthesized), then clone/futex/epoll and a shell
from a pristine distro rootfs. The architecture is fixed and machine-checked.
