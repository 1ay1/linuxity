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
./build/linuxity
```

Requires a C++23 compiler (`std::expected`, concepts). Tested with GCC 16.

## Status

Foundational skeleton: the type algebra, the subsystem concept lattice, the
host boundary, and an end-to-end syscall dispatch path are in place and
proven by tests. The subsystem *bodies* (a real VFS with tmpfs/procfs/overlay
backends, CoW fork, futex, epoll, an ELF loader) are the road ahead — but the
architecture they slot into is fixed and machine-checked.
