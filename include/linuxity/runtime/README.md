# `linuxity/runtime/` — the trap backends

This directory answers one question: **how do guest syscalls get intercepted
on this host?** Everything above it (`abi/`, `kernel/`, `vfs/`) is portable and
doesn't know or care.

## Layout

| path | what's in it | built on |
|---|---|---|
| `backend.hpp` | **the contract.** What a backend must provide, and the named optional capabilities. | every host |
| `trap.hpp` | the native-execution run loop, written ONCE against that contract | every host |
| `resource_governor.hpp` | cgroup-style limits | every host |
| `shared/` | host-agnostic logic two backends need | every host |
| `linux/` | ptrace + seccomp (`PTRACE_SYSCALL`, SIGSYS fast path) | Linux |
| `darwin/` | Hypervisor.framework | macOS/arm64 |
| `windows/` | Windows Hypervisor Platform | Windows/x86-64 |

## The rules

Enforced by `tools/check_layout.sh`, which runs as the `runtime_layout` test:

1. **No backend includes another backend.** Each compiles only on its own host,
   so a cross-include is either dead code or a layering bug.
2. **Portable headers don't depend on a backend.** `backend.hpp` and
   `trap.hpp` are the contract and the loop. If they reach into `darwin/`, the
   concept stops meaning anything.
3. **`shared/` touches no platform API** — no `hv_*`, no `WHvRun`, no
   `PTRACE_*`, no `__APPLE__`/`_WIN32`.
4. **Every backend asserts itself against the contract** where it is defined.

Rule 1 exists because it was already broken. These files used to sit in one
flat directory, told apart by an `hvf_`/`whp_`/`ptrace_` filename prefix, and
the *Windows* backend included `hvf_vma.hpp` — because that file was actually
host-agnostic and merely misnamed. It's now `shared/address_space.hpp`. A
prefix is a convention you can violate by accident; a directory plus a checked
rule is not.

## Adding a backend

1. Make a directory. Implement the core `SyscallTrap` from `backend.hpp` —
   `start`, `next`, `resume`, `forward`, `redirect`, `exited`, `exit_code`.
2. `static_assert(SyscallTrap<YourTrap>)` next to the class. A missing or
   mistyped method is a build error naming it.
3. Add capabilities as you go, each with its own `static_assert`. Until then
   the run loop returns a truthful errno (`ENOTSUP` for an untranslatable
   socket, `ENOEXEC` for a dynamic exec it can't rewrite) instead of guessing.

That last point is the whole design. The loop used to probe with
`if constexpr (requires { trap_.rewrite_sockaddr(...); })` and fall back to a
plain forward — which forwarded the **untranslated guest path**, putting the
guest's AF_UNIX socket on the host filesystem. A typo in a method name
couldn't fail the build. Now capability gaps are named, asserted, and fail
loudly.

## Backend capability matrix

Current state, as asserted in each backend's header:

| capability | `linux/` | `darwin/` | `windows/` |
|---|---|---|---|
| core `SyscallTrap` | yes | yes | yes |
| two-path redirect + scrub | yes | yes | no |
| `forward_sync` (dup fd mirroring) | yes | yes | no |
| AF_UNIX path translation | yes | yes | no |
| exec through interpreter | yes | yes | no |
| signal delivery to guest pid | yes | yes | no |
| proc events (clone/exec/exit) | yes | no | no |

`windows/` is core-only today. That was previously invisible — the loop's
silent fallbacks hid it — and is now a documented fact with one place to
update as each capability lands.
