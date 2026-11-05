# linuxity conformance goldens

Recorded syscall traces, one file per scenario per guest ABI. These are what
let a host with **no Linux kernel** — macOS arm64, Windows x86-64 — verify
that its linuxity answers syscalls the way a real kernel does.

## What a golden is

The **native kernel's** answer to a scenario's probe, captured once on Linux
and committed. Each line is one observed syscall:

```
rt_sigaction = -EINVAL | catching SIGKILL is EINVAL
lseek = 1              | rewind by a byte delta (the fish case)
```

The format is the same one probes emit and the parser reads, so a golden is
literally a captured probe run. One grammar, both directions, nothing to
drift.

Deliberately **not** a recording of linuxity's own output. If it were, the
test would prove only that linuxity still does what it did on recording day —
a change detector, not a conformance check.

## Layout

```
goldens/<arch>/<scenario-key>.trace
```

The arch is part of the **identity**, not metadata. The two Linux ABIs are not
interchangeable: 56 syscalls exist on x86-64 and not on aarch64 (`open`,
`fork`, `stat`, `lstat`, `arch_prctl`; aarch64 has only `openat`, `clone`,
`newfstatat`). An x86-64 golden replayed on aarch64 would compare against a
trace that cannot occur there.

## Recording

Needs a real Linux kernel, so it only runs on the Linux hosts. Do it once per
arch and commit the result:

```sh
cmake --build build --target record_goldens
LX_PROBE_DIR=$PWD/build/probes ./build/tests/record_goldens
```

`record_goldens` refuses to run on a non-Linux host rather than producing a
golden with no kernel behind it.

## Who reads them

| test | reference | runs on |
|---|---|---|
| `conform_diff` | the live kernel | Linux only |
| `conform_replay` | these goldens | **every host** |

`conform_replay` needs only a `ProbeRunner`, not `HasLinuxKernel`, which is
why it instantiates everywhere. It is green on Linux too, so the replay path
is exercised in CI rather than only on the hosts that depend on it.

## When a golden goes stale

Editing a probe without re-recording shows up as a loud divergence, not a
silent pass:

```
memory  DIVERGES FROM GOLDEN
  step 38: number of syscalls differs
  native: 38
  guest:  39
```

A **missing** golden also fails. An unverified scenario is a hole, not a pass —
that is what stops the suite going quietly green as scenarios get added faster
than goldens get recorded.

## Re-recording after a deliberate change

If you changed a probe on purpose, re-record on each Linux arch and commit the
new goldens **with** the probe change. Review the diff: it is plain text, and a
line moving from `= 0` to `= -EINVAL` is exactly the kind of change worth a
second look.
