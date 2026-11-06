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
goldens/<platform->?<arch>/<scenario-key>.trace
```

Two axes, both part of the **identity**, not metadata.

The **arch** comes first because the two Linux ABIs are not interchangeable:
56 syscalls exist on x86-64 and not on aarch64 (`open`, `fork`, `stat`,
`lstat`, `arch_prctl`; aarch64 has only `openat`, `clone`, `newfstatat`). An
x86-64 golden replayed on aarch64 would compare against a trace that cannot
occur there.

The **platform** prefix exists because the same ABI can still disagree about
what a syscall RETURNS. Android is aarch64 Linux plus an SELinux policy that
denies the `shell` domain things a desktop kernel allows, and the denial
arrives *before* the kernel's own check — so the errno differs, not just the
verdict. Measured on a Pixel 6a against this laptop:

| step | desktop x86-64 | Android aarch64 |
|---|---|---|
| `TCGETS2` on a pty slave | `0` | `-EACCES` |
| `TIOCGSID` before we own the tty | `-ENOTTY` | `-EACCES` |
| `TIOCNOTTY` on our pty | `-ENOTTY` | `-EACCES` |

If both lived in `aarch64/`, recording on a desktop arm64 kernel would flip
those to `-ENOTTY` and the diff would read as a linuxity regression. They are
separate recordings of two real kernels, and both must hold.

`Platform::linux_` renders as the empty prefix, so a desktop set keeps the
plain `x86_64/` and `aarch64/` names and nothing moves when the axis is added.

## Recording

Needs a real Linux kernel, so it only runs on the Linux hosts. Do it once per
arch and commit the result:

```sh
cmake --build build --target record_goldens
LX_PROBE_DIR=$PWD/build/probes ./build/tests/record_goldens
```

`record_goldens` refuses to run on a non-Linux host rather than producing a
golden with no kernel behind it.

### Recording the Android set

The `android-aarch64` goldens were recorded on a **real Android device**
(Pixel 6a, Linux 6.1 GKI, arm64, domain `u:r:shell:s0`), not an emulator or a
cross-build. Two things make that non-negotiable:

- **qemu-user cannot do it.** linuxity is a ptrace supervisor, and qemu-user
  services guest syscalls itself, so there is no real trap for
  `PTRACE_SYSCALL` to intercept — linuxity hangs with no output. Tried,
  measured, dead end.
- **A desktop arm64 VM is the wrong kernel.** It boots and runs fine, but it
  reproduces none of the SELinux denials, so its goldens describe a platform
  the guest will not meet on a phone.

To re-record, build with the NDK (which defines `__ANDROID__`, so the platform
tags itself) and run on the device:

```sh
cmake --build build-android --target record_goldens
adb push build-android/tests/record_goldens build-android/probes /data/local/tmp/lxconf/
adb shell 'cd /data/local/tmp/lxconf && \
  LX_PROBE_DIR=$PWD/probes LX_GOLDEN_DIR=$PWD/goldens ./record_goldens'
adb pull /data/local/tmp/lxconf/goldens/android-aarch64 tests/goldens/
```

The `ioctls` golden pins the denials directly --

```
ioctl = -EACCES | TCGETS2 on the pty slave
```

-- because the shell domain's ioctl whitelist for devpts predates termios2.
That is the real kernel's answer on that platform, so it is what the golden
says. linuxity deliberately diverges there (it serves the request with the
classic ioctl), and the `HostPolicyMayDeny` law is what permits that one
direction: succeed where the host denied by policy, never the reverse.

With only an x86-64 golden, every Android-specific path had no reference at
all -- which is how four tty bugs shipped in a day. There is a script for the
whole cycle, because a procedure that lives only in someone's shell history
is a procedure that stops being run:

```sh
scripts/conform-android.sh            # build, push, diff against the device
scripts/conform-android.sh --record   # ...and re-record the goldens
```

It builds for the device, pushes linuxity and every probe, runs the probes
twice (natively and under linuxity) on the phone, and diffs. Each device step
has a hard deadline, so a guest that hangs fails the run instead of wedging
it. Exit status is meaningful, so it can gate CI.

A probe must emit the SAME NUMBER OF STEPS on every host, because traces are
compared step by step: a check skipped after a failure shortens the trace and
misaligns everything after it against an unrelated operation. Where a check
cannot be answered -- its precondition failed -- emit `LX_NA` rather than 0,
so "unanswerable" is distinguishable from "false".

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
