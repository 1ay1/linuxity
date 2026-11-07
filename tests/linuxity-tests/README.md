# linuxity-tests

A Python test suite that checks whether an environment behaves like Linux.
It needs only Python 3.10+ and the usual userland tools. Run it the same way
natively, inside linuxity, in a container, or anywhere else:

    python3 run.py                         # everything, one test at a time
    python3 run.py -j8                     # 8 at once (timing-sensitive tests still run alone)
    python3 run.py process memory          # whole areas
    python3 run.py terminal/pty '*fifo*'   # a module, or globs over area/module:name
    python3 run.py --list                  # what would run, with tags
    python3 run.py -v                      # tracebacks and test output for failures
    python3 run.py --timeout-scale 2       # slow device

Compare two environments by saving one run and diffing the other against it:

    python3 run.py -j8 --json native.json               # on real Linux
    linuxity python3 run.py -j8 --compare native.json   # under linuxity

## Layout

    kernel/      procfs, sysfs, syscalls (errno contracts), capabilities, io_uring
    process/     fork/exec/wait, signals, scheduling, namespaces
    memory/      mmap, memfd, protection
    filesystem/  vfs, permissions, inotify, concurrency (appends, renames, locks, fifos)
    networking/  tcp, udp, unix, epoll (+ eventfd, timerfd, pidfd, asyncio)
    terminal/    pty, termios, terminal-generated signals and shell job control
    tools/       coreutils, findutils/grep/sed/awk/tar, the shell
    lxt/         the framework: @test, check/eq/expect_errno, spawn/reap, sh, raw syscalls

## How a test runs

Each test is a plain function marked with `@test`. It runs in its own forked
process group, inside a fresh scratch directory, with a deadline. If it
hangs, crashes or leaves children behind, the whole group gets killed and
the next test starts clean. A test passes by returning (the returned string
is the summary line), fails by raising, and skips by calling `skip(why)`.

Tags:

- `serial` tests are timing-sensitive and never run beside another test.
- `root` tests skip unless uid is 0.
- `host` tests answer what the *host kernel* allows when the environment
  isn't bare metal (a container, chroot, proot or linuxity). Examples are
  io_uring, capabilities and creating namespaces. Their results are marked
  `[host]` there.

A refusal counts as a skip when it's the documented way to say "not
available". For example io_uring returning ENOSYS/EPERM makes liburing users
fall back. An answer that differs from Linux is always a failure.
