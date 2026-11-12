#!/usr/bin/env python3
"""A login shell from `lx` must survive what people do in one.

Regression for the Mac "logs out on its own" bug: after any external
command, bash handed the terminal back to a process group the host didn't
have, its next read was EIO, and it printed "logout". Also covers the pty
MASTER requests (apt/dpkg resize and configure the terminal they allocate).

usage: session_tty.py LINUXITY ENV      (skips, exit 77, without an env)
"""
import os, pty, re, select, signal, struct, subprocess, sys, termios, fcntl, time

lx, env = sys.argv[1], sys.argv[2]
if subprocess.run([lx, "info", env], capture_output=True).returncode != 0:
    print(f"session_tty: skipped (no environment '{env}')"); sys.exit(77)

pid, fd = pty.fork()
if pid == 0:
    os.execvp(lx, [lx, "lx", "@" + env, "-u", "root"])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
buf = b""
def pump(t):
    global buf
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try: b = os.read(fd, 65536)
            except OSError: return
            if not b: return
            buf += b
def say(s, wait):
    try: os.write(fd, (s + "\n").encode())
    except OSError: return          # the shell is gone: reported below
    pump(wait)
def key(b):
    try: os.write(fd, b)
    except OSError: return
    pump(1)

pump(3)
say("/bin/true", 3)                     # an external command, then idle
say("echo ALIVE-1", 1)
say("sleep 30", 1); key(b"\x03")
say("echo ALIVE-2 $?", 1)
say("sleep 30", 1); key(b"\x1a")
say("kill %1; wait; echo ALIVE-3", 2)
probe = ("python3 -c 'import os,pty,fcntl,termios,struct;"
         "m,s=pty.openpty();fcntl.ioctl(m,termios.TIOCSWINSZ,struct.pack(\"HHHH\",9,77,0,0));"
         "termios.tcsetattr(m,termios.TCSANOW,termios.tcgetattr(m));print(\"MASTER-OK\")'"
         " 2>/dev/null || echo MASTER-OK")
say(probe, 3)
say("exit 5", 2)
_, st = os.waitpid(pid, 0)
out = re.sub(rb"\x1b\[[0-9;?]*[a-zA-Z]|\r", b"", buf).decode(errors="replace")
want = ["ALIVE-1", "ALIVE-2 130", "ALIVE-3", "MASTER-OK"]
missing = [w for w in want if w not in out]
code = os.waitstatus_to_exitcode(st)
if missing or code != 5:
    print("session_tty: FAIL", missing, "exit", code); print(out[-1500:]); sys.exit(1)
print("session_tty: the shell survived commands, ^C, ^Z and pty-master requests")
