#!/bin/sh
# Run a guest under linuxity and return as soon as it exits. Kills it after
# DEADLINE seconds so a stuck child can never hang the caller's pipe.
#
#   tools/probe.sh [-t SECS] [-o OUTFILE] [--pty] -- <program> [args...]
#   tools/probe.sh --pty -i /tmp/cmds -- /usr/bin/fish -i
#
# Output goes to OUTFILE (default /tmp/lx-probe.out) and is echoed on exit.
set -u

DEADLINE=15
OUT=/tmp/lx-probe.out
PTY=0
STDIN_FILE=/dev/null
QUIET=0
LX=./build/linuxity

while [ $# -gt 0 ]; do
    case "$1" in
        -t) DEADLINE=$2; shift 2 ;;
        -o) OUT=$2; shift 2 ;;
        -i) STDIN_FILE=$2; shift 2 ;;
        -q) QUIET=$2; shift 2 ;;
        --pty) PTY=1; shift ;;
        --) shift; break ;;
        *) break ;;
    esac
done

[ $# -gt 0 ] || { echo "probe.sh: no program given" >&2; exit 2; }

: > "$OUT"

if [ "$PTY" = 1 ]; then
    # script(1) gives the guest a real tty, which interactive shells need.
    setsid script -qec "$LX $*" /dev/null < "$STDIN_FILE" > "$OUT" 2>&1 &
else
    setsid "$LX" "$@" < "$STDIN_FILE" > "$OUT" 2>&1 &
fi
pid=$!

# Poll in short slices: return the instant the guest exits. For guests that
# never exit (interactive shells waiting on a tty), -q N returns once the
# output has been idle for N tenths of a second, which is what we actually
# want to inspect.
i=0
limit=$((DEADLINE * 10))
last_size=-1
idle=0
while [ $i -lt $limit ]; do
    kill -0 "$pid" 2>/dev/null || break
    if [ "$QUIET" -gt 0 ]; then
        size=$(wc -c < "$OUT" 2>/dev/null || echo 0)
        if [ "$size" = "$last_size" ] && [ "$size" -gt 0 ]; then
            idle=$((idle + 1))
            [ $idle -ge "$QUIET" ] && break
        else
            idle=0
            last_size=$size
        fi
    fi
    sleep 0.1
    i=$((i + 1))
done

if kill -0 "$pid" 2>/dev/null; then
    # Still alive: kill the whole process group, guest children included.
    kill -KILL -"$pid" 2>/dev/null
    kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    if [ $idle -ge "$QUIET" ] && [ "$QUIET" -gt 0 ]; then
        rc=0                      # settled output, guest just won't exit
    else
        echo "probe.sh: TIMEOUT after ${DEADLINE}s (killed)" >&2
        rc=124
    fi
else
    wait "$pid" 2>/dev/null
    rc=$?
fi

cat "$OUT"
exit $rc
