#!/bin/sh
# Run a command with a HARD deadline and no inherited stdin, so nothing can
# block on input or outlive its welcome. Output goes to a file and is echoed.
#
#   tools/t.sh [SECS] <command...>
#
# Defaults to 10s. Always returns: 124 means it was killed on the deadline.
# Use this for ANY command that touches a guest, a tracer, or a pty -- those
# are the ones that hang, and a hung command burns the whole turn.
set -u

DEADLINE=10
case "${1:-}" in
    [0-9]*) DEADLINE=$1; shift ;;
esac

[ $# -gt 0 ] || { echo "t.sh: no command" >&2; exit 2; }

# setsid + process-group kill: a tracer or shell that forks children must not
# leave them holding the pipe open after the parent dies.
setsid timeout -s KILL "$DEADLINE" "$@" < /dev/null 2>&1
rc=$?
[ "$rc" = 137 ] && rc=124
[ "$rc" = 124 ] && echo "[t.sh: KILLED after ${DEADLINE}s]" >&2
exit $rc
