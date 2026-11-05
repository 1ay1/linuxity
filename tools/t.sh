#!/bin/sh
# Run a command with a HARD deadline and no inherited stdin, so nothing can
# block on input or outlive its welcome.
#
#   tools/t.sh [SECS] <command...>
#
# Defaults to 10s. Returns 124 if it was killed on the deadline.
#
# CAVEAT: do NOT wrap a guest that itself runs timeout(1) or otherwise manages
# its own process group -- this script puts the command in a new session and
# kills the whole group, which collides with the inner timeout's own group
# handling and reports a false 124. (It did: `timeout 1 sleep 5` under
# linuxity looked hung for an afternoon and was actually finishing in 1.005s
# vs 1.003s native.) For those, run the command directly and time it.
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
