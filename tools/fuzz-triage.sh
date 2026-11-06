#!/usr/bin/env bash
# tools/fuzz-triage.sh -- shrink a differential-fuzz divergence to its cause.
#
# The fuzzer runs 400 generated operations and reports which ones answered
# differently under linuxity. That list is long and mostly CASCADE: once one
# operation has a different effect, every later one sees different state, so
# hundreds of steps "diverge" because of a single real bug.
#
# Hand-bisecting that is slow and error-prone -- I tried, repeatedly isolating
# a step into a standalone program only to find it agreed, because the real
# cause was several operations earlier. This does it mechanically: binary
# search on the operation COUNT for the smallest prefix that still diverges.
# The last operation of that prefix is the culprit, and everything after it is
# noise.
#
# Usage:
#   tools/fuzz-triage.sh                 # triage the default seed
#   LX_FUZZ_SEED=0x1234 tools/fuzz-triage.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${LX_BUILD:-$REPO/build}"
PROBE="$BUILD/probes/fuzz"
LINUXITY="${LX_BINARY:-$BUILD/linuxity}"
SEED="${LX_FUZZ_SEED:-}"

[ -x "$PROBE" ] || { echo "build probe_fuzz first" >&2; exit 1; }

# The guest resolves its program through its own namespace, so the probe has
# to live somewhere BOTH runs can reach by the same absolute path. /tmp is
# linuxity's private tmpfs, so it cannot be there.
stage="${LX_STAGE:-/var/tmp/lx-fuzz-stage}"
mkdir -p "$stage"
cp "$PROBE" "$stage/fuzz"

run() {   # run(n_ops) -> trace on stdout
    local n="$1" who="$2"
    # Leftovers change the answers, and the fuzzer can leave a directory
    # without write permission, so force it open before removing.
    chmod -R u+rwX /tmp/lx-fuzz-probe 2>/dev/null || true
    rm -rf /tmp/lx-fuzz-probe
    # env keeps the assignments in the environment rather than letting a
    # ${SEED:+...} expansion land where the command name goes -- with a seed
    # set, that made the shell try to execute "LX_FUZZ_SEED=N".
    if [ "$who" = native ]; then
        env LX_FUZZ_OPS="$n" ${SEED:+LX_FUZZ_SEED="$SEED"} "$stage/fuzz" 2>&1
    else
        env LX_FUZZ_OPS="$n" ${SEED:+LX_FUZZ_SEED="$SEED"} \
            "$LINUXITY" "$stage/fuzz" 2>&1 | grep -v '^linuxity:'
    fi
}

diverges() {   # diverges(n) -> 0 if the first n ops already differ
    local n="$1"
    ! diff -q <(run "$n" native) <(run "$n" guest) >/dev/null 2>&1
}

full="${LX_FUZZ_OPS:-400}"
if ! diverges "$full"; then
    echo "no divergence in $full operations${SEED:+ (seed $SEED)}"
    exit 0
fi

echo "diverges within $full operations -- bisecting"
lo=1; hi="$full"
while [ "$lo" -lt "$hi" ]; do
    mid=$(( (lo + hi) / 2 ))
    if diverges "$mid"; then hi="$mid"; else lo=$(( mid + 1 )); fi
done

echo
echo "SMALLEST DIVERGING PREFIX: $lo operations"
echo "the last one is the cause; everything after it is cascade."
echo
diff <(run "$lo" native) <(run "$lo" guest) | tail -6
