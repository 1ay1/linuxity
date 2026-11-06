#!/usr/bin/env bash
# tools/coverage.sh -- how much of the dispatcher do the probes actually run?
#
# WHY THIS EXISTS. conform_coverage reports 100%, and that claim is true but
# narrower than it sounds: it means every INTERCEPTED HANDLER is named by some
# scenario. A handler counts as proven if one probe step touches it once. It
# says nothing about the branches inside.
#
# This measures the other thing -- line coverage of the syscall dispatcher
# under the whole probe suite. The gap between the two numbers is the honest
# answer to "is 100% really 100%":
#
#     handlers reached : 130/130   (conform_coverage)
#     dispatcher lines :  ~80%     (this)
#
# What is left is mostly error paths that need a failure the probes cannot
# easily stage (EFAULT on a copy that does not fail, ENOMEM), plus
# compatibility shims for specific programs. Finding a block that is NOT one
# of those is how the statfs-magic bug was found: 13 of 19 scenarios run
# host_backed, so the synthesized side of statx/statfs was dead, and probing
# it turned up /proc reporting TMPFS_MAGIC.
#
# Usage:  tools/coverage.sh [--list]     # --list names the dead blocks
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${LX_COV_BUILD:-/tmp/lx-coverage}"
PROBES="${LX_PROBE_DIR:-$REPO/build/probes}"

[ -d "$PROBES" ] || { echo "no probes at $PROBES -- build them first" >&2; exit 1; }

# A separate instrumented tree: --coverage changes codegen, so it must not
# pollute the build the tests run against.
if [ ! -f "$BUILD/CMakeCache.txt" ]; then
    cmake -S "$REPO" -B "$BUILD" -DCMAKE_BUILD_TYPE=Debug \
          -DCMAKE_CXX_FLAGS="--coverage" >/dev/null
fi
cmake --build "$BUILD" --target linuxity -j"$(nproc)" >/dev/null
find "$BUILD" -name '*.gcda' -delete

# Run every probe the way the suite does. dirseek takes the directory as an
# argument and defaults to /usr/bin -- running it bare leaves the VIRTUAL
# path (/proc, /sys) unexercised, which silently understated coverage by
# three points the first time this was measured by hand.
for p in "$PROBES"/*; do
    [ -x "$p" ] && timeout 60 "$BUILD/linuxity" "$p" >/dev/null 2>&1 || true
done
for d in /proc /sys /etc; do
    timeout 60 "$BUILD/linuxity" "$PROBES/dirseek" "$d" >/dev/null 2>&1 || true
done

cd "$BUILD"
gcov -o ./CMakeFiles/linuxity.dir/src/ \
        ./CMakeFiles/linuxity.dir/src/main.cpp.gcda >/dev/null 2>&1

python3 - "${1:-}" <<'PY'
import sys, collections
want_list = sys.argv[1] == "--list"
lines = open("syscall.hpp.gcov", errors="ignore").read().splitlines()
exe = hit = 0
dead = []
for l in lines:
    p = l.split(":", 2)
    if len(p) < 3:
        continue
    c, n = p[0].strip(), p[1].strip()
    if c in ("-", "") or not n.isdigit():
        continue
    exe += 1
    if c == "#####":
        dead.append((int(n), p[2].rstrip()))
    else:
        hit += 1

print(f"dispatcher line coverage: {hit}/{exe} = {100*hit/exe:.1f}%")
print(f"never executed: {len(dead)} lines")

if want_list and dead:
    runs, cur = [], [dead[0]]
    for a, b in zip(dead, dead[1:]):
        if b[0] == a[0] + 1:
            cur.append(b)
        else:
            runs.append(cur); cur = [b]
    runs.append(cur)
    runs.sort(key=len, reverse=True)
    print("\nlargest never-executed blocks:")
    for r in runs[:15]:
        body = " ".join(x[1].strip() for x in r)[:84]
        print(f"  L{r[0][0]:<5} ({len(r):2d})  {body}")
PY
