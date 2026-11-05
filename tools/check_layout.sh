#!/bin/sh
# Structural invariants for include/linuxity/runtime/.
#
# The backends used to live in one flat directory, told apart only by an
# hvf_/whp_/ptrace_ filename prefix. That let a real mistake through: the
# Windows backend included hvf_vma.hpp (macOS-prefixed) because the file was
# actually host-agnostic and misnamed. A prefix is a convention; a directory
# plus this check is a rule.
#
# Run from the repo root. Exits nonzero on a violation.
set -e
cd "$(dirname "$0")/.."
R=include/linuxity/runtime
fail=0

note() { printf '  FAIL: %s\n' "$1"; fail=1; }

# 1. No backend may include another backend's headers. Each is compiled only
#    on its own host, so a cross-include is either dead or a layering bug.
for a in linux darwin windows; do
    for b in linux darwin windows; do
        [ "$a" = "$b" ] && continue
        hits=$(grep -rl "runtime/$b/" "$R/$a/" 2>/dev/null || true)
        [ -n "$hits" ] && note "$a includes $b: $hits"
    done
done

# 2. Portable headers (runtime/*.hpp) must not depend on any backend. They are
#    the contract and the loop; if they reach into a backend they stop being
#    portable and the concept stops meaning anything.
hits=$(grep -lE 'runtime/(linux|darwin|windows)/' "$R"/*.hpp 2>/dev/null || true)
[ -n "$hits" ] && note "portable header depends on a backend: $hits"

# 3. shared/ is for host-agnostic logic, so it must not touch a platform API
#    or a backend. This is what hvf_vma.hpp violated by being named for one.
hits=$(grep -lE 'runtime/(linux|darwin|windows)/' "$R"/shared/*.hpp 2>/dev/null || true)
[ -n "$hits" ] && note "shared/ depends on a backend: $hits"
hits=$(grep -lE '\bhv_[a-z]|WHvRun|PTRACE_|__APPLE__|_WIN32' "$R"/shared/*.hpp 2>/dev/null || true)
[ -n "$hits" ] && note "shared/ uses a platform API: $hits"

# 4. Every backend must assert itself against the written contract, so a
#    missing or mistyped primitive is a build error rather than a silent
#    fallback. (backend.hpp explains why this one matters most.)
for f in "$R"/linux/ptrace_trap.hpp "$R"/darwin/trap.hpp "$R"/windows/trap.hpp; do
    [ -f "$f" ] || continue
    grep -q 'static_assert.*SyscallTrap' "$f" \
        || note "$f does not assert SyscallTrap"
done

if [ "$fail" -eq 0 ]; then
    echo "runtime layout: all structural invariants hold"
else
    echo "runtime layout: violations found"
    exit 1
fi
