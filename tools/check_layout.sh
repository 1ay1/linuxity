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

# An #include of a given path, as a grep pattern. Only real includes count:
# a comment that NAMES a file ("see runtime/windows/sys.hpp") is documentation,
# not a dependency, and matching it made this check fire on its own prose.
inc_of() { printf '^[[:space:]]*#[[:space:]]*include.*%s' "$1"; }

# 1. No backend may include another backend's headers. Each is compiled only
#    on its own host, so a cross-include is either dead or a layering bug.
for a in linux darwin windows; do
    for b in linux darwin windows; do
        [ "$a" = "$b" ] && continue
        hits=$(grep -rlE "$(inc_of "runtime/$b/")" "$R/$a/" 2>/dev/null || true)
        [ -n "$hits" ] && note "$a includes $b: $hits"
    done
done

# 2. Portable headers (runtime/*.hpp) must not depend on any backend. They are
#    the contract and the loop; if they reach into a backend they stop being
#    portable and the concept stops meaning anything.
hits=$(grep -lE "$(inc_of 'runtime/(linux|darwin|windows)/')" "$R"/*.hpp 2>/dev/null || true)
[ -n "$hits" ] && note "portable header depends on a backend: $hits"

# 3. shared/ is for host-agnostic logic, so it must not touch a platform API
#    or a backend. This is what hvf_vma.hpp violated by being named for one.
hits=$(grep -lE "$(inc_of 'runtime/(linux|darwin|windows)/')" "$R"/shared/*.hpp 2>/dev/null || true)
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

# 5. Kernel ABI structs are encoded in ONE place: include/linuxity/abi/wire/.
#    linux_dirent64 was hand-rolled in THREE files that drifted into three
#    behaviours -- the Windows copy wrote d_ino = position and d_type =
#    DT_UNKNOWN, which made `pacman -Q` report zero packages on an intact
#    database (libalpm matches d_ino against a later stat's st_ino).
#
#    The violation is WRITING a GUEST dirent's bytes. Reading a HOST dirent
#    (e->d_ino from readdir) is fine and unavoidable, and so are comments. So
#    look for the byte-poking signature: an offset-19 name copy, or an
#    explicit d_reclen store. Both spellings of the length field are covered,
#    since the portable copy said `d_reclen` and darwin's said `reclen`.
hits=$(grep -rlE '(memcpy|memset)\([[:alnum:]_]+ \+ (16|18|19)|\+ base \+ 1[6-9]\]|d_reclen (lo|hi)' \
       include/linuxity src 2>/dev/null \
       | grep -v '^include/linuxity/abi/wire/' || true)
[ -n "$hits" ] && note "guest dirent bytes written outside abi/wire/: $hits"

# 6. abi/wire/ is pure ABI: values in, bytes out. No platform headers, no
#    backend includes -- that is what makes one encoder serve every host.
#    Only #include lines count, so prose in a comment can't trip it.
hits=$(grep -lE '^[[:space:]]*#[[:space:]]*include.*(<windows|<sys/|<dirent|runtime/(linux|darwin|windows)/)' \
       include/linuxity/abi/wire/*.hpp 2>/dev/null || true)
[ -n "$hits" ] && note "abi/wire/ depends on a platform or backend: $hits"

if [ "$fail" -eq 0 ]; then
    echo "runtime layout: all structural invariants hold"
else
    echo "runtime layout: violations found"
    exit 1
fi
