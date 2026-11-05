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

# 7. A syscall is named through the GENERATED Sysno table (abi/sysno.hpp), not
#    by its raw number. A literal like `case 56:` is correct on x86-64 and
#    silently names a DIFFERENT syscall on aarch64 -- the one bug class here
#    that produces plausible wrong answers instead of errors. (ptrace_trap's
#    returns_pid() matched 56/57/58/435/61 that way; it now decodes.)
#
#    Scoped to files that actually SWITCH on a syscall-number variable, so a
#    switch over register indices or termios flags doesn't trip it.
#
#    KNOWN EXCEPTION, tracked not excused: windows/sys.hpp is a second
#    dispatcher with 71 raw cases. It is being deleted in favour of routing
#    WhpTrap through abi::Syscalls + WhpHostCalls (doc/SYSCALL_LAYER.md step
#    5), which cannot be compile-verified without a Windows toolchain. Until
#    then this reports but does not fail, and the COUNT is pinned so the file
#    can only shrink -- if it grows, that is a new violation and this fails.
win_raw_budget=71
for f in $(grep -rlE 'switch \((nr|sysno|regs_\.nr\(\)|f\.regs\.nr)' \
           include/linuxity src 2>/dev/null | grep -v '^include/linuxity/abi/'); do
    n=$(grep -cE 'case (SYS_[A-Za-z_0-9]+|[0-9]+):' "$f" 2>/dev/null || echo 0)
    [ "$n" -eq 0 ] && continue
    if [ "$f" = "include/linuxity/runtime/windows/sys.hpp" ]; then
        if [ "$n" -gt "$win_raw_budget" ]; then
            note "$f grew to $n raw syscall cases (budget $win_raw_budget); use Sysno"
        else
            printf '  note: %s still has %s raw syscall cases (budget %s, shrinking to 0 -- see doc/SYSCALL_LAYER.md step 5)\n' \
                "$f" "$n" "$win_raw_budget"
        fi
        continue
    fi
    note "$f dispatches on raw syscall numbers ($n cases); use Sysno"
done

# 8. A guest ABI struct is DECLARED once, in abi/wire/, and aliased elsewhere.
#    struct timespec had three identical declarations (hostcalls.hpp,
#    darwin/timer.hpp, windows/win32.hpp). Three copies of a two-field struct
#    look harmless -- the damage is what grows AROUND them: Windows already
#    had a FILETIME->timespec conversion, and the duplicate struct bred a
#    second one with different pre-epoch clamping.
#
#    Backends may still DEFINE a struct whose layout is genuinely per-ABI
#    (LinuxStat differs between x86-64 and asm-generic) as long as it
#    static_asserts against abi/wire -- rule 5's authority check covers that.
#    What this rule forbids is re-declaring a shape that does NOT vary.
for s in Timespec Timeval Itimerval Itimerspec Iovec; do
    hits=$(grep -rlE "^(struct|using)[[:space:]]+(Linux|Guest)?$s[[:space:]]*[{=]" \
           include/linuxity src 2>/dev/null \
           | grep -v '^include/linuxity/abi/wire/' || true)
    for f in $hits; do
        grep -qE "^using[[:space:]]+(Linux|Guest)?$s[[:space:]]*=" "$f" \
            || note "$f re-declares guest ABI struct $s; alias abi/wire instead"
    done
done

# 9. Guest ABI CONSTANTS are defined in abi/wire/, not re-spelled per backend.
#    MAP_*/PROT_* lived in windows/mm.hpp, windows/win32.hpp AND as an inline
#    `constexpr kFixed = 0x10, kAnon = 0x20` inside a darwin function body.
#    That last one is the tell: a constant cheap to redeclare gets redeclared
#    at the point of use, and then there is no single place to fix it. MAP_*
#    is also a near-miss family (0x2000 LOCKED / 0x4000 NORESERVE / 0x8000
#    POPULATE), where picking the wrong neighbour changes mapping semantics
#    silently rather than failing.
#
#    Matches a literal hex assignment to a MAP_/PROT_-ish name. A backend
#    aliasing abi::wire::bits(...) passes; writing 0x20 again does not. The
#    WHv* prefix is excluded: those are Win32's OWN hypervisor API constants
#    (WHvMapGpaRangeFlagRead), not the guest's ABI, and they must stay with
#    the API they belong to.
hits=$(grep -rlE '(^|[^A-Za-z])(k|LINUX_|LX_)?(Map|Prot|MAP_|PROT_)[A-Za-z_]*[[:space:]]*=[[:space:]]*0x?[0-9]+' \
       include/linuxity src 2>/dev/null \
       | grep -v '^include/linuxity/abi/wire/' || true)
for f in $hits; do
    # Keep only files with a hit that ISN'T a WHv*/host-API constant.
    grep -E '(^|[^A-Za-z])(k|LINUX_|LX_)?(Map|Prot|MAP_|PROT_)[A-Za-z_]*[[:space:]]*=[[:space:]]*0x?[0-9]+' "$f" \
        | grep -qvE 'WHv|ExceptionType' \
        && note "guest mmap constants defined outside abi/wire/: $f"
done

# 10. A file that USES a shared symbol must INCLUDE the header defining it.
#     This is the single most common way a cross-platform edit breaks: on a
#     Linux host, a backend header for macOS or Windows is never compiled, so
#     a missing include is invisible until CI builds that platform. It cost
#     three CI round-trips -- darwin/timer.hpp aliased abi::wire::Timespec
#     without including time.hpp, windows/api.hpp called host::random_bytes
#     without entropy.hpp, and three more files were one build away from the
#     same failure.
#
#     So check it HERE, where every file is visible regardless of host, rather
#     than discovering it one platform at a time.
check_include() {   # <symbol-regex> <required-header>
    for f in $(grep -rlE "$1" include/linuxity src --include=*.hpp --include=*.cpp 2>/dev/null); do
        case "$f" in *"$2") continue;; esac      # the definition itself
        # Must be a real #include line. A plain `grep -q "$2"` also matched a
        # COMMENT naming the header -- which is exactly how darwin/trap.hpp
        # passed this check while missing the include, since its comment says
        # "come from abi/identity.hpp".
        grep -qE "^[[:space:]]*#[[:space:]]*include.*$2" "$f" \
            || note "$f uses ${3:-$1} without including $2"
    done
}

check_include 'host::random_bytes'            'host/entropy.hpp'    'host::random_bytes'
check_include 'abi::(identity_answer|TaskIdentity)' \
              'abi/identity.hpp'    'a shared identity answer'
check_include 'abi::wire::(Timespec|Timeval|Itimerval|Itimerspec|kNsecPerSec|to_millis_ceil)' \
              'abi/wire/time.hpp'   'a wire time type'
check_include 'abi::wire::(Iovec|kIovMax)'    'abi/wire/iovec.hpp'  'wire::Iovec'
check_include 'abi::wire::(DType|dirent_reclen|encode_dirent64|dtype_from_mode)' \
              'abi/wire/dirent64.hpp' 'a wire dirent symbol'
check_include 'abi::wire::(OpenFlag|writable)' 'abi/wire/open_flags.hpp' 'wire::OpenFlag'
check_include 'abi::wire::(MapFlag|is_anonymous|wants_fixed)' 'abi/wire/mmap.hpp' 'wire::MapFlag'
check_include 'abi::wire::(AtFlag|kAtFdCwd|has_at)' 'abi/wire/at_flags.hpp' 'wire::AtFlag'
check_include 'abi::wire::(FileType|kPermMask|kFileTypeMask|stat_layout|kStat)' \
              'abi/wire/stat.hpp'   'a wire stat symbol'
check_include 'abi::wire::(kOCloexec|kONonblock|kMfdCloexec)' 'abi/wire/fd_flags.hpp' 'a wire fd flag'
check_include 'abi::wire::errno_from_host'    'abi/wire/errno_map.hpp' 'errno_from_host'
check_include 'abi::wire::(normalize_path|absolutize_path)' 'abi/wire/path.hpp' 'a wire path helper'

# ---- conform/ must keep the law host-independent -------------------------
#
# The conformance LAW (what agreement means), the trace format, both oracles
# and the scenario registry are shared by all four hosts. Only the
# ProbeRunner implementations may touch a platform API, and only host.hpp may
# choose between them. If a platform header creeps anywhere else, the law
# stops compiling on macOS or Windows and those hosts silently lose
# conformance coverage -- the vacuous pass this design exists to prevent.
for f in include/linuxity/conform/*.hpp; do
    [ -e "$f" ] || continue
    case "$(basename "$f")" in
        runner_*.hpp|host.hpp) continue ;;   # the sanctioned host seam
        arch.hpp) continue ;;                # the sanctioned guest-ABI seam
    esac
    if grep -qE '^[[:space:]]*#[[:space:]]*include[[:space:]]*<(sys/|unistd|fcntl|dirent|pthread|windows|spawn|signal)' "$f"; then
        note "$f includes a platform header; only conform/runner_*.hpp may \
(put host code behind the ProbeRunner concept)"
    fi
    if grep -qE '^[[:space:]]*#[[:space:]]*(if|ifdef|ifndef).*(_WIN32|__linux__|__APPLE__)' "$f"; then
        note "$f branches on the host with a preprocessor test; conform/ \
selects a host ONCE in host.hpp"
    fi
    if grep -qE '\b(fork|vfork|execve|execvp|ptrace|posix_spawn|CreateProcess)[[:space:]]*\(' "$f"; then
        note "$f spawns a process; only a ProbeRunner implementation may"
    fi
done

# The Sysno name table is generated from the enum, so it cannot drift. If the
# enum gains a member without the table being regenerated, the static_assert
# in sysno_names.hpp fires -- but catch it here too, with a clearer message.
if [ -f include/linuxity/conform/sysno_names.inc ] && \
   [ -f include/linuxity/abi/sysno.hpp ]; then
    enum_n=$(sed -n '/enum class Sysno/,/^};/p' include/linuxity/abi/sysno.hpp \
             | sed 's,//.*,,' | tr ',' '\n' \
             | grep -cE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*([[:space:]]*=[^,]*)?[[:space:]]*$')
    table_n=$(grep -c 'LX_SYSNO_NAME(' include/linuxity/conform/sysno_names.inc)
    if [ "$enum_n" -ne "$table_n" ]; then
        note "Sysno has $enum_n members but the name table has $table_n; \
rerun tools/gen_sysno_names.py"
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "runtime layout: all structural invariants hold"
else
    echo "runtime layout: violations found"
    exit 1
fi
