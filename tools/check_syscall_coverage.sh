#!/bin/sh
# Every syscall the dispatcher HANDLES must actually be TRAPPED.
#
# linuxity's seccomp filter (runtime/linux/seccomp_filter.hpp) returns
# SECCOMP_RET_TRACE for a fixed list of syscall numbers; everything else runs
# natively with zero tracer involvement. That list and the dispatcher's
# `case Sysno::` labels are maintained SEPARATELY, so they drift -- and when
# they do, a perfectly correct handler becomes dead code and the syscall goes
# straight to the host.
#
# That has now happened three times:
#
#   lseek      the dispatcher had a Sysno::lseek case written specifically for
#              rewinddir on merged directories. it was never trapped, so
#              `pacman -Q` reported 0 of 139 packages.
#   fchmodat2  do_chmod handled it; untrapped, so a guest chmod landed on the
#              HOST path. a sandbox escape.
#   creat      neither handled nor trapped. also an escape.
#
# Finding these by running real workloads works but is luck. This makes the
# mismatch visible, and for path-bearing syscalls it is an ERROR: an untrapped
# path syscall is a confinement hole, not a style issue.
#
# Run from the repo root.
set -e
cd "$(dirname "$0")/.."

python3 - "$@" <<'PY'
import re, sys, pathlib

root = pathlib.Path('.')
sysno = (root / 'include/linuxity/abi/sysno.hpp').read_text()
filt  = (root / 'include/linuxity/runtime/linux/seccomp_filter.hpp').read_text()
disp  = (root / 'include/linuxity/abi/syscall.hpp').read_text()

# number -> name, from the x86-64 decode table only (aarch64 reuses names at
# different numbers, and the filter is x86-64).
i = sysno.index('Arch::x86_64')
j = sysno.index('Arch::aarch64', i)
num2name = {int(n): nm for n, nm in
            re.findall(r'case\s+(\d+):\s*return\s+Sysno::([a-z_0-9]+);', sysno[i:j])}
name2num = {v: k for k, v in num2name.items()}

m = re.search(r'kTrappedX86_64\[\] = \{(.*?)\n\};', filt, re.S)
trapped_nums = {int(n) for n in re.findall(r'\b(\d+)\b', re.sub(r'//[^\n]*', '', m.group(1)))}
trapped = {num2name[n] for n in trapped_nums if n in num2name}

handled = set(re.findall(r'case Sysno::([a-z_0-9]+)', disp))

# Syscalls whose FIRST-CLASS job is to name a filesystem path. If one of these
# is handled-but-untrapped, the guest's path reaches the host unchanged.
PATH_BEARING = {
 'open','openat','openat2','creat','stat','lstat','newfstatat','statx','statfs',
 'access','faccessat','faccessat2','chdir','chroot','truncate','rename','renameat',
 'renameat2','mkdir','mkdirat','rmdir','link','linkat','unlink','unlinkat',
 'symlink','symlinkat','readlink','readlinkat','chmod','fchmodat','fchmodat2',
 'chown','lchown','fchownat','mknod','mknodat','utimensat','futimesat','utimes',
 'setxattr','lsetxattr','getxattr','lgetxattr','listxattr','llistxattr',
 'removexattr','lremovexattr','mount','umount2','pivot_root','swapon','swapoff',
 'acct','quotactl','name_to_handle_at','open_tree','move_mount','fsopen','fspick',
 'execve','execveat','statmount','listmount',
 # 6.13+/6.14+ *at and attribute calls. Added after the check reported them as
 # "no path argument" -- they very much have one, and that misclassification
 # would have downgraded a real confinement hole to a note.
 'setxattrat','getxattrat','listxattrat','removexattrat',
 'open_tree_attr','file_getattr','file_setattr',
}

# Deliberately untrapped syscalls carry an explicit marker in the filter:
#
#     // UNTRAPPED(name,NUMBER): <reason>
#
# A marker, not prose. I tried twice to infer intent from the comments and
# both attempts were wrong in a way that DEFEATED the check rather than
# annoying me:
#
#   1. matching "NOT filtered" anywhere absorbed creat from a comment that
#      describes the bug it USED to have ("It was NOT trapped and NOT
#      handled") -- so deleting creat's trap still reported all-clear.
#   2. restricting to present tense "is ... NOT filtered" still matched
#      "creat(85) is open(O_CREAT...). It was NOT trapped", because the two
#      clauses share a line.
#
# Caught both only because I tested the check by reverting a real fix. A
# security check that can be silenced by rewording a comment is worse than no
# check, so intent is now declared, not guessed.
INTENTIONAL = {}
for name, num in re.findall(r'UNTRAPPED\((\w+),\s*(\d+)\)', filt):
    INTENTIONAL[name] = int(num)

# rt_sigreturn is special and has no "NOT filtered" note: trapping it would
# corrupt the signal frame it exists to pop.
INTENTIONAL.setdefault('rt_sigreturn', name2num.get('rt_sigreturn', 15))

# A case that only ever returns fwd() is NOT a dead handler. Forwarding is
# what an untrapped syscall already does, faster, with no tracer round-trip --
# so the case exists for documentation (and for the kernel-less backends,
# which have no host to forward to). rt_sigaction and friends are exactly
# this: syscall.hpp explains that the traced task's REAL sigaction table must
# be set, so forwarding is the point.
#
# Detect them by walking the dispatcher line by line: a run of `case Sysno::`
# labels whose next statement is `return fwd();`.
#
# Deliberately NOT a single regex -- my first attempt
# `((?:\s*case Sysno::\w+:\s*)+)\s*return fwd\(\);` backtracked
# catastrophically on a 2000-line file and hung for over three minutes.
forward_only = set()
pending = []
for line in disp.splitlines():
    labels = re.findall(r'case Sysno::([a-z_0-9]+):', line)
    if labels:
        pending += labels
        # A label line may also carry its body (`case Sysno::x: return fwd();`).
        # Check for that by looking AFTER the last label, not by splitting on
        # the first ':' -- `Sysno::` contains colons, which is what broke my
        # first version and left the whole rt_sig* group reported as dead.
        tail = line[line.rfind(':') + 1:].strip()
        if tail.startswith('return'):
            if 'fwd()' in tail:
                forward_only |= set(pending)
            pending = []
        continue
    stripped = line.strip()
    if not stripped or stripped.startswith('//'):
        continue
    if pending:
        if stripped == 'return fwd();':
            forward_only |= set(pending)
        pending = []

dead = sorted((handled & set(name2num)) - trapped - set(INTENTIONAL) - forward_only)
holes = [d for d in dead if d in PATH_BEARING]
rest  = [d for d in dead if d not in PATH_BEARING]

if holes:
    print('ERROR: path-bearing syscalls are HANDLED but never TRAPPED.')
    print('       The guest\'s path reaches the host kernel untranslated,')
    print('       which is a sandbox escape, and the handler is dead code.')
    for d in holes:
        print(f'         {d} ({name2num[d]})')
    print('       Add the number to kTrappedX86_64 in')
    print('       include/linuxity/runtime/linux/seccomp_filter.hpp')

if rest:
    print(f'note: {len(rest)} handled-but-untrapped syscalls (no path argument,')
    print('      so not a confinement hole -- but the handler IS dead code and')
    print('      the guest gets the host\'s answer instead of ours):')
    for d in rest:
        print(f'        {d} ({name2num[d]})')

if not holes and not rest:
    print(f'syscall coverage: all {len(handled & set(name2num))} handled syscalls are trapped')

sys.exit(1 if holes else 0)
PY
