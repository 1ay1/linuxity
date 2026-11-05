#!/bin/sh
# Run the Linux Test Project syscall tests natively AND under linuxity, and
# report where the two disagree.
#
# WHY LTP. The differential probes in tests/probes/ are mine, so they only
# check what I thought to check -- and I got that wrong three times in one
# afternoon (a test that passed with the fix reverted, an assertion that was
# factually wrong about Linux, a bug I reported that did not exist). LTP's
# assertions were written by other people against the real kernel, which makes
# its pass rate an EXTERNAL number rather than a restatement of my own
# assumptions.
#
# THE COMPARISON IS DIFFERENTIAL, NOT ABSOLUTE. A test that fails natively on
# this host tells us nothing about linuxity -- it needs root, or a kernel
# config we lack, or a filesystem feature tmpfs has not got. Only a test that
# PASSES natively and FAILS under linuxity is a linuxity bug. That distinction
# is the whole point; an absolute pass rate would be dominated by environment.
#
#   tools/ltp_diff.sh [-l LTPDIR] [-b BINARY] [-t SECS] [-j N] [DIR...]
#
# Writes a summary to stdout and the per-test detail to /tmp/ltp-diff.txt.
set -u

LTP=/tmp/ltp
LX=./build/linuxity
DEADLINE=20
JOBS=4
OUT=/tmp/ltp-diff.txt

while [ $# -gt 0 ]; do
    case "$1" in
        -l) LTP=$2; shift 2 ;;
        -b) LX=$2; shift 2 ;;
        -t) DEADLINE=$2; shift 2 ;;
        -j) JOBS=$2; shift 2 ;;
        --) shift; break ;;
        -*) echo "ltp_diff: unknown flag $1" >&2; exit 2 ;;
        *) break ;;
    esac
done

[ -d "$LTP" ] || { echo "ltp_diff: no LTP tree at $LTP" >&2; exit 2; }
[ -x "$LX" ]  || { echo "ltp_diff: no linuxity binary at $LX" >&2; exit 2; }
LX=$(cd "$(dirname "$LX")" && pwd)/$(basename "$LX")

DIRS=${*:-$(ls "$LTP/testcases/kernel/syscalls")}

# LTP needs these: LTPROOT for its data files, TMPDIR for scratch. Each test
# gets a FRESH tmpdir in both runs so neither can see the other's leftovers.
export LTPROOT="$LTP"
export PATH="$LTP/testcases/bin:$PATH"

: > "$OUT"

# Run one test binary once, with a deadline, and echo its exit code.
# LTP's convention: 0 = pass, 32 = all-skipped (TCONF), anything else = fail.
#
# THE GUEST RUN GOES ONE FORK DEEPER, deliberately. LTP's heartbeat() calls
# `getppid() == 1` to detect "my parent died and init adopted me" -- the
# universal orphan idiom. A linuxity guest's top process legitimately IS pid 1
# with ppid 0, exactly like init, so every forked test case saw ppid==1 and
# reported "Main test process might have exit!". That was 27 of the first 30
# failures: an artifact of the pid namespace, not a linuxity bug. Launching
# through `sh -c` puts the test at pid >= 2 so the check means what LTP
# intended.
run_one() {
    _bin=$1; _mode=$2
    _tmp=$(mktemp -d /tmp/ltpd.XXXXXX)
    # POSIX shm names live in a FLAT namespace shared with the host, and a
    # test killed on the deadline leaves its segment behind. The next run then
    # hits EEXIST on O_CREAT|O_EXCL and reports a bug that is really our own
    # litter -- pipe13 looked broken for several rounds because of it. Clear
    # this test's segments before each run.
    rm -f "/dev/shm/ltp_$(basename "$_bin")"_* 2>/dev/null
    if [ "$_mode" = native ]; then
        ( cd "$_tmp" && TMPDIR="$_tmp" timeout -s KILL "$DEADLINE" "$_bin" ) \
            >/dev/null 2>&1
    else
        # The trailing `:` stops sh from exec'ing its last command into its own
        # slot, which would leave the test at pid 1 and defeat the point.
        ( cd "$_tmp" && TMPDIR="$_tmp" timeout -s KILL "$DEADLINE" \
            "$LX" /bin/sh -c '"$0"; :' "$_bin" ) >/dev/null 2>&1
    fi
    _rc=$?
    rm -rf "$_tmp"
    echo "$_rc"
}

# Compare one test and append a verdict line to $OUT.
compare_one() {
    _bin=$1
    _name=$(basename "$_bin")
    _n=$(run_one "$_bin" native)
    _g=$(run_one "$_bin" guest)

    # 32 is TCONF (test decided it cannot run here); 0 is pass.
    if [ "$_n" = 0 ] && [ "$_g" = 0 ]; then
        echo "BOTH_PASS $_name" >> "$OUT"
    elif [ "$_n" = 0 ]; then
        # The only case that indicts linuxity.
        echo "LINUXITY_FAILS $_name native=$_n guest=$_g" >> "$OUT"
    elif [ "$_g" = 0 ]; then
        echo "LINUXITY_BETTER $_name native=$_n guest=$_g" >> "$OUT"
    else
        echo "BOTH_FAIL $_name native=$_n guest=$_g" >> "$OUT"
    fi
}

# Collect the test binaries: executable, not source, not a shell script.
list_bins() {
    for d in $DIRS; do
        _dir="$LTP/testcases/kernel/syscalls/$d"
        [ -d "$_dir" ] || continue
        for f in "$_dir"/*; do
            [ -f "$f" ] || continue
            [ -x "$f" ] || continue
            case "$f" in *.c|*.h|*.sh|*Makefile*|*.log) continue ;; esac
            echo "$f"
        done
    done
}

BINS=$(list_bins)
TOTAL=$(echo "$BINS" | grep -c . || true)
echo "ltp_diff: $TOTAL test binaries, deadline ${DEADLINE}s, $JOBS at a time"

# Bounded parallelism: $JOBS at a time, so a slow test cannot serialise the run
# but we also do not fork 315 guests at once.
running=0
for b in $BINS; do
    compare_one "$b" &
    running=$((running + 1))
    if [ "$running" -ge "$JOBS" ]; then wait; running=0; fi
done
wait

bp=$(grep -c '^BOTH_PASS'      "$OUT" 2>/dev/null | head -1 || echo 0)
lf=$(grep -c '^LINUXITY_FAILS' "$OUT" 2>/dev/null | head -1 || echo 0)
lb=$(grep -c '^LINUXITY_BETTER' "$OUT" 2>/dev/null | head -1 || echo 0)
bf=$(grep -c '^BOTH_FAIL'      "$OUT" 2>/dev/null | head -1 || echo 0)

echo
echo "  both pass                  : $bp"
echo "  both fail (environment)    : $bf"
echo "  linuxity better than native: $lb"
echo "  LINUXITY FAILS             : $lf   <- the only number that indicts us"
echo
if [ "$bp" -gt 0 ]; then
    echo "  differential pass rate: $(( bp * 100 / (bp + lf) ))% of natively-passing tests"
fi
if [ "$lf" -gt 0 ]; then
    echo
    echo "  failures:"
    grep '^LINUXITY_FAILS' "$OUT" | sed 's/^/    /' | head -40
fi
echo
echo "  detail: $OUT"
