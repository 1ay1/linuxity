#!/usr/bin/env bash
# scripts/conform-android.sh -- run the differential conformance suite on a
# real Android device, against that device's own kernel.
#
# WHY THIS EXISTS. linuxity's correctness claim is "agrees with a real Linux
# kernel", and the suite proves that by running each probe twice -- natively
# and under linuxity -- and diffing. On x86-64 that is a ctest target. On
# Android it was a dozen ad-hoc adb commands, which meant it was run by hand,
# rarely, and the aarch64 goldens drifted.
#
# That is not a small gap. Android is not just "Linux on arm64": it is Linux
# plus an SELinux policy that denies syscalls a desktop kernel allows, plus
# bionic instead of glibc, plus a loader called linker64. Every one of those
# has produced a real bug here. Four tty bugs shipped in a day because nothing
# ran the suite on a phone.
#
# Usage:
#   scripts/conform-android.sh                # build, push, diff
#   scripts/conform-android.sh --record       # ...and re-record the goldens
#   scripts/conform-android.sh --build-only   # just build for the device
#
# Requires: adb with a device attached, and an NDK. Point LX_ANDROID_BUILD at
# an existing aarch64 build tree to skip configuring one.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${LX_ANDROID_BUILD:-$REPO/build-android}"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK:-/opt/android-ndk}}"
REMOTE="${LX_REMOTE_DIR:-/data/local/tmp/lxconform}"
ABI="${ANDROID_ABI:-arm64-v8a}"
API="${ANDROID_PLATFORM:-android-28}"

# A device probe can hang -- a guest that never exits keeps the adb pipe open
# and the whole run with it. Everything that touches the device gets a hard
# deadline rather than being allowed to wedge a CI job.
DEADLINE="${LX_DEADLINE:-300}"

record=0
build_only=0
for a in "$@"; do
    case "$a" in
        --record)     record=1 ;;
        --build-only) build_only=1 ;;
        -h|--help)    sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# -- preflight -------------------------------------------------------------
command -v adb >/dev/null || die "adb not found"
[ -f "$NDK/build/cmake/android.toolchain.cmake" ] ||
    die "no NDK at $NDK (set ANDROID_NDK_HOME)"

devices=$(adb devices | awk 'NR>1 && $2=="device" {print $1}')
[ -n "$devices" ] || die "no device attached (adb devices)"
say "device: $(echo "$devices" | head -1)  ($(adb shell getprop ro.build.version.release | tr -d '\r') / $(adb shell uname -r | tr -d '\r'))"

# -- build -----------------------------------------------------------------
if [ ! -f "$BUILD/CMakeCache.txt" ]; then
    say "configuring $BUILD for $ABI/$API"
    cmake -S "$REPO" -B "$BUILD" \
        -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$ABI" -DANDROID_PLATFORM="$API" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
fi

say "building linuxity + probes"
# Only what the device run needs. Building everything pulls in host-only
# tests that do not cross-compile (and need not).
targets=(linuxity record_goldens test_conform_diff)
while read -r p; do targets+=("probe_$p"); done < <(
    sed -n 's/.*set(LX_PROBES \(.*\))/\1/p' "$REPO/tests/CMakeLists.txt" | tr ' ' '\n'
)
cmake --build "$BUILD" --target "${targets[@]}" -j"$(nproc)" >/dev/null ||
    die "build failed"

[ "$build_only" -eq 1 ] && { say "built; not pushing (--build-only)"; exit 0; }

# -- push ------------------------------------------------------------------
say "pushing to $REMOTE"
adb shell "rm -rf $REMOTE && mkdir -p $REMOTE/probes" >/dev/null
adb push "$BUILD/linuxity"                 "$REMOTE/linuxity"          >/dev/null
adb push "$BUILD/tests/record_goldens"     "$REMOTE/record_goldens"    >/dev/null
adb push "$BUILD/tests/test_conform_diff"  "$REMOTE/test_conform_diff" >/dev/null
for p in "$BUILD"/probes/*; do
    [ -f "$p" ] && adb push "$p" "$REMOTE/probes/$(basename "$p")" >/dev/null
done
adb shell "chmod +x $REMOTE/linuxity $REMOTE/record_goldens $REMOTE/test_conform_diff $REMOTE/probes/*" >/dev/null

env_vars="LX_PROBE_DIR=$REMOTE/probes LX_BINARY=$REMOTE/linuxity LX_GOLDEN_DIR=$REMOTE/goldens"

# -- goldens ---------------------------------------------------------------
# The golden is the DEVICE KERNEL's own answer, recorded on the device. It is
# deliberately not a recording of linuxity's output: that would prove only
# that linuxity still does what it did on recording day.
if [ "$record" -eq 1 ]; then
    say "recording goldens from the device kernel"
    adb shell "cd $REMOTE && LX_PROBE_DIR=$REMOTE/probes timeout -s KILL $DEADLINE ./record_goldens" ||
        die "recording failed"
    rm -rf "$REPO/tests/goldens/aarch64"
    mkdir -p "$REPO/tests/goldens"
    adb pull "$REMOTE/tests/goldens/aarch64" "$REPO/tests/goldens/" >/dev/null ||
        die "could not pull goldens"
    say "wrote $(ls "$REPO/tests/goldens/aarch64"/*.trace | wc -l) goldens to tests/goldens/aarch64"
fi

# Ship the committed goldens so the replay path has a reference too.
adb shell "mkdir -p $REMOTE/goldens" >/dev/null
adb push "$REPO/tests/goldens/aarch64" "$REMOTE/goldens/" >/dev/null 2>&1 || true

# -- the actual check ------------------------------------------------------
say "running conform_diff against the device kernel"
set +e
out=$(adb shell "cd $REMOTE && $env_vars timeout -s KILL $DEADLINE ./test_conform_diff 2>&1")
rc=$?
set -e
echo "$out" | sed 's/\r$//'

# adb shell's exit status is unreliable on older devices, so judge by the
# summary line the test prints rather than by $?.
if echo "$out" | grep -q '0 failing'; then
    say "PASS -- every scenario agrees with the device's own kernel"
    exit 0
fi
[ "$rc" -ne 0 ] && die "conform_diff exited $rc"
die "scenarios diverged from the device kernel (see above)"
