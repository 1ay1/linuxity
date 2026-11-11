#!/bin/sh
# Compile-check the LINUX host build from any host linuxity runs on (a Mac,
# say), inside a linuxity Alpine environment. Catches Linux-only breaks
# before CI does -- the reverse of what CI has done for macOS.
#
#   tools/linux-build-check.sh [ENV] [TARGET...]     (default: env "linux-build", target linuxity)
#
# The first run makes the environment and installs the toolchain; later
# runs reuse both (the build dir lives in the env's /tmp... /var/tmp).
set -eu
cd "$(dirname "$0")/.."
L=${LINUXITY:-$(command -v linuxity || echo build-mac/linuxity)}
ENV=${1:-linux-build}
[ $# -gt 0 ] && shift
TARGETS=${*:-linuxity}
if ! "$L" list 2>/dev/null | grep -qE "^[* ] +$ENV "; then
    "$L" new alpine "$ENV"
fi
exec "$L" run "$ENV" --user root --bind "$PWD:/src" -- sh -c "
    command -v g++ >/dev/null && command -v cmake >/dev/null && command -v ninja >/dev/null ||
        apk add -q build-base cmake samurai linux-headers zlib-dev
    cmake -S /src -B /var/tmp/lx-linux -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo >/var/tmp/lx-cfg.log 2>&1 ||
        { tail -20 /var/tmp/lx-cfg.log; exit 1; }
    cd /var/tmp/lx-linux && ninja -k 0 $TARGETS >/var/tmp/lx-build.log 2>&1
    rc=\$?
    grep -E 'error|warning:|undefined reference|FAILED' /var/tmp/lx-build.log | sort -u
    [ \$rc -eq 0 ] && echo 'linux build: ok' || echo \"linux build: FAILED (full log: /var/tmp/lx-build.log in $ENV)\"
    exit \$rc
"
