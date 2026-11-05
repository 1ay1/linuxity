#!/bin/sh
# The LTP RATCHET: fail if the number of differential failures grows.
#
# ltp_diff.sh measures; this enforces. Without a ratchet a measurement is just
# a number someone looks at once -- the point is that a change which breaks a
# previously-passing LTP test cannot land quietly.
#
#   tools/ltp_ratchet.sh [-l LTPDIR] [-b BINARY] [-t SECS] [-j N]
#
# The budget lives in tools/ltp_budget.txt: one line, the maximum acceptable
# LINUXITY_FAILS count, with a comment block explaining each entry. Lower it
# as bugs get fixed; raising it requires saying why in the commit.
set -u

BUDGET_FILE=tools/ltp_budget.txt
ARGS=""

while [ $# -gt 0 ]; do
    case "$1" in
        -f) BUDGET_FILE=$2; shift 2 ;;
        *)  ARGS="$ARGS $1"; shift ;;
    esac
done

[ -f "$BUDGET_FILE" ] || { echo "ltp_ratchet: no budget at $BUDGET_FILE" >&2; exit 2; }

BUDGET=$(grep -vE '^\s*#|^\s*$' "$BUDGET_FILE" | head -1 | tr -d ' ')
case "$BUDGET" in
    ''|*[!0-9]*) echo "ltp_ratchet: budget is not a number: '$BUDGET'" >&2; exit 2 ;;
esac

# shellcheck disable=SC2086
sh tools/ltp_diff.sh $ARGS || true

OUT=/tmp/ltp-diff.txt
[ -f "$OUT" ] || { echo "ltp_ratchet: ltp_diff produced no detail file" >&2; exit 2; }

FAILS=$(grep -c '^LINUXITY_FAILS' "$OUT" 2>/dev/null | head -1)
[ -n "$FAILS" ] || FAILS=0

echo
echo "ltp_ratchet: $FAILS failures, budget $BUDGET"

if [ "$FAILS" -gt "$BUDGET" ]; then
    echo "FAIL: differential failures ROSE from $BUDGET to $FAILS." >&2
    echo "      A test that passes natively now fails under linuxity:" >&2
    grep '^LINUXITY_FAILS' "$OUT" | sed 's/^/        /' >&2
    echo "      Fix it, or raise the budget in $BUDGET_FILE and say why." >&2
    exit 1
fi

if [ "$FAILS" -lt "$BUDGET" ]; then
    echo "ratchet CAN TIGHTEN: $FAILS < $BUDGET."
    echo "  Lower the budget in $BUDGET_FILE to $FAILS to lock the gain in."
fi

echo "ltp_ratchet: holds"
