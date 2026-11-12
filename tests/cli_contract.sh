#!/bin/sh
# The command line's own contract, on every POSIX host, with no guest run:
# the verb table, help, typo hints and completion agree with each other.
# usage: cli_contract.sh path/to/linuxity
set -u
L=$1
H=$(mktemp -d)
trap 'rm -rf "$H"' EXIT
export LINUXITY_HOME=$H NO_COLOR=1
fail=0
check() {   # check NAME EXPECTED-SUBSTRING COMMAND...
    name=$1 want=$2; shift 2
    out=$("$@" 2>&1)
    case $out in *"$want"*) ;; *) echo "FAIL: $name: wanted '$want', got:"; echo "$out" | sed 's/^/    /'; fail=1;; esac
}

# every verb help lists is a verb: `help VERB` knows it, completion offers it
for v in $("$L" help | sed -n 's/^  linuxity \([a-z][a-z-]*\).*/\1/p' | sort -u); do
    check "help $v" "linuxity $v" "$L" help "$v"
    "$L" __complete "$v" | grep -qx "$v" || { echo "FAIL: completion doesn't offer '$v'"; fail=1; }
done
# and completion offers nothing help doesn't list
for v in $("$L" __complete ""); do
    "$L" help | grep -q "^  linuxity $v\b" || { echo "FAIL: completion offers '$v', help doesn't list it"; fail=1; }
done
check "help has lx"   "lx @ENV"                           "$L" help
check "old verb"      "is now \`lx\`"                     "$L" shell
check "old set"       "linuxity config KEY=VALUE"         "$L" set
check "typo"          "Did you mean \`linuxity config\`"  "$L" confg
check "program"       "lx sh"                             "$L" sh
check "bad verb help" "no command 'nope'"                 "$L" help nope
check "images complete" "alpine" "$L" __complete new ""
check "keys complete" "system.hostname=" "$L" __complete config system.h
check "lx flags complete" "--temp" "$L" __complete lx -
check "no env yet"    "linuxity new alpine" "$L" ls
check "lx no env"     "linuxity new alpine" "$L" lx
check "rm needs name" "the name is required" "$L" rm
check "version"       "linuxity " "$L" version
for sh in bash zsh fish; do
    check "completion $sh" "__complete" "$L" completion "$sh"
done
[ $fail -eq 0 ] && echo "cli contract: help, verbs and completion agree"
exit $fail
