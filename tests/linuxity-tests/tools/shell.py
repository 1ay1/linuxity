"""The shell: pipelines, traps, expansions, subshells, redirections."""
import os

from lxt import check, eq, need_cmd, sh, test


@test
def pipelines_and_status():
    """Exit status through pipes, pipefail, PIPESTATUS, && / || chains."""
    need_cmd("bash")
    eq(sh("false | true; echo $?").stdout, "0\n", "last stage wins")
    eq(sh("bash -c 'set -o pipefail; false | true; echo $?'").stdout, "1\n", "pipefail")
    eq(sh("bash -c 'true | false | true; echo ${PIPESTATUS[@]}'").stdout, "0 1 0\n", "PIPESTATUS")
    eq(sh("false && echo no || echo yes").stdout, "yes\n", "&& ||")
    eq(sh("yes | head -n 3").stdout, "y\ny\ny\n", "yes gets SIGPIPE and the pipeline ends")
    return "status, pipefail, PIPESTATUS, chains, SIGPIPE"


@test
def traps_and_signals():
    """trap on TERM/EXIT/ERR, kill $$, wait for background jobs and $!."""
    need_cmd("bash")
    r = sh("trap 'echo trapped; exit 3' TERM; kill -TERM $$; sleep 5")
    eq((r.returncode, r.stdout), (3, "trapped\n"), "TERM trap")
    eq(sh("trap 'echo bye' EXIT; echo hi").stdout, "hi\nbye\n", "EXIT trap")
    eq(sh("bash -c \"trap 'echo err' ERR; false; true\"").stdout, "err\n", "ERR trap")
    eq(sh("sleep 0.1 & p=$!; wait $p; echo $?").stdout, "0\n", "wait $!")
    eq(sh("(exit 7) & wait $!; echo $?").stdout, "7\n", "background exit status")
    eq(sh("sleep 30 & kill $!; wait $!; echo $?").stdout, "143\n", "a killed job's status")
    return "TERM/EXIT/ERR traps, wait, $!, 143"


@test
def expansions():
    """Command substitution, arithmetic, globbing, brace and parameter expansion."""
    need_cmd("bash")
    for f in ("a1", "a2", "b1"):
        open(f, "w").close()
    eq(sh("echo a*").stdout, "a1 a2\n", "glob")
    eq(sh("echo $((6 * 7)) $(echo nested $(echo deep))").stdout, "42 nested deep\n", "$(( )) and $( )")
    eq(sh("bash -c 'echo {1..3} x{a,b}'").stdout, "1 2 3 xa xb\n", "brace expansion")
    eq(sh("v=hello.tar.gz; echo ${v%%.*} ${v#*.} ${#v}").stdout, "hello tar.gz 12\n", "parameter expansion")
    eq(sh("x=$( (echo a; echo b) | tr a-z A-Z | paste -sd, ); echo \"$x\"").stdout, "A,B\n", "subshell in $( )")
    eq(sh("bash -c 'shopt -s nullglob; echo zz*'").stdout, "\n", "nullglob")
    return "glob, $(( )), $( ), braces, ${...}"


@test
def redirections():
    """Here-docs, here-strings, fd duplication, noclobber and /dev/fd."""
    need_cmd("bash", "cat")
    eq(sh("cat <<EOF\nline $((1+1))\nEOF").stdout, "line 2\n", "here-doc")
    eq(sh("bash -c 'cat <<< \"here string\"'").stdout, "here string\n", "here-string")
    r = sh("echo out; echo err >&2")
    eq((r.stdout, r.stderr), ("out\n", "err\n"), "stdout/stderr")
    eq(sh("{ echo out; echo err >&2; } 2>&1 >/dev/null").stdout, "err\n", "2>&1 >/dev/null order")
    eq(sh("exec 3>three; echo via3 >&3; exec 3>&-; cat three").stdout, "via3\n", "exec 3>")
    eq(sh("bash -c 'cat <(echo procsub)'").stdout, "procsub\n", "process substitution (/dev/fd)")
    r = sh("set -C; echo a > clob; echo b > clob")
    check(r.returncode != 0, "noclobber allowed an overwrite")
    eq(sh("echo x | cat /dev/stdin").stdout, "x\n", "/dev/stdin")
    return "heredoc, <<<, 2>&1 order, exec 3>, <( ), noclobber, /dev/stdin"


@test
def many_shells():
    """64 shells in parallel, nested 20 deep, and a big loop."""
    need_cmd("bash")
    eq(sh("for i in $(seq 1 64); do (exit $((i % 7))) & done; wait; echo done").stdout, "done\n", "64 bg subshells")
    with open("nest.sh", "w") as f:
        f.write('if [ "$1" -gt 0 ]; then sh ./nest.sh $(($1 - 1)); else echo deep; fi\n')
    eq(sh("sh ./nest.sh 20").stdout, "deep\n", "20 nested shells")
    eq(sh("i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done; echo $i").stdout, "20000\n", "20000-step loop")
    return "64 parallel, 20 nested, 20000-iteration loop"
