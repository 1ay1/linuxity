#!/bin/bash
# bench.sh BINARY  -- median of 5 runs per workload, native vs linuxity.
# Every run must exit 0, or the timing is meaningless.
L=$1
R=$HOME/arch/root.x86_64; U=$HOME/arch/upper; REPO=$HOME/projects/linuxity
N=5
median() { sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
t1() {   # t1 MODE CMD...  -> ms
  local mode=$1; shift; local s e rc
  s=$(date +%s%N)
  if [ $mode = native ]; then (cd $REPO && "$@") >/dev/null 2>&1; rc=$?
  else $L --quiet --root $R --persist $U --bind $REPO:/work --cwd /work "$@" >/dev/null 2>&1; rc=$?; fi
  e=$(date +%s%N)
  [ $rc = 0 ] || { echo "FAILED($rc)"; return; }
  echo $(( (e - s) / 1000000 ))
}
row() {   # row NAME NATIVE_CMD -- GUEST_CMD
  local name=$1; shift; local nat=() gst=() seen=0
  for a in "$@"; do if [ "$a" = -- ]; then seen=1; elif [ $seen = 0 ]; then nat+=("$a"); else gst+=("$a"); fi; done
  local n g
  n=$(for i in $(seq $N); do t1 native "${nat[@]}"; done | median)
  g=$(for i in $(seq $N); do t1 guest "${gst[@]}"; done | median)
  printf '%-14s native %5s ms   linuxity %5s ms   %sx\n' $name $n $g $(awk -v a=$n -v b=$g 'BEGIN{ if (a>0) printf "%.1f", b/a; else print "-" }')
}
row bash-startup  bash -lc true                                   -- /usr/bin/bash -lc true
row python-import python3 -c 'import json,email.parser,asyncio,http.client,sqlite3' -- /usr/bin/python3 -c 'import json,email.parser,asyncio,http.client,sqlite3'
row git-status    git status --short                              -- /usr/bin/git status --short
row git-log       git log --oneline -300                          -- /usr/bin/git log --oneline -300
row gcc-compile   gcc -O1 -c tests/probes/proclife.c -Itests/probes -o /dev/null -- /usr/bin/gcc -O1 -c tests/probes/proclife.c -Itests/probes -o /dev/null
row find-tree     find $R/usr/include -name '*.h'                 -- /usr/bin/find /usr/include -name '*.h'
row ls-lR         ls -lR $R/usr/lib/python3.14                    -- /usr/bin/ls -lR /usr/lib/python3.14
row stat-many     sh -c "for f in $R/usr/bin/*; do [ -e \"\$f\" ]; done"  -- /bin/sh -c 'for f in /usr/bin/*; do [ -e "$f" ]; done'
row fork-exec     sh -c 'i=0; while [ $i -lt 200 ]; do /usr/bin/true; i=$((i+1)); done' -- /bin/sh -c 'i=0; while [ $i -lt 200 ]; do /usr/bin/true; i=$((i+1)); done'
row grep-tree     grep -r --include='*.hpp' -c Result include     -- /usr/bin/grep -r --include=*.hpp -c Result include
