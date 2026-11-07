#!/bin/bash
# realworld.sh: real programs doing real work. Each step has a deadline and
# prints PASS/FAIL with the reason, so one hang doesn't stop the rest.
W=${W:-/root/rw}
rm -rf "$W"; mkdir -p "$W"; cd "$W" || exit 1
pass=0; fail=0
step() {   # step NAME DEADLINE CMD...
    local name=$1 dl=$2; shift 2
    local t0=$EPOCHREALTIME
    if out=$(timeout -s KILL "$dl" bash -c "$*" 2>&1); then
        printf 'PASS  %-22s %6ss\n' "$name" "$(awk -v a="$t0" -v b="$EPOCHREALTIME" 'BEGIN{printf "%.2f", b-a}')"
        pass=$((pass+1))
    else
        rc=$?
        printf 'FAIL  %-22s rc=%s  %s\n' "$name" "$rc" "$(echo "$out" | tail -3 | tr '\n' ' ' | cut -c1-220)"
        fail=$((fail+1))
    fi
}

# --- a C project: autotools-free, but multi-file, -j, ar, a shared lib, gdb
mkdir -p c/src
cat > c/src/lib.c <<'EOF'
#include <stdio.h>
int add(int a, int b) { return a + b; }
const char* who(void) { return "libadd"; }
EOF
cat > c/src/main.c <<'EOF'
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
int add(int, int); const char* who(void);
static void* t(void* p) { long n = (long)p; long s = 0; for (long i = 0; i < 1000000; i++) s += i % (n + 2); return (void*)s; }
int main(int argc, char** argv) {
    pthread_t th[8]; long sum = 0;
    for (long i = 0; i < 8; i++) pthread_create(&th[i], 0, t, (void*)i);
    for (int i = 0; i < 8; i++) { void* r; pthread_join(th[i], &r); sum += (long)r; }
    printf("%s %d %ld\n", who(), add(2, 3), sum);
    return 0;
}
EOF
for i in $(seq 1 24); do printf 'int f%d(int x){return x*%d;}\n' $i $i > c/src/f$i.c; done
cat > c/Makefile <<'EOF'
SRCS := $(wildcard src/f*.c)
OBJS := $(SRCS:.c=.o)
all: app
src/%.o: src/%.c
	$(CC) -O2 -fPIC -c $< -o $@
libf.a: $(OBJS)
	ar rcs $@ $^
libadd.so: src/lib.c
	$(CC) -O2 -g -shared -fPIC $< -o $@
app: src/main.c libadd.so libf.a
	$(CC) -O2 -g src/main.c -L. -ladd libf.a -lpthread -Wl,-rpath,'$$ORIGIN' -o $@
clean:
	rm -f src/*.o *.a *.so app
EOF
step make_j8          120 "cd c && make -j8 CC=gcc"
step run_app          20  "cd c && ./app | grep -q '^libadd 5 '"
step make_noop        20  "cd c && make CC=gcc | grep -q 'Nothing to be done'"
step make_touch       20  "cd c && touch -d @0 src/f3.o && make CC=gcc 2>&1 | grep -q 'f3.o'"
step gdb_batch        60  "cd c && gdb -batch -ex 'break add' -ex run -ex 'print a+b' -ex 'info threads' ./app 2>&1 | grep -q '\\\$1 = 5'"
step cxx_stl          120 "printf '#include <map>\n#include <string>\n#include <iostream>\n#include <thread>\n#include <future>\nint main(){std::map<std::string,int> m; for(int i=0;i<1000;i++) m[std::to_string(i)]=i; auto f=std::async(std::launch::async,[&]{return m.size();}); std::cout<<f.get()<<std::endl;}' > a.cpp && g++ -O1 -std=c++20 a.cpp -o a && ./a | grep -qx 1000"

# --- cmake
mkdir -p cm
printf 'cmake_minimum_required(VERSION 3.20)\nproject(t C)\nadd_executable(t t.c)\n' > cm/CMakeLists.txt
printf '#include <stdio.h>\nint main(){puts("cmake-ok");}\n' > cm/t.c
step cmake_build      180 "cd cm && cmake -S . -B b >/dev/null && cmake --build b -j4 >/dev/null && ./b/t | grep -qx cmake-ok"

# --- git: init, commits, branches, merge, gc, a local clone, a worktree
step git_flow         120 "set -e; git init -q g && cd g && git config user.email a@b && git config user.name t
  for i in \$(seq 1 30); do echo \$i > f\$i; git add f\$i; git commit -qm c\$i; done
  git checkout -qb side && echo s > s && git add s && git commit -qm side
  git checkout -q - && echo m > m && git add m && git commit -qm main
  git merge -q --no-edit side && git gc -q && git fsck --no-progress
  cd .. && git clone -q g g2 && test \$(git -C g2 rev-list --count HEAD) = 33
  git -C g worktree add -q ../wt side && test -f wt/s"
step git_hooks_diff   60  "set -e; cd g && printf '#!/bin/sh\necho hook-ran > ../hook.out\n' > .git/hooks/post-commit && chmod +x .git/hooks/post-commit
  echo x >> f1 && git commit -qam hk && grep -q hook-ran ../hook.out && git log -p -3 | grep -q '^+x'"

# --- sqlite under concurrent writers (fcntl locks + WAL + mmap)
step sqlite_wal       120 "set -e; sqlite3 db.sqlite 'pragma journal_mode=wal; create table t(a integer);' >/dev/null
  for w in 1 2 3 4 5 6; do (for i in \$(seq 1 200); do sqlite3 -cmd '.timeout 20000' db.sqlite \"insert into t values(\$w)\" || exit 1; done) & done; wait
  test \$(sqlite3 db.sqlite 'select count(*) from t') = 1200 && sqlite3 db.sqlite 'pragma integrity_check' | grep -qx ok"

# --- python: venv + pip (no network: --no-index), sqlite3, threads, subprocess
step python_venv      120 "set -e; python3 -m venv v && v/bin/python -c 'import sys; assert sys.prefix != sys.base_prefix' && v/bin/pip --version >/dev/null"
cat > mix.py <<'PY'
import subprocess, sqlite3, concurrent.futures as cf, tempfile, os, json
if __name__ == '__main__':
    db = sqlite3.connect(':memory:'); db.execute('create table t(x)'); db.executemany('insert into t values(?)', [(i,) for i in range(10000)])
    assert db.execute('select sum(x) from t').fetchone()[0] == 49995000
    with cf.ProcessPoolExecutor(4) as ex: assert sum(ex.map(abs, range(-1000, 0))) == 500500
    out = subprocess.run(['sh', '-c', 'echo $((6*7))'], capture_output=True, text=True).stdout.strip(); assert out == '42', out
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 'x.json'); json.dump({'a': list(range(100))}, open(p, 'w')); assert json.load(open(p))['a'][-1] == 99
PY
step python_mix       120 "python3 mix.py"

# --- node: fs, child_process, worker_threads, a local http server
step node_mix         120 "node -e \"
const http=require('http'),cp=require('child_process'),{Worker}=require('worker_threads'),fs=require('fs');
fs.writeFileSync('n.txt','x'.repeat(1e5)); if(fs.readFileSync('n.txt').length!==1e5) process.exit(2);
if(cp.execSync('echo hi').toString().trim()!=='hi') process.exit(3);
new Worker('require(\\\"worker_threads\\\").parentPort.postMessage(21*2)',{eval:true}).on('message',m=>{ if(m!==42) process.exit(4);
 const s=http.createServer((q,r)=>r.end('pong')).listen(0,()=>{ let n=0; for(let i=0;i<50;i++) http.get('http://127.0.0.1:'+s.address().port,r=>{let b='';r.on('data',d=>b+=d);r.on('end',()=>{ if(b!=='pong') process.exit(5); if(++n===50){s.close();console.log('ok');}})}); });
});\" | grep -qx ok"

# --- archives and compression
step tar_zstd_xz      120 "set -e; mkdir -p ar && for i in \$(seq 1 300); do head -c 3000 /dev/urandom > ar/r\$i; done; ln -s r1 ar/link; mkdir ar/empty
  tar -I 'zstd -T0' -cf a.tzst ar && tar -cJf a.txz ar && mkdir x1 x2 && tar -xf a.tzst -C x1 && tar -xJf a.txz -C x2
  diff -r ar x1/ar && diff -r ar x2/ar && test -L x1/ar/link"

# --- perl, gpg, file, find/xargs, fish
step perl_mix         60  "perl -MDigest::SHA=sha256_hex -MPOSIX -e 'my \$p=fork; if(!\$p){exit 7} waitpid(\$p,0); die unless (\$?>>8)==7; print sha256_hex(\"x\"),\"\n\"' | grep -q '^2d711642'"
step gpg_sign         120 "set -e; export GNUPGHOME=\$PWD/gh; mkdir -m700 gh
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key 'T <t@t>' ed25519 sign never 2>/dev/null
  echo data > d && gpg --batch --pinentry-mode loopback --passphrase '' -s d 2>/dev/null && gpg --verify d.gpg 2>&1 | grep -q 'Good signature'
  gpgconf --kill all"
step file_find_xargs  60  "set -e; file c/app | grep -q ELF && test \$(find c -name '*.o' | xargs -P4 -n3 ls | wc -l) = 24"
step fish_script      60  "fish -c 'set -l n 0; for i in (seq 100); set n (math \$n + \$i); end; test \$n = 5050; and echo ok' | grep -qx ok"
step bash_jobs        20  "bash -c 'set -m; sleep 0.05 & sleep 0.05 & jobs | wc -l | grep -qx 2; wait; echo done' | grep -qx done"

# --- pacman read-only queries
step pacman_query     60  "pacman -Q | wc -l | awk '{exit !(\$1>100)}' && pacman -Qi bash | grep -q '^Name *: bash' && pacman -Qkq bash >/dev/null"

echo
echo "realworld: $pass passed, $fail failed"
