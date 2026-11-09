#!/bin/bash
# linuxity smoke test: everything a user does in the first hour.
# Run it as root inside an environment, e.g. on the phone through the app's
# instance: `linuxity exec <env> -T --user root -- /bin/bash smoke.sh`.
# Needs network; installs git python sqlite tmux vim, and expects a user
# `ayush` with sudo (`linuxity env adduser <env> ayush`).
pass=0; fail=0
t() {  # t "name" cmd...
  local name=$1; shift
  local out
  if out=$(timeout 120 "$@" 2>&1); then pass=$((pass+1)); printf 'PASS %s\n' "$name"
  else fail=$((fail+1)); printf 'FAIL %s\n%s\n' "$name" "$(printf '%s' "$out" | tail -4 | sed 's/^/     /')"; fi
}
cd /root
t "identity"        sh -c '[ "$(id -u)" = 0 ] && uname -m | grep -q aarch64 && [ "$(uname -n)" = "$(cat /etc/hostname)" ]'
t "dns"             getent hosts archlinux.org
t "https"           curl -fsSI https://archlinux.org
t "pacman install"  pacman -S --noconfirm --needed git python sqlite tmux vim
t "git clone"       sh -c 'rm -rf /tmp/r && git clone -q --depth 1 https://github.com/1ay1/vibe /tmp/r && test -f /tmp/r/vibe.h'
t "python"          python -c 'import ssl, json, hashlib; print(hashlib.sha256(b"x").hexdigest()[:8])'
t "threads+procs"   python -c '
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
with ThreadPoolExecutor(8) as e: assert sum(e.map(lambda x: x*x, range(100))) == 328350
with ProcessPoolExecutor(4) as e: assert sum(e.map(abs, range(-50, 50))) == 2500'
t "unix socket"     python -c '
import socket, os, threading
p="/tmp/s.sock"; os.path.exists(p) and os.unlink(p)
s=socket.socket(socket.AF_UNIX); s.bind(p); s.listen(1)
threading.Thread(target=lambda: socket.socket(socket.AF_UNIX).connect(p) or None).start()
c,_=s.accept(); print("ok")'
t "fifo"            sh -c 'rm -f /tmp/f; mkfifo /tmp/f && (echo hi > /tmp/f &) && read x < /tmp/f && [ "$x" = hi ]'
t "sqlite file"     sh -c 'rm -f /tmp/d.db; sqlite3 /tmp/d.db "create table t(x); insert into t values(42);" && [ "$(sqlite3 /tmp/d.db "select x from t")" = 42 ]'
t "hardlink"        sh -c 'rm -f /tmp/a /tmp/b; echo 1 > /tmp/a && ln /tmp/a /tmp/b && echo 2 >> /tmp/b && [ "$(cat /tmp/a)" = "$(printf "1\n2")" ] && [ "$(stat -c %h /tmp/a)" = 2 ]'
t "pty"             python -c 'import pty, os; pid, fd = pty.fork(); os.execvp("tty", ["tty"]) if pid == 0 else print(os.read(fd, 100))'
t "tmux"            sh -c 'tmux -S /tmp/tm new -d -s x "sleep 5" && tmux -S /tmp/tm ls && tmux -S /tmp/tm kill-server'
t "vim batch"       sh -c 'printf "a\n" > /tmp/v && vim -es -c "s/a/b/" -c wq /tmp/v && grep -q b /tmp/v'
t "signals"         sh -c 'sleep 30 & p=$!; kill -TERM $p; wait $p; [ $? = 143 ]'
t "ps/top"          sh -c 'ps aux | grep -q "[p]s aux" && top -bn1 | head -3 >/dev/null'
t "proc/sys"        sh -c 'grep -q MemTotal /proc/meminfo && nproc && ls /sys/class/net | grep -q lo && ls /sys/class /sys/fs/cgroup >/dev/null && lscpu >/dev/null'
t "sudo as user"    su ayush -c 'sudo -n whoami | grep -qx root'
t "locale+utf8"     sh -c 'printf "\xc3\xa9\n" | wc -m | grep -q 2'
t "bridge helpers"  sh -c 'command -v xdg-open && command -v wl-copy'
echo "== $pass passed, $fail failed"
