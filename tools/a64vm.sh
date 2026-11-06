#!/bin/sh
# Bring up a real arm64 Linux VM for linuxity conformance work.
#
# WHY a full-system VM and not qemu-user: linuxity IS a ptrace supervisor, and
# qemu-user emulates guest syscalls itself -- there is no real trap for
# PTRACE_SYSCALL to intercept, so linuxity hangs the moment it tries to
# supervise anything. Measured, not assumed. A full-system VM runs a genuine
# arm64 kernel, so ptrace, /proc, devpts and signals are all the real thing
# and goldens recorded here ARE kernel truth.
#
# This host is x86-64, so there is no KVM for arm64 -- TCG only. Boot is slow
# (minutes), the build inside is slower. That is the price of real goldens;
# keep the VM alive across sessions rather than rebooting it.
#
#   tools/a64vm.sh up      # boot (background, serial log to /tmp/a64/serial.log)
#   tools/a64vm.sh ssh     # shell in
#   tools/a64vm.sh down    # shut down
set -u

DIR=/tmp/a64
IMG=$DIR/root.qcow2
BASE=/tmp/deb-a64.qcow2
SEED=$DIR/seed.iso
PORT=2222
PIDF=$DIR/qemu.pid
LOG=$DIR/serial.log

mkdir -p "$DIR"

case "${1:-up}" in
up)
    if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
        echo "already running (pid $(cat "$PIDF")), ssh on port $PORT"
        exit 0
    fi
    [ -f "$BASE" ] || { echo "missing base image $BASE" >&2; exit 1; }

    # A copy-on-write overlay, so the pristine download stays reusable.
    [ -f "$IMG" ] || qemu-img create -f qcow2 -b "$BASE" -F qcow2 "$IMG" 40G >/dev/null

    # cloud-init: one user, our ssh key, no password prompts.
    if [ ! -f "$SEED" ]; then
        mkdir -p "$DIR/ci"
        [ -f ~/.ssh/id_ed25519.pub ] || ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519
        cat > "$DIR/ci/meta-data" <<EOF
instance-id: a64vm
local-hostname: a64vm
EOF
        cat > "$DIR/ci/user-data" <<EOF
#cloud-config
users:
  - name: dev
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat ~/.ssh/id_ed25519.pub)
# The toolchain linuxity needs to build and record goldens natively.
package_update: true
packages:
  - build-essential
  - cmake
  - ninja-build
  - git
  - gdb
  - strace
  - python3
ssh_pwauth: false
EOF
        ( cd "$DIR/ci" && genisoimage -quiet -output "$SEED" -volid cidata \
            -joliet -rock meta-data user-data ) 2>/dev/null \
          || ( cd "$DIR/ci" && xorriso -as mkisofs -quiet -o "$SEED" \
                 -V cidata -J -r meta-data user-data )
    fi

    # UEFI needs a writable copy of the varstore.
    [ -f "$DIR/vars.fd" ] || cp /usr/share/edk2/aarch64/QEMU_VARS.fd "$DIR/vars.fd"

    # -smp 4: TCG does not scale past a few vCPUs for this workload.
    qemu-system-aarch64 \
        -machine virt -cpu cortex-a72 -smp 4 -m 4096 \
        -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/aarch64/QEMU_EFI.fd \
        -drive if=pflash,format=raw,file="$DIR/vars.fd" \
        -drive if=virtio,format=qcow2,file="$IMG" \
        -drive if=virtio,format=raw,file="$SEED" \
        -netdev user,id=n0,hostfwd=tcp::$PORT-:22 \
        -device virtio-net-pci,netdev=n0 \
        -nodefaults -serial "file:$LOG" -monitor none -display none \
        -pidfile "$PIDF" -daemonize
    echo "booting (TCG, slow). serial log: $LOG"
    echo "wait for ssh:  tools/a64vm.sh wait"
    ;;
wait)
    i=0
    while [ $i -lt 600 ]; do
        if ssh -p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
               -o ConnectTimeout=2 -o BatchMode=yes dev@localhost true 2>/dev/null; then
            echo "ssh is up after ${i}s"
            exit 0
        fi
        sleep 1
        i=$((i+1))
    done
    echo "timed out; check $LOG" >&2
    exit 1
    ;;
ssh)
    shift || true
    exec ssh -p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        dev@localhost "$@"
    ;;
down)
    [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null && rm -f "$PIDF" && echo "stopped"
    ;;
*)
    echo "usage: $0 {up|wait|ssh|down}" >&2
    exit 2
    ;;
esac
