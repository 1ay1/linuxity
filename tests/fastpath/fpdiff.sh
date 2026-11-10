#!/bin/bash
# fpdiff.sh LINUXITY ROOT UPPER: the in-guest fast path must answer exactly
# like the trap. Runs fpdiff.c over tricky paths with it on and off, diffs.
set -u
L=$1; R=$2; U=$3
here=$(cd "$(dirname "$0")" && pwd)
bin=$(mktemp -d)/fpdiff
cc -O1 -o "$bin" "$here/fpdiff.c" || exit 2
d=$(dirname "$bin")
run() {
    # a scratch tree inside the guest, then the probes
    "$L" --quiet --root "$R" --persist "$U" --bind "$d:/fpd" /bin/sh -c '
        set -e
        w=/tmp/fpw; rm -rf $w; mkdir -p $w/dir/sub $w/rmme
        echo hi > $w/file; ln -s file $w/link; ln -s /etc/hostname $w/abslink
        ln -s dir $w/dirlink; ln -s nowhere $w/dangling
        echo x > $w/modded; chmod 600 $w/modded; chown 1000:1000 $w/modded 2>/dev/null || true
        echo y > $w/hard1; ln $w/hard1 $w/hard2 2>/dev/null || true
        touch $w/rmme/gone; rm $w/rmme/gone
        mkfifo $w/fifo 2>/dev/null || true
        /fpd/fpdiff / /usr /usr/bin /usr/bin/bash /bin /bin/sh /lib /usr/lib/libc.so.6 /lib/libc.so.6 \
            /etc /etc/passwd /etc/hostname /etc/mtab /proc /proc/self /proc/self/exe /proc/1/cwd \
            /dev /dev/null /dev/stdin /dev/fd /sys /sys/kernel /tmp /tmp/ \
            $w $w/file $w/link $w/abslink $w/dirlink $w/dirlink/sub $w/dangling $w/modded \
            $w/hard1 $w/hard2 $w/rmme/gone $w/fifo $w/nope $w/file/x $w/./file $w/../fpw/file \
            /usr//bin/bash /usr/bin/ "" \
            /var/lib/pacman/local /var/lib/pacman/local/nonexistent \
            --cd $w file link dirlink/sub dir/sub nope ./file ../fpw/file \
            --cd / usr/bin/bash etc
    ' 2>&1
}
on=$(mktemp); off=$(mktemp)
# inode numbers and birth times differ between two runs' scratch trees
norm() { sed -E 's/ ino=[0-9]+//; s/ btime=[0-9]+//'; }
run | norm > "$on"
LINUXITY_FASTPATH=0 run | norm > "$off"
if diff "$off" "$on" > "$d/diff"; then
    echo "fpdiff: $(wc -l < "$on") answers match"
    rm -rf "$d" "$on" "$off"; exit 0
fi
echo "fpdiff: fast path differs (< trap, > fast):"
cat "$d/diff"
rm -rf "$d" "$on" "$off"
exit 1
