#!/bin/sh
# no_got.sh OBJDUMP OBJ... -- fail if any in-guest object needs a GOT entry
# or a dynamic relocation: the flat blob is copied into the guest as bytes
# and never relocated (see blob.ld).
objdump=$1; shift
if "$objdump" -r "$@" | grep -E 'GOT|_GLOB_DAT|_RELATIVE'; then
    echo "in-guest blob: the relocations above need a GOT; keep data pointer-free" >&2
    exit 1
fi
exit 0
