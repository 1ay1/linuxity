#!/usr/bin/env python3
"""Recreate the shared-library version symlinks that Windows tar dropped.

Extracting a Linux rootfs on Windows without privilege loses every symlink
("Can't create ... Invalid argument"). For shared libraries that is fatal in a
specific way: the real file is `libcap.so.2.78`, but every binary's DT_NEEDED
names the SONAME `libcap.so.2`, which only existed as a symlink. ld.so then
reports "cannot open shared object file" for a library that is physically
present.

So: read each ELF's own SONAME out of its .dynamic section and hard-link (or
copy) the SONAME onto the real file. Hard links need no privilege on NTFS,
unlike symlinks, which is why this works where tar failed.

Usage:  python fix_rootfs_symlinks.py <rootfs-dir>
"""
import os, struct, sys

def read_soname(path):
    """Return the DT_SONAME of an ELF64 shared object, or None."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return None

    e_phoff    = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize= struct.unpack_from("<H", data, 54)[0]
    e_phnum    = struct.unpack_from("<H", data, 56)[0]

    dyn_off = dyn_size = None
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        if base + 56 > len(data):
            return None
        p_type = struct.unpack_from("<I", data, base)[0]
        if p_type == 2:                      # PT_DYNAMIC
            dyn_off  = struct.unpack_from("<Q", data, base + 8)[0]
            dyn_size = struct.unpack_from("<Q", data, base + 32)[0]
            break
    if dyn_off is None:
        return None

    # Walk the dynamic array for DT_SONAME (14) and DT_STRTAB (5).
    soname_off = strtab_vaddr = None
    off = dyn_off
    end = min(dyn_off + dyn_size, len(data))
    while off + 16 <= end:
        tag, val = struct.unpack_from("<qQ", data, off)
        if tag == 0:
            break
        if tag == 14:
            soname_off = val
        elif tag == 5:
            strtab_vaddr = val
        off += 16
    if soname_off is None or strtab_vaddr is None:
        return None

    # STRTAB is given as a vaddr; translate it to a file offset via PT_LOAD.
    strtab_off = None
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, base)[0]
        if p_type != 1:                      # PT_LOAD
            continue
        p_offset = struct.unpack_from("<Q", data, base + 8)[0]
        p_vaddr  = struct.unpack_from("<Q", data, base + 16)[0]
        p_filesz = struct.unpack_from("<Q", data, base + 32)[0]
        if p_vaddr <= strtab_vaddr < p_vaddr + p_filesz:
            strtab_off = p_offset + (strtab_vaddr - p_vaddr)
            break
    if strtab_off is None:
        return None

    start = strtab_off + soname_off
    nul = data.find(b"\0", start)
    if nul < 0:
        return None
    try:
        return data[start:nul].decode("utf-8")
    except UnicodeDecodeError:
        return None


def link_or_copy(src, dst):
    """Hard-link src->dst, falling back to a copy. Returns 'link'/'copy'/None."""
    try:
        os.link(src, dst)
        return "link"
    except OSError:
        pass
    try:
        import shutil
        shutil.copy2(src, dst)
        return "copy"
    except OSError:
        return None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    root = sys.argv[1]

    made = skipped = failed = 0
    for libdir in ("usr/lib", "usr/lib64", "lib", "lib64", "usr/local/lib"):
        d = os.path.join(root, libdir)
        if not os.path.isdir(d):
            continue
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for name in names:
            if ".so" not in name:
                continue
            full = os.path.join(d, name)
            if not os.path.isfile(full):
                continue
            soname = read_soname(full)
            if not soname or soname == name:
                continue
            target = os.path.join(d, soname)
            if os.path.exists(target):
                skipped += 1
                continue
            how = link_or_copy(full, target)
            if how:
                made += 1
                print(f"  {libdir}/{soname} -> {name} ({how})")
            else:
                failed += 1
                print(f"  FAILED {libdir}/{soname}", file=sys.stderr)

    print(f"\ncreated {made}, already present {skipped}, failed {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
