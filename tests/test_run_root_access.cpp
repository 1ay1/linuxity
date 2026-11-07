// What systemd's post-install hooks need from the guest, on any host.
//
// pacman's hooks failed four ways on Android, each a place where linuxity
// was not acting like a Linux machine with root:
//   - fchmodat2(fd, "", mode, AT_EMPTY_PATH) answered ENOENT, so
//     systemd-sysusers could not copy /etc/group's mode onto its temp file
//     and never created a user;
//   - fstatfs on an O_PATH /proc said tmpfs, so systemd-tmpfiles decided
//     /proc was not mounted;
//   - socket(AF_NETLINK, NETLINK_AUDIT) answered the host's EACCES, and
//     systemd logged "Failed to connect to audit log" on every run;
//   - guest root could not write a 0444 file -- one it chmod'ed, created,
//     or copied up from the rootfs -- because linuxity applied the mode to
//     the host inode literally, so systemd-machine-id-setup decided /etc
//     was read-only.
#include "guest_harness.hpp"

#include <cstdio>

static const char* kSrc =
    "#define _GNU_SOURCE\n"
    "#include <errno.h>\n#include <fcntl.h>\n#include <string.h>\n"
    "#include <unistd.h>\n#include <sys/stat.h>\n#include <sys/vfs.h>\n"
    "#include <sys/socket.h>\n#include <sys/syscall.h>\n#include <linux/netlink.h>\n"
    "static int mode_of(const char* p) { struct stat s; return stat(p, &s) ? -1 : (int)(s.st_mode & 07777); }\n"
    "static int app(const char* p) {\n"
    "  int f = open(p, O_WRONLY|O_APPEND); if (f < 0) return -1;\n"
    "  int n = write(f, \"z\", 1); close(f); return n == 1 ? 0 : -1;\n"
    "}\n"
    "int main(void) {\n"
    "  struct statfs s;\n"
    "  int p = open(\"/proc/\", O_PATH|O_CLOEXEC);\n"
    "  if (p < 0 || fstatfs(p, &s) || s.f_type != 0x9fa0) return 10;   /* PROC_SUPER_MAGIC */\n"
    "  close(p);\n"
    "  int a = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_AUDIT);\n"
    "  if (a >= 0 || errno != EPROTONOSUPPORT) return 11;              /* no audit here */\n"
    "  int f = open(\"/w\", O_WRONLY|O_CREAT|O_TRUNC, 0644); write(f, \"a\", 1); close(f);\n"
    "  if (chmod(\"/w\", 0444)) return 12;\n"
    "  if (app(\"/w\")) return 13;                                       /* root writes 0444 */\n"
    "  if (mode_of(\"/w\") != 0444) return 14;\n"
    "  f = open(\"/c\", O_RDWR|O_CREAT|O_TRUNC, 0444);\n"
    "  if (f < 0 || write(f, \"x\", 1) != 1) return 15;                  /* create 0444, write */\n"
    "  close(f);\n"
    "  if (mode_of(\"/c\") != 0444) return 16;\n"
    "  if (app(\"/lower_ro\")) return 17;                                 /* copy-up of a 0444 file */\n"
    "  if (mode_of(\"/lower_ro\") != 0444) return 18;\n"
    "  int o = open(\"/c\", O_PATH|O_CLOEXEC);\n"
    "  if (o < 0 || syscall(452, o, \"\", 0640, AT_EMPTY_PATH)) return 19;  /* fchmodat2 */\n"
    "  close(o);\n"
    "  if (mode_of(\"/c\") != 0640) return 20;\n"
    "  return 42;\n"
    "}\n";

int main() {
#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__))
    std::puts("run_root_access: skipped (needs Linux/x86-64 or aarch64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("root_access", /*overlay=*/true,
        "printf ro > /tmp/lx_root_access_root/lower_ro && chmod 0444 /tmp/lx_root_access_root/lower_ro");
    if (!lxtest::compile_guest("run_root_access", tree, kSrc)) return 0;
    auto r = lxtest::run_guest(tree);
    lxtest::remove_tree(tree);
    if (!r) { std::puts("run_root_access: skipped (ptrace unavailable)"); return 0; }
    if (*r != 42) {
        std::printf("run_root_access: FAIL guest exit=%d (10 fstatfs(/proc) not proc, "
                    "11 audit socket not EPROTONOSUPPORT, 13 root could not write a file "
                    "it chmod'ed 0444, 15 ... a file it created 0444, 17 ... a 0444 file "
                    "from the rootfs, 14/16/18 the 0444 mode did not survive, 19/20 "
                    "fchmodat2 AT_EMPTY_PATH)\n", *r);
        return 1;
    }
    std::puts("run_root_access: guest root writes 0444 files, /proc fstatfs's as proc, "
              "fchmodat2 AT_EMPTY_PATH works, and there is no audit socket");
    return 0;
#endif
}
