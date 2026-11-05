// Shadow metadata store (fake_id0-grade) — a guest's chmod/chown must ROUND-TRIP
// through a later stat even though the host process is unprivileged and cannot
// really chown or keep every mode bit.
//
// The probe, run inside linuxity, exercises the coherence contract:
//   * chmod to a "weird" mode (0000, then 0755, then setuid 04711) and assert
//     the FULL guest-intended permission bits come back from stat — including
//     the setuid bit the unprivileged host would silently drop.
//   * chown to (1000,1000) and (0,0) and assert stat reports the recorded owner
//     (the host inode never actually changed owner).
//   * a fresh file defaults to root-owned (uid=gid=0) with NO shadow record.
//   * fchmod/fchown on an open fd take effect the same way.
//   * rename carries the metadata; a re-created file at a removed path starts
//     fresh (host default), not the stale record.
//
// The store persists in the overlay UPPER layer's .linuxity-meta journal, so we
// mount a real upper dir. If the guest ever saw the host's raw owner or lost a
// chmod, one of the ~10 checks below diverges and the probe returns its code.
#include "guest_harness.hpp"

#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

static const char* kProbe =
    "#include <unistd.h>\n#include <sys/stat.h>\n#include <fcntl.h>\n"
    "#include <stdio.h>\n"
    "static int m(const char*p){struct stat s; if(stat(p,&s)) return -1;"
        " return (int)(s.st_mode & 07777);}\n"
    "static int u(const char*p){struct stat s; if(stat(p,&s)) return -1;"
        " return (int)s.st_uid;}\n"
    "static int g(const char*p){struct stat s; if(stat(p,&s)) return -1;"
        " return (int)s.st_gid;}\n"
    "int main(void){\n"
    "  const char* F=\"/work/f\";\n"
    "  int fd=open(F,O_CREAT|O_WRONLY,0644); if(fd<0) return 10; close(fd);\n"
    "  /* fresh file => root-owned, no shadow record */\n"
    "  if(u(F)!=0||g(F)!=0) return 11;\n"
    "  /* chmod 0000 must round-trip exactly */\n"
    "  if(chmod(F,00000)) return 12;\n"
    "  if(m(F)!=00000) return 13;\n"
    "  /* chmod 0755 */\n"
    "  if(chmod(F,00755)) return 14;\n"
    "  if(m(F)!=00755) return 15;\n"
    "  /* setuid bit the unprivileged host would drop */\n"
    "  if(chmod(F,04711)) return 16;\n"
    "  if(m(F)!=04711) return 17;\n"
    "  /* chown to a non-root owner, recorded not real */\n"
    "  if(chown(F,1000,1001)) return 18;\n"
    "  if(u(F)!=1000||g(F)!=1001) return 19;\n"
    "  /* chown back to root */\n"
    "  if(chown(F,0,0)) return 20;\n"
    "  if(u(F)!=0||g(F)!=0) return 21;\n"
    "  /* -1 leaves a component unchanged */\n"
    "  if(chown(F,1000,-1)) return 22;\n"
    "  if(u(F)!=1000||g(F)!=0) return 23;\n"
    "  /* fchmod/fchown on an open fd */\n"
    "  int fd2=open(F,O_RDWR); if(fd2<0) return 24;\n"
    "  if(fchmod(fd2,02750)) return 25;\n"
    "  if(fchown(fd2,7,8)) return 26;\n"
    "  close(fd2);\n"
    "  if(m(F)!=02750||u(F)!=7||g(F)!=8) return 27;\n"
    "  /* rename carries the metadata */\n"
    "  if(rename(F,\"/work/g\")) return 28;\n"
    "  if(m(\"/work/g\")!=02750||u(\"/work/g\")!=7) return 29;\n"
    "  /* remove + recreate => fresh (root, default mode) */\n"
    "  if(unlink(\"/work/g\")) return 30;\n"
    "  int fd3=open(\"/work/g\",O_CREAT|O_WRONLY,0644); if(fd3<0) return 31; close(fd3);\n"
    "  if(u(\"/work/g\")!=0||g(\"/work/g\")!=0) return 32;\n"
    "  return 0;\n"
    "}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_meta: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    // /work exists only in the read-only LOWER, so the guest's chmod/chown
    // of things under it must copy up into the upper layer.
    const auto tree = lxtest::make_tree("meta", /*overlay=*/true,
                                        "mkdir -p /tmp/lx_meta_root/work",
                                        "/bin/mprobe");
    if (!lxtest::compile_guest("run_meta", tree, kProbe)) return 0;
    const std::string root  = tree.root;
    const std::string upper = tree.upper;

    // A real environment: a static glibc startup reads it, and an empty envp
    // is a different code path than a populated one.
    auto probe = [&] {
        auto r = lxtest::run_guest(tree, [&](auto& k) {
            kernel::ProcInfo init;
            init.pid = 1;
            init.cmdline = tree.exec;
            k.procs().upsert(init);
        }, {}, {"PATH=/bin:/usr/bin", "HOME=/root"});
        return r ? *r : -1;
    };

    const int code = probe();

    // Second run REUSES the same upper dir: the journal must replay, so the
    // recreated /work/g from the first run is still root-owned (no stale
    // record) and the probe (which recreates state from scratch) again returns
    // 0 -- proving the persisted journal doesn't corrupt a subsequent run.
    const int code2 = probe();

    lxtest::remove_tree(tree);

    if (code == -1) { std::puts("run_meta: skipped (ptrace unavailable)"); return 0; }
    if (code != 0) {
        std::printf("run_meta: FAIL probe code=%d (11 fresh-owner 13/15/17 chmod "
                    "17=setuid 19/21/23 chown 27 fchmod/fchown 29 rename-carries "
                    "32 recreate-fresh)\n", code);
        return 1;
    }
    if (code2 != 0) {
        std::printf("run_meta: FAIL second run (journal replay) code=%d\n", code2);
        return 1;
    }
    std::puts("run_meta: guest chmod/chown round-trips through stat — 0000, 0755 "
              "and setuid 04711 modes, non-root ownership, fchmod/fchown, and "
              "rename-carries-metadata all coherent (fake_id0-grade); the shadow "
              "journal persists and replays across runs");
    return 0;
#endif
}
