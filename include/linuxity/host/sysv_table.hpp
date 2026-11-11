// linuxity/host/sysv_table.hpp
//
// The host's System V IPC objects as Linux's /proc/sysvipc/{msg,sem,shm}
// text, for hosts that have SysV IPC but no /proc to read it from (Darwin).
// The rows use the HOST's pids and uids, in the same columns a Linux
// /proc/sysvipc file has, so vfs/procfs.hpp's sysvipc_from_host maps them to
// the guest's view exactly as it does for a Linux host.
//
// Darwin lists its objects through a private sysctl iteration
// (kern.sysv.ipcs.{shm,sem,msg}, bsd/sys/ipcs.h) -- what ipcs(1) uses. Each
// call fills one *id_ds and advances a slot cursor; the object's id is
// IXSEQ_TO_IPCID(slot, perm) = perm._seq << 16 | slot, the same id
// shmget/msgget/semget returned.
#pragma once

#include <string>
#include <string_view>

#if defined(__APPLE__)
#include <cstdio>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#endif

namespace lx::host {

#if defined(__APPLE__)
namespace detail {
struct IpcsCommand {             // struct IPCS_command
    int magic;                   // IPCS_MAGIC
    int op;
    int cursor;
    int datalen;
    void* data;
};
}  // namespace detail
#endif

// One /proc/sysvipc file's text, header line first; empty where the host
// offers no listing.
[[nodiscard]] inline std::string sysvipc_table(std::string_view which) {
#if defined(__APPLE__)
    std::string out = "header\n";
    char row[512];
    auto each = [](const char* oid, int op, auto* ds, auto&& fn) {
        detail::IpcsCommand ic{1, op, 0, static_cast<int>(sizeof *ds), ds};
        std::size_t sz = sizeof ic;
        for (int guard = 0; guard < 65536; ++guard) {
            if (::sysctlbyname(oid, &ic, &sz, &ic, sizeof ic) != 0) return;
            fn((ic.cursor - 1) & 0xffff);
        }
    };
    auto ll = [](auto v) { return static_cast<unsigned long long>(v); };
    if (which == "shm") {
        struct ::shmid_ds d{};
        each("kern.sysv.ipcs.shm", 0x2, &d, [&](int slot) {
            const auto& p = d.shm_perm;
            std::snprintf(row, sizeof row,
                          "%d %d %o %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu 0 0\n",
                          static_cast<int>(p._key), (p._seq << 16) | slot, p.mode & 0777u,
                          ll(d.shm_segsz), ll(d.shm_cpid), ll(d.shm_lpid), ll(d.shm_nattch),
                          ll(p.uid), ll(p.gid), ll(p.cuid), ll(p.cgid),
                          ll(d.shm_atime), ll(d.shm_dtime), ll(d.shm_ctime));
            out += row;
        });
    } else if (which == "msg") {
        struct ::msqid_ds d{};
        each("kern.sysv.ipcs.msg", 0x200, &d, [&](int slot) {
            const auto& p = d.msg_perm;
            std::snprintf(row, sizeof row,
                          "%d %d %o %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
                          static_cast<int>(p._key), (p._seq << 16) | slot, p.mode & 0777u,
                          ll(d.msg_cbytes), ll(d.msg_qnum), ll(d.msg_lspid), ll(d.msg_lrpid),
                          ll(p.uid), ll(p.gid), ll(p.cuid), ll(p.cgid),
                          ll(d.msg_stime), ll(d.msg_rtime), ll(d.msg_ctime));
            out += row;
        });
    } else if (which == "sem") {
        struct ::semid_ds d{};
        each("kern.sysv.ipcs.sem", 0x20, &d, [&](int slot) {
            const auto& p = d.sem_perm;
            std::snprintf(row, sizeof row, "%d %d %o %llu %llu %llu %llu %llu %llu %llu\n",
                          static_cast<int>(p._key), (p._seq << 16) | slot, p.mode & 0777u,
                          ll(d.sem_nsems), ll(p.uid), ll(p.gid), ll(p.cuid), ll(p.cgid),
                          ll(d.sem_otime), ll(d.sem_ctime));
            out += row;
        });
    } else {
        return {};
    }
    return out;
#else
    (void)which;
    return {};
#endif
}

}  // namespace lx::host
