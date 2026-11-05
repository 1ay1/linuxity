// linuxity/runtime/darwin/ipc.hpp
//
// SysV IPC and POSIX message queues.
//
// These are the oldest Unix IPC mechanisms and they are still load-bearing:
// PostgreSQL, Oracle and X11 use SysV shared memory and semaphores, and
// `ipcs`/`ipcrm` inspect them. Darwin HAS all three SysV families with the
// same semantics -- it is a BSD -- but the ABI differs in the usual ways:
//
//   * The *ctl commands diverge: Linux IPC_STAT is 2 and IPC_SET is 1,
//     Darwin's are 2 and 1 too, but Linux adds IPC_INFO/SHM_STAT/SEM_INFO
//     numbers Darwin does not have.
//   * struct ipc_perm differs in field order AND width (Linux has a 32-bit
//     key then uid/gid/cuid/cgid/mode/seq; Darwin interleaves differently).
//   * Linux multiplexes semop/semtimedop and passes `struct sembuf` arrays
//     whose layout happens to match Darwin's.
//   * shmat returns an ADDRESS, which for us must be a GUEST address -- so a
//     SysV segment has to live inside guest RAM, not in linuxity's own heap.
//
// That last point is why shm is implemented over the guest's own address
// space rather than Darwin's shmat: the guest must be able to dereference
// what it gets back.
//
// POSIX mqueue has no Darwin equivalent at all, so it is built from scratch
// on a shared file plus the futex primitive -- the same way a libc would.
#pragma once

#if defined(__APPLE__)

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace lx::runtime::ipc {

// -- Linux struct ipc_perm (asm-generic) -----------------------------------
struct LinuxIpcPerm {
    std::int32_t  key;
    std::uint32_t uid, gid, cuid, cgid;
    std::uint16_t mode, pad1_;
    std::uint16_t seq, pad2_;
    std::uint64_t unused1_, unused2_;
};
static_assert(sizeof(LinuxIpcPerm) == 48);

// struct shmid_ds, struct semid_ds, struct msqid_ds as Linux lays them out.
struct LinuxShmidDs {
    LinuxIpcPerm shm_perm;
    std::uint64_t shm_segsz;
    std::int64_t  shm_atime, shm_dtime, shm_ctime;
    std::int32_t  shm_cpid, shm_lpid;
    std::uint64_t shm_nattch;
    std::uint64_t unused4_, unused5_;
};
struct LinuxSemidDs {
    LinuxIpcPerm sem_perm;
    std::int64_t  sem_otime, sem_ctime;
    std::uint64_t sem_nsems;
    std::uint64_t unused3_, unused4_;
};
struct LinuxMsqidDs {
    LinuxIpcPerm msg_perm;
    std::int64_t  msg_stime, msg_rtime, msg_ctime;
    std::uint64_t msg_cbytes, msg_qnum, msg_qbytes;
    std::int32_t  msg_lspid, msg_lrpid;
    std::uint64_t unused4_, unused5_;
};

// IPC_* commands (identical values on both kernels for the three we need).
inline constexpr int kIpcRmid = 0, kIpcSet = 1, kIpcStat = 2;
// Linux-only query commands.
inline constexpr int kIpcInfo = 3, kShmInfo = 14, kShmStat = 13;
inline constexpr int kSemInfo = 19, kSemStat = 18;
inline constexpr int kMsgInfo = 12, kMsgStat = 11;
// GETVAL/SETVAL and friends for semctl.
inline constexpr int kGetPid = 11, kGetNcnt = 14, kGetZcnt = 15,
                     kGetVal = 12, kGetAll = 13, kSetVal = 16, kSetAll = 17;

[[nodiscard]] inline LinuxIpcPerm perm_to_linux(const struct ::ipc_perm& p) noexcept {
    LinuxIpcPerm l{};
    l.key  = p._key;
    l.uid  = p.uid;
    l.gid  = p.gid;
    l.cuid = p.cuid;
    l.cgid = p.cgid;
    l.mode = static_cast<std::uint16_t>(p.mode);
    l.seq  = p._seq;
    return l;
}

// And back, for IPC_SET (only uid/gid/mode are settable).
inline void perm_from_linux(const LinuxIpcPerm& l, struct ::ipc_perm& p) noexcept {
    p.uid  = l.uid;
    p.gid  = l.gid;
    p.mode = static_cast<mode_t>(l.mode & 0777);
}

} // namespace lx::runtime::ipc

#endif // __APPLE__
