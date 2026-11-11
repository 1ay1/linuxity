// linuxity/runtime/darwin/mqueue.hpp
//
// POSIX message queues for a host that has none (macOS has no mq_*).
// A queue is a file named after it in the env's shared shm directory (the
// one /dev/shm is -- every guest process of the env, each its own linuxity,
// sees the same files), holding a fixed header and the queued messages:
//
//   [Header][Msg 0 .. maxmsg)        Msg = { u32 prio, u32 len, u64 seq, data[msgsize] }
//
// Every operation takes flock(LOCK_EX) on the file for its read-modify-
// write, so concurrent senders and receivers in different processes never
// see a half-updated queue. A blocked mq_send/mq_receive waits for the
// header's generation counter to move (polling briefly), giving up early
// for a deliverable guest signal (EINTR) or the deadline (ETIMEDOUT).
//
// The guest's queue descriptor is the queue file itself, opened with the
// guest's O_RDONLY/O_WRONLY/O_RDWR and O_NONBLOCK: close/dup/fork/CLOEXEC
// work unchanged, and O_NONBLOCK lives in the open file description as
// Linux's does (mq_getsetattr changes it with fcntl).
#pragma once
#if defined(__APPLE__)

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace lx::runtime::mq {

inline constexpr std::uint32_t kMagic = 0x4D514C58;   // "XLQM"
struct Header {
    std::uint32_t magic;
    std::uint32_t maxmsg, msgsize;
    std::uint32_t count;
    std::uint64_t seq;           // monotonic: FIFO order within a priority
    std::uint64_t gen;           // bumped on every send/receive (wakes waiters)
};
struct MsgHead { std::uint32_t prio, len; std::uint64_t seq; };

[[nodiscard]] inline std::size_t slot_size(const Header& h) { return sizeof(MsgHead) + h.msgsize; }

struct Lock {
    int fd;
    explicit Lock(int f) : fd{f} { while (::flock(fd, LOCK_EX) < 0 && errno == EINTR) {} }
    ~Lock() { ::flock(fd, LOCK_UN); }
};

[[nodiscard]] inline bool read_header(int fd, Header& h) {
    return ::pread(fd, &h, sizeof h, 0) == static_cast<ssize_t>(sizeof h) && h.magic == kMagic;
}

// Initialise a freshly created (empty) queue file. Linux defaults: 10 x 8 KiB.
[[nodiscard]] inline bool init(int fd, std::uint32_t maxmsg, std::uint32_t msgsize) {
    Lock l{fd};
    struct ::stat st{};
    if (::fstat(fd, &st) == 0 && st.st_size >= static_cast<off_t>(sizeof(Header))) return true;   // raced: exists
    Header h{kMagic, maxmsg ? maxmsg : 10, msgsize ? msgsize : 8192, 0, 0, 0};
    if (::ftruncate(fd, static_cast<off_t>(sizeof h + h.maxmsg * slot_size(h))) != 0) return false;
    if (::pwrite(fd, &h, sizeof h, 0) != static_cast<ssize_t>(sizeof h)) return false;
    const MsgHead freed{0, UINT32_MAX, 0};
    for (std::uint32_t i = 0; i < h.maxmsg; ++i)
        (void)::pwrite(fd, &freed, sizeof freed, static_cast<off_t>(sizeof h + i * slot_size(h)));
    return true;
}

// 0, or a positive errno. Never blocks.
[[nodiscard]] inline int try_send(int fd, const void* data, std::size_t len, std::uint32_t prio) {
    Lock l{fd};
    Header h{};
    if (!read_header(fd, h)) return EBADF;
    if (len > h.msgsize) return EMSGSIZE;
    if (h.count >= h.maxmsg) return EAGAIN;
    // the first free slot (free slots carry len == UINT32_MAX; init marks them)
    std::uint32_t slot = h.maxmsg;
    for (std::uint32_t i = 0; i < h.maxmsg; ++i) {
        MsgHead m{};
        (void)::pread(fd, &m, sizeof m, static_cast<off_t>(sizeof h + i * slot_size(h)));
        if (m.len == UINT32_MAX) { slot = i; break; }
    }
    if (slot == h.maxmsg) return EAGAIN;
    MsgHead m{prio, static_cast<std::uint32_t>(len), ++h.seq};
    const off_t at = static_cast<off_t>(sizeof h + slot * slot_size(h));
    if (::pwrite(fd, data, len, at + static_cast<off_t>(sizeof m)) != static_cast<ssize_t>(len)) return EIO;
    if (::pwrite(fd, &m, sizeof m, at) != static_cast<ssize_t>(sizeof m)) return EIO;
    ++h.count; ++h.gen;
    return ::pwrite(fd, &h, sizeof h, 0) == static_cast<ssize_t>(sizeof h) ? 0 : EIO;
}

// Bytes received (>= 0), or -errno. Never blocks. Highest priority first,
// oldest first within a priority.
[[nodiscard]] inline std::int64_t try_receive(int fd, void* buf, std::size_t cap, std::uint32_t* prio) {
    Lock l{fd};
    Header h{};
    if (!read_header(fd, h)) return -EBADF;
    if (cap < h.msgsize) return -EMSGSIZE;
    if (h.count == 0) return -EAGAIN;
    std::uint32_t best = h.maxmsg;
    MsgHead bm{};
    for (std::uint32_t i = 0; i < h.maxmsg; ++i) {
        MsgHead m{};
        (void)::pread(fd, &m, sizeof m, static_cast<off_t>(sizeof h + i * slot_size(h)));
        if (m.len == UINT32_MAX) continue;
        if (best == h.maxmsg || m.prio > bm.prio || (m.prio == bm.prio && m.seq < bm.seq)) { best = i; bm = m; }
    }
    if (best == h.maxmsg) return -EAGAIN;
    const off_t at = static_cast<off_t>(sizeof h + best * slot_size(h));
    if (::pread(fd, buf, bm.len, at + static_cast<off_t>(sizeof bm)) != static_cast<ssize_t>(bm.len)) return -EIO;
    MsgHead freed{0, UINT32_MAX, 0};
    (void)::pwrite(fd, &freed, sizeof freed, at);
    --h.count; ++h.gen;
    if (::pwrite(fd, &h, sizeof h, 0) != static_cast<ssize_t>(sizeof h)) return -EIO;
    if (prio) *prio = bm.prio;
    return bm.len;
}

}  // namespace lx::runtime::mq

#endif  // __APPLE__
