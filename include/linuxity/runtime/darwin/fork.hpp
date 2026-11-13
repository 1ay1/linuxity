// linuxity/runtime/darwin/fork.hpp
//
// Guest fork(2) on macOS: snapshot-and-spawn.
//
// Why not just fork(2) linuxity? Hypervisor.framework starts a helper thread
// the first time a VM is created, and that thread outlives hv_vm_destroy.
// fork() copies only the calling thread, so the child inherits locks the
// helper held mid-operation (we caught it inside os_log_create, reached from
// hv_vcpu_create). The result is a child that intermittently crashes or
// deadlocks while bringing up its own VM -- measured at ~10% of forks. No
// amount of teardown-before-fork fixes it, because the stale thread state
// isn't ours to clean up.
//
// So a guest fork is:
//
//   parent: COW-snapshot guest RAM (mach_make_memory_entry_64 with
//           MAP_MEM_VM_COPY: 1.5 ms for 1 GiB, no page copied up front),
//           serialize the rest of the process state, posix_spawn a fresh
//           linuxity in "--fork-child" mode, and send it both over a Mach
//           port it inherits by name.
//   child:  map the snapshot as its guest RAM, rebuild its kernel state from
//           the blob, create its VM from scratch -- in a process whose
//           Hypervisor.framework has never run, so there is nothing stale --
//           and resume the guest with x0 = 0.
//
// The child is a real host child of the parent (posix_spawn), so waitpid,
// SIGCHLD, kill and exit statuses all keep working through the host kernel.
#pragma once

#if defined(__APPLE__)

#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <sys/fileport.h>
#include <servers/bootstrap.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace lx::runtime::fork_ipc {

// The guest's memory travels as copy-on-write snapshots, one memory entry
// per extent of its address space (HvfMachine::snapshot); where each goes is
// in the blob (ForkImage::extents), in the same order.

// -- The handoff message ---------------------------------------------------
// One Mach message carries the memory entries (an out-of-line port array)
// plus an out-of-line blob with everything else. Using a message rather
// than a pipe is what lets the PORTS travel: a pipe can't carry a Mach right.
struct HandoffMsg {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t memory;
    mach_msg_ool_descriptor_t blob;
};

inline void fill_ports(mach_msg_ool_ports_descriptor_t& d, const std::vector<mach_port_t>& p) {
    d.address = p.empty() ? nullptr : const_cast<mach_port_t*>(p.data());
    d.count = static_cast<mach_msg_size_t>(p.size());
    d.deallocate = FALSE;
    d.copy = MACH_MSG_VIRTUAL_COPY;
    d.disposition = MACH_MSG_TYPE_MOVE_SEND;
    d.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
}
inline void fill_blob(mach_msg_ool_descriptor_t& d, const std::vector<std::byte>& b) {
    d.address = const_cast<std::byte*>(b.data());
    d.size = static_cast<mach_msg_size_t>(b.size());
    d.deallocate = FALSE;
    d.copy = MACH_MSG_VIRTUAL_COPY;
    d.type = MACH_MSG_OOL_DESCRIPTOR;
}
// Take ownership of a received port array / blob, freeing the OOL memory.
inline std::vector<mach_port_t> take_ports(const mach_msg_ool_ports_descriptor_t& d) {
    auto* p = static_cast<mach_port_t*>(d.address);
    std::vector<mach_port_t> out(p, p + d.count);
    if (p) ::mach_vm_deallocate(::mach_task_self(), reinterpret_cast<mach_vm_address_t>(p),
                                d.count * sizeof(mach_port_t));
    return out;
}
inline std::vector<std::byte> take_blob(const mach_msg_ool_descriptor_t& d) {
    auto* p = static_cast<std::byte*>(d.address);
    std::vector<std::byte> out(p, p + d.size);
    if (p) ::mach_vm_deallocate(::mach_task_self(), reinterpret_cast<mach_vm_address_t>(p), d.size);
    return out;
}
struct HandoffRecv {
    HandoffMsg msg;
    mach_msg_trailer_t trailer;
};

// The parent creates a receive right, registers it under a unique bootstrap
// name the child is told on its command line, and waits for the child to
// send back a reply port; then it ships the state. Bootstrap registration
// (rather than inheriting a port) works with posix_spawn, which doesn't pass
// arbitrary rights.
[[nodiscard]] inline std::string unique_service_name() {
    // pid, a per-process counter, and the clock: two threads forking in the
    // same 41 ns tick drew the same name, the second bootstrap_register
    // failed, and the guest's fork() was EAGAIN.
    static std::atomic<std::uint64_t> seq{0};
    return "org.linuxity.fork." + std::to_string(::getpid()) + "." +
           std::to_string(seq.fetch_add(1, std::memory_order_relaxed)) + "-" +
           std::to_string(::mach_absolute_time());
}

// The pid that made `name` (unique_service_name's), or -1. A zygote must
// know its creator from the name, not getppid(): if the creator has already
// exited, getppid() says 1 (launchd), and a zygote watching launchd for its
// exit stays parked forever.
[[nodiscard]] inline pid_t service_creator(std::string_view name) noexcept {
    constexpr std::string_view pre = "org.linuxity.fork.";
    if (!name.starts_with(pre)) return -1;
    name.remove_prefix(pre.size());
    pid_t pid = 0;
    std::size_t i = 0;
    for (; i < name.size() && name[i] >= '0' && name[i] <= '9'; ++i)
        pid = pid * 10 + (name[i] - '0');
    return i > 0 && i < name.size() && name[i] == '.' ? pid : -1;
}

inline void drop_ports(const std::vector<mach_port_t>& p) {
    for (mach_port_t q : p) ::mach_port_deallocate(::mach_task_self(), q);
}

// Sends `memory` (consumed either way: moved on success, released on failure).
[[nodiscard]] inline bool send(mach_port_t dest, const std::vector<mach_port_t>& memory,
                               const std::vector<std::byte>& blob) {
    HandoffMsg m{};
    m.header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    m.header.msgh_size = sizeof m;
    m.header.msgh_remote_port = dest;
    m.header.msgh_id = 0x4c58;               // 'LX'
    m.body.msgh_descriptor_count = 2;
    fill_ports(m.memory, memory);
    fill_blob(m.blob, blob);
    const bool ok = ::mach_msg(&m.header, MACH_SEND_MSG, sizeof m, 0, MACH_PORT_NULL,
                               MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == MACH_MSG_SUCCESS;
    if (!ok) drop_ports(memory);
    return ok;
}

struct Received {
    std::vector<mach_port_t> memory;   // one per ForkImage extent
    std::vector<std::byte> blob;
    std::vector<int> fds;              // fileports turned back into local fds
};

// -- fds as Mach rights ------------------------------------------------------
// A pre-spawned (zygote) child can't get its fds through posix_spawn file
// actions -- it already exists. Darwin's fileport turns an fd into a send
// right and back, so the fds ride in the same Mach message as the RAM.
[[nodiscard]] inline mach_port_t fd_to_port(int fd) {
    mach_port_t p = MACH_PORT_NULL;
    return ::fileport_makeport(fd, &p) == 0 ? p : MACH_PORT_NULL;
}

// The handoff with fds: memory port + blob + an OOL array of fileports.
struct HandoffMsgFds {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t memory;
    mach_msg_ool_descriptor_t blob;
    mach_msg_ool_ports_descriptor_t fds;
};
struct HandoffRecvFds {
    HandoffMsgFds msg;
    mach_msg_trailer_t trailer;
};

// Sends `memory` (consumed either way, like send()).
[[nodiscard]] inline bool send_with_fds(mach_port_t dest, const std::vector<mach_port_t>& memory,
                                        const std::vector<std::byte>& blob,
                                        const std::vector<int>& fds) {
    std::vector<mach_port_t> ports;
    ports.reserve(fds.size());
    for (int fd : fds) {
        const mach_port_t p = fd_to_port(fd);
        if (p == MACH_PORT_NULL) {
            drop_ports(ports);
            drop_ports(memory);
            return false;
        }
        ports.push_back(p);
    }
    HandoffMsgFds m{};
    m.header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    m.header.msgh_size = sizeof m;
    m.header.msgh_remote_port = dest;
    m.header.msgh_id = 0x4c59;               // 'LY'
    m.body.msgh_descriptor_count = 3;
    fill_ports(m.memory, memory);
    fill_blob(m.blob, blob);
    fill_ports(m.fds, ports);
    const bool ok = ::mach_msg(&m.header, MACH_SEND_MSG, sizeof m, 0, MACH_PORT_NULL,
                               MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == MACH_MSG_SUCCESS;
    if (!ok) { drop_ports(ports); drop_ports(memory); }
    return ok;
}

[[nodiscard]] inline bool receive_with_fds(mach_port_t port, Received& out) {
    HandoffRecvFds r{};
    if (::mach_msg(&r.msg.header, MACH_RCV_MSG, 0, sizeof r, port,
                   MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != MACH_MSG_SUCCESS)
        return false;
    out.memory = take_ports(r.msg.memory);
    out.blob = take_blob(r.msg.blob);
    out.fds.clear();
    for (mach_port_t p : take_ports(r.msg.fds)) {
        out.fds.push_back(::fileport_makefd(p));
        ::mach_port_deallocate(::mach_task_self(), p);
    }
    return true;
}

// A received handoff, unpacked.
[[nodiscard]] inline bool unpack(HandoffRecv& r, Received& out) {
    out.memory = take_ports(r.msg.memory);
    out.blob = take_blob(r.msg.blob);
    return true;
}

// Receive the fork handoff on `port`. `peer` is the parent's port we said
// hello on: if the parent gives up on this fork (its hello wait timed out,
// it was killed), that port dies, and so does the wait -- a child must never
// park forever on a handoff that is not coming. The zygote path has no peer
// (its creator watch ends it instead) and passes MACH_PORT_NULL.
//
// The peer dying is ALSO what follows every successful handoff: the parent
// sends, then drops the port. So "dead" never means "give up" on its own --
// only "dead and nothing queued" does. Both orders are handled: dead before
// we could ask (the request fails), and the notification dequeued before
// the handoff.
[[nodiscard]] inline bool receive(mach_port_t port, Received& out, mach_port_t peer = MACH_PORT_NULL) {
    HandoffRecv r{};
    auto take = [&](mach_port_t from, bool wait) {
        r = HandoffRecv{};
        return ::mach_msg(&r.msg.header, MACH_RCV_MSG | (wait ? 0 : MACH_RCV_TIMEOUT), 0,
                          sizeof r, from, wait ? MACH_MSG_TIMEOUT_NONE : 0,
                          MACH_PORT_NULL) == MACH_MSG_SUCCESS;
    };
    if (peer == MACH_PORT_NULL) return take(port, true) && unpack(r, out);

    mach_port_t notify = MACH_PORT_NULL, prev = MACH_PORT_NULL;
    ::mach_port_allocate(::mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify);
    if (::mach_port_request_notification(::mach_task_self(), peer, MACH_NOTIFY_DEAD_NAME, 0,
                                         notify, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev)
        != KERN_SUCCESS) {
        // already dead: the handoff is queued, or it never will be
        ::mach_port_mod_refs(::mach_task_self(), notify, MACH_PORT_RIGHT_RECEIVE, -1);
        return take(port, false) && unpack(r, out);
    }
    // one wait on {port, notify}; a port in a set is received through the set
    mach_port_t set = MACH_PORT_NULL;
    ::mach_port_allocate(::mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &set);
    ::mach_port_move_member(::mach_task_self(), port, set);
    ::mach_port_move_member(::mach_task_self(), notify, set);
    if (!take(set, true)) return false;
    if (r.msg.header.msgh_local_port == port) return unpack(r, out);
    return take(set, false) && r.msg.header.msgh_local_port == port && unpack(r, out);   // died: queued?
}

} // namespace lx::runtime::fork_ipc

#endif // __APPLE__
