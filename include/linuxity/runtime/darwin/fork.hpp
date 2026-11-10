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

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace lx::runtime::fork_ipc {

// A COW snapshot of [addr, addr+size) as a send right. Pages are shared until
// either side writes them, exactly like fork's own copy-on-write.
[[nodiscard]] inline mach_port_t snapshot(void* addr, std::uint64_t size) {
    memory_object_size_t s = size;
    mach_port_t entry = MACH_PORT_NULL;
    if (::mach_make_memory_entry_64(::mach_task_self(), &s,
                                    reinterpret_cast<memory_object_offset_t>(addr),
                                    VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_VM_COPY,
                                    &entry, MACH_PORT_NULL) != KERN_SUCCESS)
        return MACH_PORT_NULL;
    return entry;
}

// Map a snapshot as fresh, private, read-write memory.
[[nodiscard]] inline void* map_snapshot(mach_port_t entry, std::uint64_t size) {
    mach_vm_address_t a = 0;
    if (::mach_vm_map(::mach_task_self(), &a, size, 0, VM_FLAGS_ANYWHERE, entry, 0,
                      /*copy=*/FALSE, VM_PROT_READ | VM_PROT_WRITE,
                      VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE) != KERN_SUCCESS)
        return nullptr;
    return reinterpret_cast<void*>(a);
}

// -- The handoff message ---------------------------------------------------
// One Mach message carries the memory entry (a port descriptor) plus an
// out-of-line blob with everything else. Using a message rather than a pipe
// is what lets the PORT travel: a pipe can't carry a Mach right.
struct HandoffMsg {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t memory;
    mach_msg_ool_descriptor_t blob;
    std::uint64_t mem_size;
};
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
    return "org.linuxity.fork." + std::to_string(::getpid()) + "." +
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

[[nodiscard]] inline bool send(mach_port_t dest, mach_port_t memory,
                               std::uint64_t mem_size,
                               const std::vector<std::byte>& blob) {
    HandoffMsg m{};
    m.header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    m.header.msgh_size = sizeof m;
    m.header.msgh_remote_port = dest;
    m.header.msgh_id = 0x4c58;               // 'LX'
    m.body.msgh_descriptor_count = 2;
    m.memory.name = memory;
    m.memory.disposition = MACH_MSG_TYPE_MOVE_SEND;
    m.memory.type = MACH_MSG_PORT_DESCRIPTOR;
    m.blob.address = const_cast<std::byte*>(blob.data());
    m.blob.size = static_cast<mach_msg_size_t>(blob.size());
    m.blob.deallocate = FALSE;
    m.blob.copy = MACH_MSG_VIRTUAL_COPY;
    m.blob.type = MACH_MSG_OOL_DESCRIPTOR;
    m.mem_size = mem_size;
    return ::mach_msg(&m.header, MACH_SEND_MSG, sizeof m, 0, MACH_PORT_NULL,
                      MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == MACH_MSG_SUCCESS;
}

struct Received {
    mach_port_t memory{MACH_PORT_NULL};
    std::uint64_t mem_size{};
    std::vector<std::byte> blob;
    std::vector<int> fds;          // fileports turned back into local fds
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
    mach_msg_port_descriptor_t memory;
    mach_msg_ool_descriptor_t blob;
    mach_msg_ool_ports_descriptor_t fds;
    std::uint64_t mem_size;
};
struct HandoffRecvFds {
    HandoffMsgFds msg;
    mach_msg_trailer_t trailer;
};

[[nodiscard]] inline bool send_with_fds(mach_port_t dest, mach_port_t memory,
                                        std::uint64_t mem_size,
                                        const std::vector<std::byte>& blob,
                                        const std::vector<int>& fds) {
    std::vector<mach_port_t> ports;
    ports.reserve(fds.size());
    for (int fd : fds) {
        const mach_port_t p = fd_to_port(fd);
        if (p == MACH_PORT_NULL) {
            for (mach_port_t q : ports) ::mach_port_deallocate(::mach_task_self(), q);
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
    m.memory.name = memory;
    m.memory.disposition = MACH_MSG_TYPE_MOVE_SEND;
    m.memory.type = MACH_MSG_PORT_DESCRIPTOR;
    m.blob.address = const_cast<std::byte*>(blob.data());
    m.blob.size = static_cast<mach_msg_size_t>(blob.size());
    m.blob.deallocate = FALSE;
    m.blob.copy = MACH_MSG_VIRTUAL_COPY;
    m.blob.type = MACH_MSG_OOL_DESCRIPTOR;
    m.fds.address = ports.empty() ? nullptr : ports.data();
    m.fds.count = static_cast<mach_msg_size_t>(ports.size());
    m.fds.deallocate = FALSE;
    m.fds.copy = MACH_MSG_VIRTUAL_COPY;
    m.fds.disposition = MACH_MSG_TYPE_MOVE_SEND;
    m.fds.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    m.mem_size = mem_size;
    const bool ok = ::mach_msg(&m.header, MACH_SEND_MSG, sizeof m, 0, MACH_PORT_NULL,
                               MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == MACH_MSG_SUCCESS;
    if (!ok) for (mach_port_t q : ports) ::mach_port_deallocate(::mach_task_self(), q);
    return ok;
}

[[nodiscard]] inline bool receive_with_fds(mach_port_t port, Received& out) {
    HandoffRecvFds r{};
    if (::mach_msg(&r.msg.header, MACH_RCV_MSG, 0, sizeof r, port,
                   MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != MACH_MSG_SUCCESS)
        return false;
    out.memory = r.msg.memory.name;
    out.mem_size = r.msg.mem_size;
    auto* p = static_cast<std::byte*>(r.msg.blob.address);
    out.blob.assign(p, p + r.msg.blob.size);
    ::mach_vm_deallocate(::mach_task_self(),
                         reinterpret_cast<mach_vm_address_t>(r.msg.blob.address),
                         r.msg.blob.size);
    auto* ports = static_cast<mach_port_t*>(r.msg.fds.address);
    out.fds.clear();
    for (mach_msg_size_t i = 0; i < r.msg.fds.count; ++i) {
        const int fd = ::fileport_makefd(ports[i]);
        ::mach_port_deallocate(::mach_task_self(), ports[i]);
        out.fds.push_back(fd);
    }
    if (ports)
        ::mach_vm_deallocate(::mach_task_self(), reinterpret_cast<mach_vm_address_t>(ports),
                             r.msg.fds.count * sizeof(mach_port_t));
    return true;
}

[[nodiscard]] inline bool receive(mach_port_t port, Received& out) {
    HandoffRecv r{};
    if (::mach_msg(&r.msg.header, MACH_RCV_MSG, 0, sizeof r, port,
                   MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != MACH_MSG_SUCCESS)
        return false;
    out.memory = r.msg.memory.name;
    out.mem_size = r.msg.mem_size;
    auto* p = static_cast<std::byte*>(r.msg.blob.address);
    out.blob.assign(p, p + r.msg.blob.size);
    ::mach_vm_deallocate(::mach_task_self(),
                         reinterpret_cast<mach_vm_address_t>(r.msg.blob.address),
                         r.msg.blob.size);
    return true;
}

} // namespace lx::runtime::fork_ipc

#endif // __APPLE__
