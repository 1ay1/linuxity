// linuxity/kernel/kernel.hpp
//
// A concrete kernel: the product of subsystem implementations.
//
// This is a *minimal but real* kernel — enough to satisfy the Vfs, Process
// and Memory concepts and actually service getpid/read/write/mmap. Each
// subsystem is a member; the kernel just forwards. The PID space, the fd
// table, and the address-space bookkeeping are all synthesized here, on top
// of a Host — the guest never touches the real OS.
#pragma once

#include "linuxity/host/host.hpp"
#include "linuxity/kernel/authority.hpp"
#include "linuxity/kernel/file_namespace.hpp"
#include "linuxity/kernel/process_table.hpp"
#include "linuxity/kernel/subsystem.hpp"

#include <unordered_map>

namespace lx::kernel {

// A monotonic allocator over any strong Id type. This is the "virtual PID
// allocator" / "fd allocator" the design calls for, made generic once.
template <class IdT>
class IdSpace {
public:
    explicit IdSpace(typename IdT::repr_type first) : next_{IdT{first}} {}
    [[nodiscard]] IdT allocate() { IdT id = next_; ++next_; return id; }
private:
    IdT next_;
};

template <host::Host H>
class Kernel {
public:
    // The Grants describe what the layer BELOW the line offers. Default is
    // the iOS sandbox: a complete virtual world, zero delegated authority.
    explicit Kernel(H& host, Grants grants = ios_sandbox())
        : host_{host}, grants_{grants} {
        self_ = pids_.allocate(); // pid 1: our "init"
    }

    [[nodiscard]] const Grants& grants() const noexcept { return grants_; }

    // The filesystem namespace the guest lives in (mount table + cwd + fd
    // table). The syscall dispatcher routes every path syscall through here.
    [[nodiscard]] FileNamespace& files() noexcept { return files_; }
    [[nodiscard]] const FileNamespace& files() const noexcept { return files_; }

    // The virtual process table /proc is synthesized from. The runtime keeps
    // it in sync as it traces the guest tree.
    [[nodiscard]] ProcessTable& procs() noexcept { return procs_; }
    [[nodiscard]] const ProcessTable& procs() const noexcept { return procs_; }

    // -- Process subsystem --------------------------------------------------
    [[nodiscard]] Pid self() const noexcept { return self_; }

    [[nodiscard]] Result<Pid> fork() {
        // A real fork snapshots the address space (copy-on-write) and the fd
        // table. Here we only demonstrate the virtual PID allocation.
        return ok(pids_.allocate());
    }

    [[nodiscard]] Status kill(Pid pid, Signal /*sig*/) {
        if (!pid) return err(Errno::einval);
        // Signal delivery happens within our own process model; a real impl
        // enqueues on the target task's pending-signal set.
        return ok();
    }

    // -- VFS subsystem ------------------------------------------------------
    [[nodiscard]] Result<Open> open(std::string_view, OFlags, Mode) {
        return err<Open>(Errno::enosys); // backing stores plug in here
    }

    [[nodiscard]] Result<std::size_t> read(Fd fd, std::span<std::byte> b) {
        return host_.read(fd.raw(), b); // stdio pass-through for the demo
    }

    [[nodiscard]] Result<std::size_t> write(Fd fd, std::span<const std::byte> b) {
        return host_.write(fd.raw(), b);
    }

    [[nodiscard]] Status close(Fd fd) { return host_.close(fd.raw()); }

    // -- Memory subsystem ---------------------------------------------------
    [[nodiscard]] Result<UAddr> mmap(UAddr /*hint*/, std::size_t len) {
        auto m = host_.map(len, host::Prot::read | host::Prot::write);
        if (!m) return std::unexpected(m.error());
        auto a = uaddr(reinterpret_cast<std::uint64_t>(*m));
        maps_.emplace(a, len);
        return ok(a);
    }

    [[nodiscard]] Status munmap(UAddr a, std::size_t len) {
        auto it = maps_.find(a);
        if (it == maps_.end()) return err(Errno::einval);
        maps_.erase(it);
        return host_.unmap(reinterpret_cast<void*>(value(a)), len);
    }

    [[nodiscard]] Result<UAddr> brk(UAddr a) { return ok(a); }

    // -- Authority-gated operations ----------------------------------------
    // These live at the line. Each names the Cap it needs and resolves it
    // through grants_.require() — the SINGLE place unbacked authority
    // becomes an errno. No scattered EPERM/ENOSYS.

    // mount(2). A tmpfs/procfs mount is Virtual (we own the fs). Mounting a
    // real device is HostDelegated — and will EPERM on an iOS sandbox.
    [[nodiscard]] Status mount(std::string_view fstype) {
        Cap need = (fstype == "tmpfs" || fstype == "proc" || fstype == "sysfs")
                       ? Cap::VfsNamespace       // our virtual world
                       : Cap::MountRealDevice;   // needs the host to expose it
        LX_TRY(grants_.require(need));
        // ... on success, update our virtual mount table here ...
        return ok();
    }

    // init_module(2). Nowhere to load it. Structurally absent ⇒ ENOSYS.
    [[nodiscard]] Status init_module() {
        LX_TRY(grants_.require(Cap::LoadKernelModule));
        return ok(); // unreachable on any real host
    }

    // uname(2). Pure information about our virtual Linux ⇒ always Virtual.
    [[nodiscard]] Status uname() {
        LX_TRY(grants_.require(Cap::Uname));
        return ok();
    }

private:
    H& host_;
    Grants grants_{};
    IdSpace<Pid> pids_{1};
    Pid self_{};
    FileNamespace files_{};
    ProcessTable procs_{};
    std::unordered_map<UAddr, std::size_t> maps_;
};

} // namespace lx::kernel

