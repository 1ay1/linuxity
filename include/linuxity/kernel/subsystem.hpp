// linuxity/kernel/subsystem.hpp
//
// Kernel subsystems as a typed composition.
//
// The whole design turns on ONE decision: we do not fake syscalls one by
// one. A syscall is merely a *view* onto a subsystem method. `read(2)`,
// `write(2)`, `open(2)`, `stat(2)`, `mount(2)` are all just the VFS
// subsystem seen through the syscall ABI. Organising by subsystem is how
// the real Linux kernel is organised, and it scales; a flat handler table
// does not.
//
// Each subsystem is specified as a C++ concept — an interface the type
// checker enforces. The kernel is the product of these subsystems, and the
// syscall dispatcher is the natural transformation from ABI numbers to the
// appropriate subsystem method.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"

#include <concepts>
#include <cstddef>
#include <span>
#include <string_view>

namespace lx::kernel {

// Open flags & mode, kept as strong-ish types (bitset newtypes).
enum class OFlags : std::uint32_t {};
enum class Mode   : std::uint32_t {};

// A file description as the guest sees it: an opaque handle the VFS owns.
// Concretely a small integer, but the VFS is free to back it with anything.
struct Open { Fd fd; };

// -- VFS -------------------------------------------------------------------
// open/read/write/stat/mount/rename/... The filesystem *namespace*, not any
// single backing store — tmpfs, procfs, a host-backed fs, and overlays all
// plug in below this concept.
template <class V>
concept Vfs = requires(V v, std::string_view path, Fd fd,
                       std::span<std::byte> rbuf,
                       std::span<const std::byte> wbuf,
                       OFlags fl, Mode m) {
    { v.open(path, fl, m) }  -> std::same_as<Result<Open>>;
    { v.read(fd, rbuf) }     -> std::same_as<Result<std::size_t>>;
    { v.write(fd, wbuf) }    -> std::same_as<Result<std::size_t>>;
    { v.close(fd) }          -> std::same_as<Status>;
};

// -- Process ---------------------------------------------------------------
// fork/clone/execve/wait4/kill and the virtual PID space. PIDs come from the
// runtime's own allocator; they have nothing to do with host PIDs.
template <class P>
concept Process = requires(P p, Pid pid, Signal sig) {
    { p.self() }         -> std::same_as<Pid>;
    { p.fork() }         -> std::same_as<Result<Pid>>;   // 0 in child, pid in parent
    { p.kill(pid, sig) } -> std::same_as<Status>;
};

// -- Memory ----------------------------------------------------------------
// mmap/mprotect/brk/munmap over the guest's virtual address space, layered
// on the host's raw map/unmap.
template <class M>
concept Memory = requires(M m, UAddr hint, std::size_t len) {
    { m.mmap(hint, len) }   -> std::same_as<Result<UAddr>>;
    { m.munmap(hint, len) } -> std::same_as<Status>;
    { m.brk(hint) }         -> std::same_as<Result<UAddr>>;
};

// -- The kernel ------------------------------------------------------------
// The product of the subsystems. A concrete kernel is any type that models
// all of them; the syscall layer is written once, generically, against this.
template <class K>
concept IsKernel = Vfs<K> && Process<K> && Memory<K>;

} // namespace lx::kernel
