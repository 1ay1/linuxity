// linuxity/mm/address_space.hpp
//
// The guest address space: a typed model of guest virtual memory.
//
// A running process's memory is a set of regions (segments, stack, heap,
// mmap areas), each a [vaddr, vaddr+len) range with permissions, backed by
// real host memory. This is what the ELF loader maps segments into and what
// the memory subsystem's mmap/brk grow. Guest pointers (UAddr) are resolved
// to host pointers ONLY here, with bounds+permission checks — the single
// choke point that keeps "the kernel followed a bad userspace pointer" from
// ever being possible above this layer.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"
#include "linuxity/host/host.hpp"

#include <cstring>
#include <span>
#include <vector>

namespace lx::mm {

// Permissions on a guest region — a strong bitset mirroring PROT_*.
enum class Perm : unsigned { none = 0, read = 1, write = 2, exec = 4 };
[[nodiscard]] constexpr Perm operator|(Perm a, Perm b) noexcept {
    return Perm(unsigned(a) | unsigned(b));
}
[[nodiscard]] constexpr bool allows(Perm set, Perm p) noexcept {
    return (unsigned(set) & unsigned(p)) == unsigned(p);
}

// A mapped region of the guest address space.
struct Region {
    UAddr       base{};       // guest virtual start
    std::size_t len{};        // length in bytes
    Perm        perm{};       // access permissions
    void*       host{};       // backing host memory (region base)

    [[nodiscard]] bool contains(UAddr a, std::size_t n) const noexcept {
        std::uint64_t s = value(base), e = s + len;
        std::uint64_t x = value(a);
        return x >= s && x + n >= x /*no overflow*/ && x + n <= e;
    }
};

// The address space owns its regions and, through the host, the memory
// behind them. Non-copyable (it holds host mappings); movable.
template <host::Host H>
class AddressSpace {
public:
    explicit AddressSpace(H& host) : host_{host} {}

    AddressSpace(const AddressSpace&) = delete;
    AddressSpace& operator=(const AddressSpace&) = delete;
    AddressSpace(AddressSpace&&) = default;

    ~AddressSpace() {
        for (auto& r : regions_)
            if (r.host) (void)host_.unmap(r.host, r.len);
    }

    // Reserve+back a region at a fixed guest vaddr (page-aligned by caller).
    // Used by the ELF loader for PT_LOAD and for the initial stack.
    [[nodiscard]] Result<Region*> map_fixed(UAddr base, std::size_t len, Perm perm) {
        // Map host memory writable first (loader needs to fill it); the
        // final permissions are applied by protect() once populated.
        auto m = host_.map(len, host::Prot::read | host::Prot::write);
        if (!m) return err<Region*>(m.error());
        regions_.push_back(Region{base, len, perm, *m});
        return ok(&regions_.back());
    }

    // Copy bytes INTO the guest at a guest vaddr (loader segment fill,
    // copy_out to userspace). Bounds+writability checked.
    [[nodiscard]] Status write(UAddr dst, std::span<const std::byte> src) {
        Region* r = find(dst, src.size());
        if (!r) return err(Errno::efault);
        std::size_t off = value(dst) - value(r->base);
        std::memcpy(static_cast<std::byte*>(r->host) + off, src.data(), src.size());
        return ok();
    }

    // Copy bytes OUT of the guest (copy_in from userspace). Bounds+readability.
    [[nodiscard]] Status read(UAddr src, std::span<std::byte> dst) const {
        const Region* r = find(src, dst.size());
        if (!r) return err(Errno::efault);
        std::size_t off = value(src) - value(r->base);
        std::memcpy(dst.data(), static_cast<std::byte*>(r->host) + off, dst.size());
        return ok();
    }

    // Zero a guest range (PT_LOAD .bss tail). Range must be writable.
    [[nodiscard]] Status zero(UAddr at, std::size_t n) {
        Region* r = find(at, n);
        if (!r) return err(Errno::efault);
        std::size_t off = value(at) - value(r->base);
        std::memset(static_cast<std::byte*>(r->host) + off, 0, n);
        return ok();
    }

    // Translate a guest vaddr to a host pointer, checking a required
    // permission over [a, a+n). THE guest->host pointer resolution point.
    [[nodiscard]] Result<void*> translate(UAddr a, std::size_t n, Perm need) {
        Region* r = find(a, n);
        if (!r) return err<void*>(Errno::efault);
        if (!allows(r->perm, need)) return err<void*>(Errno::eacces);
        return ok(static_cast<void*>(static_cast<std::byte*>(r->host)
                                     + (value(a) - value(r->base))));
    }

    // Apply a region's stored permissions to its host mapping (post-load).
    [[nodiscard]] Status finalize_perms() {
        for (auto& r : regions_) {
            host::Prot p = host::Prot::none;
            if (allows(r.perm, Perm::read))  p = p | host::Prot::read;
            if (allows(r.perm, Perm::write)) p = p | host::Prot::write;
            if (allows(r.perm, Perm::exec))  p = p | host::Prot::exec;
            LX_TRY(host_.protect(r.host, r.len, p));
        }
        return ok();
    }

    [[nodiscard]] const std::vector<Region>& regions() const noexcept { return regions_; }

private:
    [[nodiscard]] Region* find(UAddr a, std::size_t n) {
        for (auto& r : regions_) if (r.contains(a, n)) return &r;
        return nullptr;
    }
    [[nodiscard]] const Region* find(UAddr a, std::size_t n) const {
        for (auto& r : regions_) if (r.contains(a, n)) return &r;
        return nullptr;
    }

    H& host_;
    std::vector<Region> regions_;
};

} // namespace lx::mm
