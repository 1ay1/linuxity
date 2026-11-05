// linuxity/runtime/whp_vm.hpp
//
// The kernel-less virtual machine: a WHP partition, guest RAM, 4-level page
// tables, and vCPUs entered directly in 64-bit long mode at CPL 3.
//
// THE CENTRAL TRICK OF THIS BACKEND
// ---------------------------------
// On Linux we catch guest syscalls with seccomp (SIGSYS) or ptrace. On
// Darwin/arm64 the guest's `svc #0` traps to EL2 and Hypervisor.framework
// hands it to us. Windows has neither: there is no ptrace that can catch a
// Linux `syscall`, and WHP has no "syscall exit" reason.
//
// But x86-64 gives us something better. The `syscall` instruction is only
// legal when IA32_EFER.SCE (bit 0, "System Call Enable") is set; with SCE
// CLEAR, `syscall` raises #UD -- invalid opcode. And WHP can be told to
// deliver a chosen exception vector to the host as a VM exit, via the
// partition's ExceptionExitBitmap. So:
//
//     EFER.SCE = 0  +  ExceptionExitBitmap |= 1 << 6 (#UD)
//        => every guest `syscall` becomes a WHvRunVpExitReasonException exit,
//           delivered straight to us, with the guest stopped on the
//           instruction.
//
// That is the exact x86 analogue of HVF's svc-to-EL2, and it is strictly
// better than the alternative (point LSTAR at a guest-resident stub and have
// the stub hypercall out): there is NO guest kernel, NO LSTAR trampoline, NO
// ring-0 code in the guest address space at all. The guest runs entirely at
// CPL 3 and the only thing that leaves the CPU is a syscall. Every arithmetic,
// branch and memory instruction executes bare, at native speed.
//
// Consequences we must honor, and do:
//   * #UD is a FAULT, not a trap: RIP points AT the 2-byte `syscall`, so
//     resuming requires advancing RIP by 2 (see whp_regs.hpp advance()).
//   * A GENUINE invalid opcode (the guest executing garbage) arrives through
//     the same exit. We disambiguate by reading the instruction bytes: 0F 05
//     is a syscall, anything else is a real #UD and becomes SIGILL.
//
// THE SPLIT, which mirrors hvf_vm.hpp because SMP forces it:
//   WhpMachine -- the partition + guest RAM + page tables. One per process,
//                 shared by every vCPU.
//   WhpCpu     -- one vCPU: its index and run loop. WHP ties a vCPU to no
//                 particular thread, but we keep the "one guest thread = one
//                 host thread = one vCPU" model so the OS schedules guest
//                 threads across real cores.
//
// No syscall knowledge lives here. This is the "CPU + RAM" layer that the
// trap backend (whp_trap.hpp) and the loader build on.
#pragma once

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))

#include "linuxity/abi/result.hpp"
#include "linuxity/runtime/whp_api.hpp"
#include "linuxity/runtime/whp_mem.hpp"
#include "linuxity/runtime/whp_regs.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>

namespace lx::runtime {

// -- The guest-physical layout ---------------------------------------------
// Everything the guest can touch lives at or above kGuestFloor; the page
// tables and the GDT live below it, where a guest pointer cannot reach them
// (GuestRam::permits enforces the floor, and the tables' own PTEs never map
// that region, so the guest cannot even address it virtually).
//
//   0x0000_0000  PML4        (4KiB)
//   0x0000_1000  PDPT        (4KiB)
//   0x0000_2000  PD  #0      (4KiB)  -- 2MiB leaves covering the low 1GiB
//   0x0000_3000  GDT         (4KiB)
//   0x0020_0000  kGuestFloor -- guest-accessible RAM starts here
inline constexpr std::uint64_t kPml4Gpa     = 0x0000;
inline constexpr std::uint64_t kPdptGpa     = 0x1000;
inline constexpr std::uint64_t kPdGpa       = 0x2000;
inline constexpr std::uint64_t kGdtGpa      = 0x3000;
inline constexpr std::uint64_t kGuestFloor  = 0x20'0000;   // 2MiB

// Segment selectors in our GDT. Long mode barely uses segmentation, but CS
// must still carry the L (64-bit) bit and the right DPL, and SS must be a
// writable data segment at the same privilege level.
inline constexpr std::uint16_t kSelUserCode = 0x23;  // index 4, RPL 3
inline constexpr std::uint16_t kSelUserData = 0x1b;  // index 3, RPL 3

// -- The machine -----------------------------------------------------------
class WhpMachine {
public:
    WhpMachine() = default;
    WhpMachine(const WhpMachine&) = delete;
    WhpMachine& operator=(const WhpMachine&) = delete;

    ~WhpMachine() { destroy(); }

    // Create the partition and `bytes` of guest RAM, then build the page
    // tables that make it a flat 64-bit user address space.
    [[nodiscard]] Status create(std::uint64_t bytes, std::uint32_t vcpus = 1) {
        if (!whp().ok() || !hypervisor_present()) return err(Errno::enosys);
        if (bytes <= kGuestFloor) return err(Errno::einval);
        bytes = (bytes + kPageMask) & ~kPageMask;

        if (FAILED(whp().CreatePartition(&part_))) return err(Errno::eperm);

        // Processor count must be set BEFORE WHvSetupPartition.
        WHV_PARTITION_PROPERTY prop{};
        prop.ProcessorCount = vcpus;
        if (FAILED(whp().SetPartitionProperty(
                part_, WHvPartitionPropertyCodeProcessorCount,
                &prop, sizeof(prop)))) {
            destroy();
            return err(Errno::einval);
        }

        // Ask for exception VM exits -- the feature the whole backend rests
        // on. Must also precede SetupPartition.
        WHV_PARTITION_PROPERTY ext{};
        ext.ExtendedVmExits.ExceptionExit = 1;
        if (FAILED(whp().SetPartitionProperty(
                part_, WHvPartitionPropertyCodeExtendedVmExits,
                &ext, sizeof(ext)))) {
            destroy();
            return err(Errno::enosys);
        }

        // ...and specifically vector 6, #UD: our syscall trap.
        WHV_PARTITION_PROPERTY bitmap{};
        bitmap.ExceptionExitBitmap =
            1ull << unsigned(WHvX64ExceptionTypeInvalidOpcodeFault);
        if (FAILED(whp().SetPartitionProperty(
                part_, WHvPartitionPropertyCodeExceptionExitBitmap,
                &bitmap, sizeof(bitmap)))) {
            destroy();
            return err(Errno::enosys);
        }

        if (FAILED(whp().SetupPartition(part_))) {
            destroy();
            return err(Errno::eperm);
        }

        // Back guest RAM with host pages. VirtualAlloc rather than `new`
        // because WHvMapGpaRange pins whole pages and wants page alignment.
        host_ram_ = static_cast<std::byte*>(::VirtualAlloc(
            nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!host_ram_) { destroy(); return err(Errno::enomem); }
        ram_bytes_ = bytes;

        if (FAILED(whp().MapGpaRange(
                part_, host_ram_, 0, bytes,
                WHV_MAP_GPA_RANGE_FLAGS(WHvMapGpaRangeFlagRead |
                                        WHvMapGpaRangeFlagWrite |
                                        WHvMapGpaRangeFlagExecute)))) {
            destroy();
            return err(Errno::enomem);
        }

        ram_ = GuestRam{host_ram_, ram_bytes_, kGuestFloor};
        if (auto st = build_tables(); !st) { destroy(); return st; }
        mmu_ = Mmu{ram_, kPml4Gpa};
        return ok();
    }

    void destroy() noexcept {
        if (host_ram_) {
            if (part_) (void)whp().UnmapGpaRange(part_, 0, ram_bytes_);
            ::VirtualFree(host_ram_, 0, MEM_RELEASE);
            host_ram_ = nullptr;
            ram_bytes_ = 0;
        }
        if (part_) {
            (void)whp().DeletePartition(part_);
            part_ = nullptr;
        }
        ram_ = GuestRam{};
        mmu_ = Mmu{};
    }

    [[nodiscard]] WHV_PARTITION_HANDLE partition() const noexcept { return part_; }
    [[nodiscard]] const GuestRam& ram() const noexcept { return ram_; }
    [[nodiscard]] const Mmu& mmu() const noexcept { return mmu_; }
    [[nodiscard]] GuestMemView mem() const noexcept { return GuestMemView{ram_, mmu_}; }
    [[nodiscard]] bool live() const noexcept { return part_ != nullptr; }

    // Map [gva, gva+len) as 4KiB user pages onto the identical gpa, with the
    // requested permissions. The loader calls this for each ELF segment and
    // for the stack; mmap() calls it for new VMAs. Identity GVA==GPA keeps the
    // model simple and matches what the flat arm64 space gives us for free --
    // but it is a mapping we CHOOSE, and the MMU walk above means nothing
    // depends on it being identity.
    [[nodiscard]] Status map_pages(std::uint64_t gva, std::uint64_t len,
                                   bool writable, bool executable) {
        if (!ram_.valid()) return err(Errno::efault);
        const std::uint64_t beg = gva & ~kPageMask;
        const std::uint64_t end = (gva + len + kPageMask) & ~kPageMask;
        for (std::uint64_t a = beg; a < end; a += kPageSize) {
            if (auto st = map_one(a, a, writable, executable); !st) return st;
        }
        return ok();
    }

private:
    // Build the minimal 4-level table set plus a GDT. One PML4 entry -> one
    // PDPT -> one PD of 2MiB leaves covering the low 1GiB. Guest RAM beyond
    // 1GiB would need more PDs; `map_one` grows the tree on demand for
    // anything the loader maps explicitly, and this bootstrap covers the
    // identity window the loader places images in.
    [[nodiscard]] Status build_tables() {
        auto zero = [&](std::uint64_t gpa) {
            auto p = ram_.at_table(gpa, kPageSize);
            if (!p.empty()) std::memset(p.data(), 0, kPageSize);
            return !p.empty();
        };
        if (!zero(kPml4Gpa) || !zero(kPdptGpa) || !zero(kPdGpa) || !zero(kGdtGpa))
            return err(Errno::enomem);

        // PML4[0] -> PDPT, PDPT[0] -> PD. User-accessible and writable; the
        // leaf entries carry the real permissions.
        if (!write_entry(kPml4Gpa, 0, kPdptGpa | kPtePresent | kPteWrite | kPteUser))
            return err(Errno::enomem);
        if (!write_entry(kPdptGpa, 0, kPdGpa | kPtePresent | kPteWrite | kPteUser))
            return err(Errno::enomem);

        // PD: 2MiB leaves identity-mapping the low 1GiB, skipping entry 0 so
        // the table/GDT region below kGuestFloor is NOT mapped for the guest.
        // Writable + user; NX is left clear because guest text must execute
        // and per-segment W^X is enforced by map_one on 4KiB pages.
        for (std::uint64_t i = 1; i < 512; ++i) {
            const std::uint64_t leaf = (i << 21) | kPtePresent | kPteWrite |
                                       kPteUser | kPtePageSize;
            if (!write_entry(kPdGpa, i, leaf)) return err(Errno::enomem);
        }

        build_gdt();
        return ok();
    }

    bool write_entry(std::uint64_t table_gpa, std::uint64_t idx, std::uint64_t e) {
        auto cell = ram_.at_table(table_gpa + idx * 8, 8);
        if (cell.empty()) return false;
        std::memcpy(cell.data(), &e, 8);
        return true;
    }

    bool read_entry(std::uint64_t table_gpa, std::uint64_t idx, std::uint64_t& e) {
        auto cell = ram_.at_table(table_gpa + idx * 8, 8);
        if (cell.empty()) return false;
        std::memcpy(&e, cell.data(), 8);
        return true;
    }

    // A flat GDT: null, then a 64-bit user code and user data descriptor.
    void build_gdt() {
        auto gdt = ram_.at_table(kGdtGpa, kPageSize);
        if (gdt.empty()) return;
        std::uint64_t* e = reinterpret_cast<std::uint64_t*>(gdt.data());
        e[0] = 0;
        e[1] = 0;
        e[2] = 0;
        // index 3 = user data: present, DPL 3, type=data RW, G, D/B.
        e[3] = 0x00cff2000000ffffull;
        // index 4 = user code: present, DPL 3, type=code RX, L (64-bit), G.
        e[4] = 0x00affa000000ffffull;
    }

    // Map one 4KiB page, growing the table tree as needed.
    [[nodiscard]] Status map_one(std::uint64_t gva, std::uint64_t gpa,
                                 bool writable, bool executable) {
        std::uint64_t table = kPml4Gpa;
        for (int level = 4; level >= 2; --level) {
            const unsigned shift = unsigned(12 + 9 * (level - 1));
            const std::uint64_t idx = (gva >> shift) & 0x1ff;
            std::uint64_t e = 0;
            if (!read_entry(table, idx, e)) return err(Errno::efault);
            if ((e & kPtePresent) && (e & kPtePageSize)) {
                // A large leaf already covers this VA (the bootstrap identity
                // window). Splitting it would be needed to give this page
                // different permissions; for the identity window the 2MiB
                // leaf's permissions already permit RWX, so accept it.
                return ok();
            }
            if (!(e & kPtePresent)) {
                const std::uint64_t fresh = alloc_table();
                if (!fresh) return err(Errno::enomem);
                e = fresh | kPtePresent | kPteWrite | kPteUser;
                if (!write_entry(table, idx, e)) return err(Errno::efault);
            }
            table = e & kPteAddrMask;
        }
        const std::uint64_t idx = (gva >> 12) & 0x1ff;
        std::uint64_t leaf = (gpa & kPteAddrMask) | kPtePresent | kPteUser;
        if (writable) leaf |= kPteWrite;
        if (!executable) leaf |= kPteNx;
        return write_entry(table, idx, leaf) ? ok() : err(Errno::efault);
    }

    // Page-table pages come from a bump allocator at the TOP of guest RAM,
    // growing down. They are above kGuestFloor, so in principle a guest
    // pointer could reach them -- but they are never MAPPED into the guest's
    // virtual space, so the guest has no virtual address for them. (The
    // identity 2MiB window stops at 1GiB; the allocator starts above it for
    // any RAM larger than that, and below it we only hand out pages the
    // bootstrap window already covers read-write for the tables' own use.)
    [[nodiscard]] std::uint64_t alloc_table() {
        if (table_next_ == 0) table_next_ = ram_bytes_;
        if (table_next_ < kGuestFloor + kPageSize) return 0;
        table_next_ -= kPageSize;
        auto p = ram_.at_table(table_next_, kPageSize);
        if (p.empty()) return 0;
        std::memset(p.data(), 0, kPageSize);
        return table_next_;
    }

    WHV_PARTITION_HANDLE part_{nullptr};
    std::byte* host_ram_{nullptr};
    std::uint64_t ram_bytes_{0};
    std::uint64_t table_next_{0};
    GuestRam ram_{};
    Mmu mmu_{};
};

// -- One vCPU --------------------------------------------------------------
class WhpCpu {
public:
    WhpCpu() = default;
    WhpCpu(const WhpCpu&) = delete;
    WhpCpu& operator=(const WhpCpu&) = delete;
    ~WhpCpu() { destroy(); }

    [[nodiscard]] Status create(WhpMachine& m, std::uint32_t index = 0) {
        if (!m.live()) return err(Errno::enosys);
        part_ = m.partition();
        index_ = index;
        if (FAILED(whp().CreateVirtualProcessor(part_, index_, 0)))
            return err(Errno::eperm);
        live_ = true;
        return ok();
    }

    void destroy() noexcept {
        if (live_) {
            (void)whp().DeleteVirtualProcessor(part_, index_);
            live_ = false;
        }
    }

    // Put the vCPU straight into 64-bit long mode at CPL 3, with SCE clear.
    //
    // There is no real-mode bootstrap and no ring-0 code: we simply SET the
    // architectural state that a CPU would have reached after a boot sequence,
    // because a hypervisor lets us write CR0/CR4/EFER/CR3 and the segment
    // registers directly. This is why the backend needs no guest kernel.
    [[nodiscard]] Status enter_user(std::uint64_t rip, std::uint64_t rsp) {
        if (!live_) return err(Errno::enosys);

        const WHV_REGISTER_NAME names[]{
            WHvX64RegisterCr0, WHvX64RegisterCr3, WHvX64RegisterCr4,
            WHvX64RegisterEfer, WHvX64RegisterCs, WHvX64RegisterSs,
            WHvX64RegisterDs, WHvX64RegisterEs, WHvX64RegisterFs,
            WHvX64RegisterGs, WHvX64RegisterRip, WHvX64RegisterRsp,
            WHvX64RegisterRflags, WHvX64RegisterGdtr,
        };
        WHV_REGISTER_VALUE v[sizeof(names) / sizeof(names[0])]{};

        // CR0: PE (protected) | PG (paging) | NE | MP. Paging is mandatory in
        // long mode, which is why the tables above exist.
        v[0].Reg64 = 0x8000'0033ull;
        v[1].Reg64 = kPml4Gpa;                 // CR3 -> our PML4
        // CR4: PAE (required for 4-level paging) | OSFXSR | OSXMMEXCPT, so SSE
        // works -- every modern libc's memcpy uses it, and without OSFXSR the
        // first SSE instruction would #UD and look like a syscall.
        v[2].Reg64 = 0x0000'0620ull;
        // EFER: LME | LMA (long mode) | NXE (so the NX bit in our PTEs is
        // honored) -- and SCE deliberately CLEAR. That single zero bit is the
        // syscall trap.
        v[3].Reg64 = (1ull << 8) | (1ull << 10) | (1ull << 11);

        // CS: 64-bit user code. Long=1 is what actually selects 64-bit mode.
        v[4].Segment.Base = 0;
        v[4].Segment.Limit = 0xfffff;
        v[4].Segment.Selector = kSelUserCode;
        v[4].Segment.SegmentType = 0xb;        // code, execute/read, accessed
        v[4].Segment.NonSystemSegment = 1;
        v[4].Segment.DescriptorPrivilegeLevel = 3;
        v[4].Segment.Present = 1;
        v[4].Segment.Long = 1;
        v[4].Segment.Granularity = 1;

        // SS/DS/ES/FS/GS: user data at DPL 3.
        for (int i = 5; i <= 9; ++i) {
            v[i].Segment.Base = 0;
            v[i].Segment.Limit = 0xfffff;
            v[i].Segment.Selector = kSelUserData;
            v[i].Segment.SegmentType = 0x3;    // data, read/write, accessed
            v[i].Segment.NonSystemSegment = 1;
            v[i].Segment.DescriptorPrivilegeLevel = 3;
            v[i].Segment.Present = 1;
            v[i].Segment.Default = 1;
            v[i].Segment.Granularity = 1;
        }

        v[10].Reg64 = rip;
        v[11].Reg64 = rsp;
        // RFLAGS: bit 1 is reserved-one; IF set. No TF, no IOPL.
        v[12].Reg64 = 0x202;
        v[13].Table.Base = kGdtGpa;
        v[13].Table.Limit = 0xfff;

        if (FAILED(whp().SetVirtualProcessorRegisters(
                part_, index_, names,
                UINT32(sizeof(names) / sizeof(names[0])), v)))
            return err(Errno::einval);
        return ok();
    }

    // Run until the next exit. The exit context is retained so the trap
    // backend can inspect it (exception vector, instruction bytes, GPA).
    [[nodiscard]] Status run() {
        if (!live_) return err(Errno::enosys);
        std::memset(&exit_, 0, sizeof(exit_));
        if (FAILED(whp().RunVirtualProcessor(part_, index_, &exit_,
                                             sizeof(exit_))))
            return err(Errno::eio);
        return ok();
    }

    [[nodiscard]] const WHV_RUN_VP_EXIT_CONTEXT& last_exit() const noexcept {
        return exit_;
    }

    // Was the last exit our syscall trap -- a #UD whose faulting bytes are
    // actually `syscall` (0F 05)? Anything else that raises #UD is a REAL
    // invalid opcode and must become SIGILL, not a mystery syscall.
    [[nodiscard]] bool exit_is_syscall() const noexcept {
        if (exit_.ExitReason != WHvRunVpExitReasonException) return false;
        const auto& e = exit_.VpException;
        if (e.ExceptionType != unsigned(WHvX64ExceptionTypeInvalidOpcodeFault))
            return false;
        return e.InstructionByteCount >= 2 &&
               e.InstructionBytes[0] == 0x0f && e.InstructionBytes[1] == 0x05;
    }

    [[nodiscard]] bool read(GuestRegs& r) const noexcept {
        return read_regs(part_, index_, r);
    }
    [[nodiscard]] bool write_ret(const GuestRegs& r) const noexcept {
        return write_return(part_, index_, r);
    }
    [[nodiscard]] bool write_all(const GuestRegs& r) const noexcept {
        return write_regs(part_, index_, r);
    }

    // Force the vCPU out of WHvRunVirtualProcessor from another thread. The
    // run loop sees WHvRunVpExitReasonCanceled. This is how a signal, or a
    // sibling thread's exit_group, interrupts a blocked guest -- the analogue
    // of hv_vcpus_exit on Darwin.
    void kick() const noexcept {
        if (live_) (void)whp().CancelRunVirtualProcessor(part_, index_, 0);
    }

    [[nodiscard]] std::uint32_t index() const noexcept { return index_; }

private:
    WHV_PARTITION_HANDLE part_{nullptr};
    std::uint32_t index_{0};
    bool live_{false};
    WHV_RUN_VP_EXIT_CONTEXT exit_{};
};

} // namespace lx::runtime

#endif // _WIN32 && x86-64
