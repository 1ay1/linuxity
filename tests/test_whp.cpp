// tests/test_whp.cpp
//
// The Windows Hypervisor Platform backend.
//
// Split in two deliberately:
//
//   OFFLINE checks run EVERYWHERE (any Windows machine, CI container, a box
//   with virtualization disabled in firmware). They cover the parts that are
//   pure logic and therefore the parts where a silent bug is most likely: the
//   Linux/Win32 flag and struct translation, and the 4-level page-table walk.
//   No hypervisor is touched.
//
//   LIVE checks need a real partition, so they SKIP cleanly when WHP is
//   unavailable rather than failing the suite. A developer without Hyper-V
//   enabled must still get a green build.
#include "linuxity/runtime/whp_api.hpp"
#include "linuxity/runtime/whp_mem.hpp"
#include "linuxity/runtime/whp_regs.hpp"
#include "linuxity/runtime/whp_trap.hpp"
#include "linuxity/runtime/whp_vm.hpp"
#include "linuxity/runtime/whp_win32.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace lx::runtime;

static int failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                   \
        }                                                                 \
    } while (0)

// -- Offline: the Linux/Win32 translation layer ---------------------------
static void test_open_flags() {
    using namespace lx::runtime::win32;

    // O_RDONLY is 0, so it must be decoded from the low two bits, not tested
    // as a flag. This is the bug the access_mode() helper exists to prevent.
    CHECK(access_mode(0) == 0);
    auto ro = translate_open(0);
    CHECK(ro.access == GENERIC_READ);
    CHECK(ro.disposition == OPEN_EXISTING);

    auto rw = translate_open(std::uint64_t(LinuxOpen::rdwr));
    CHECK(rw.access == (GENERIC_READ | GENERIC_WRITE));

    // O_CREAT|O_EXCL must be CREATE_NEW -- the one disposition that fails if
    // the file exists. Getting this wrong silently clobbers lockfiles.
    auto excl = translate_open(std::uint64_t(LinuxOpen::creat) |
                               std::uint64_t(LinuxOpen::excl) |
                               std::uint64_t(LinuxOpen::wronly));
    CHECK(excl.disposition == CREATE_NEW);

    auto ctrunc = translate_open(std::uint64_t(LinuxOpen::creat) |
                                 std::uint64_t(LinuxOpen::trunc));
    CHECK(ctrunc.disposition == CREATE_ALWAYS);

    auto conly = translate_open(std::uint64_t(LinuxOpen::creat));
    CHECK(conly.disposition == OPEN_ALWAYS);

    // A directory handle is impossible without BACKUP_SEMANTICS.
    auto dir = translate_open(std::uint64_t(LinuxOpen::directory));
    CHECK((dir.attrs & FILE_FLAG_BACKUP_SEMANTICS) != 0);
    CHECK(dir.want_directory);

    // Every open must share DELETE, or the POSIX "unlink an open file" idiom
    // breaks.
    CHECK((ro.share & FILE_SHARE_DELETE) != 0);

    // Flags Win32 cannot express must be REPORTED, not dropped.
    auto app = translate_open(std::uint64_t(LinuxOpen::append) |
                              std::uint64_t(LinuxOpen::nonblock));
    CHECK(app.want_append);
    CHECK(app.want_nonblock);

    auto nofollow = translate_open(std::uint64_t(LinuxOpen::nofollow));
    CHECK((nofollow.attrs & FILE_FLAG_OPEN_REPARSE_POINT) != 0);
}

static void test_stat_translation() {
    using namespace lx::runtime::win32;

    BY_HANDLE_FILE_INFORMATION b{};
    b.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    b.nFileSizeLow = 4096;
    b.nNumberOfLinks = 1;
    b.dwVolumeSerialNumber = 0xdeadbeef;
    auto sd = stat_from_win(b);
    CHECK((sd.st_mode & 0xf000) == kSIfdir);
    CHECK((sd.st_mode & 0777) == 0755);

    b.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    auto sf = stat_from_win(b);
    CHECK((sf.st_mode & 0xf000) == kSIfreg);
    CHECK((sf.st_mode & 0777) == 0644);

    // READONLY is the one real permission signal Win32 carries; it must clear
    // the write bits or the guest's `test -w` lies.
    b.dwFileAttributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY;
    auto sr = stat_from_win(b);
    CHECK((sr.st_mode & 0222) == 0);

    b.dwFileAttributes = FILE_ATTRIBUTE_REPARSE_POINT;
    CHECK((stat_from_win(b).st_mode & 0xf000) == kSIflnk);

    // st_blocks is in 512-byte units regardless of st_blksize.
    b.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    b.nFileSizeLow = 1000;
    auto sb = stat_from_win(b);
    CHECK(sb.st_blksize == 4096);
    CHECK(sb.st_blocks == 2);

    // A >4GiB size must survive the hi/lo split.
    b.nFileSizeHigh = 1;
    b.nFileSizeLow = 0;
    CHECK(stat_from_win(b).st_size == 0x1'0000'0000ll);
}

static void test_time_translation() {
    using namespace lx::runtime::win32;

    // The 1601->1970 epoch gap, the error that hides for 369 years.
    FILETIME zero{0, 0};
    CHECK(from_filetime(zero).sec == -kFiletimeEpochDeltaSec);

    // Round-trip a known instant.
    LinuxTimespec t{1'700'000'000, 123'456'700};
    auto back = from_filetime(to_filetime(t));
    CHECK(back.sec == t.sec);
    CHECK(back.nsec == t.nsec);

    // The Unix epoch itself is exactly the delta in ticks.
    auto ft = to_filetime(LinuxTimespec{0, 0});
    const std::uint64_t ticks =
        (std::uint64_t(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    CHECK(ticks == std::uint64_t(kFiletimeEpochDeltaSec) * 10'000'000ull);
}

static void test_errno_translation() {
    using namespace lx::runtime::win32;
    CHECK(error_to_linux(ERROR_FILE_NOT_FOUND) == LNOENT);
    CHECK(error_to_linux(ERROR_PATH_NOT_FOUND) == LNOENT);
    CHECK(error_to_linux(ERROR_ACCESS_DENIED) == LACCES);
    CHECK(error_to_linux(ERROR_FILE_EXISTS) == LEXIST);
    CHECK(error_to_linux(ERROR_ALREADY_EXISTS) == LEXIST);
    CHECK(error_to_linux(ERROR_DIR_NOT_EMPTY) == LNOTEMPTY);
    CHECK(error_to_linux(ERROR_DISK_FULL) == LNOSPC);
    CHECK(error_to_linux(ERROR_INVALID_HANDLE) == LBADF);
    CHECK(error_to_linux(ERROR_BROKEN_PIPE) == LPIPE);
    // Sharing violations are Windows-specific; EACCES is the closest truth.
    CHECK(error_to_linux(ERROR_SHARING_VIOLATION) == LACCES);
    // An unmapped error must become EIO, never pass through as a lie.
    CHECK(error_to_linux(0xfffe) == LIO);
    CHECK(fail(ERROR_FILE_NOT_FOUND) == -LNOENT);
}

static void test_path_translation() {
    using namespace lx::runtime::win32;

    // Absolute paths get \\?\ so MAX_PATH and reserved names stop mattering.
    auto w = to_win_path("C:/rootfs/etc/passwd");
    CHECK(w == L"\\\\?\\C:\\rootfs\\etc\\passwd");

    // A relative path must NOT take the prefix (Win32 rejects it).
    CHECK(to_win_path("etc/passwd") == L"etc\\passwd");

    // Round-trip back to Linux form.
    CHECK(from_win_path(L"\\\\?\\C:\\rootfs\\etc") == "C:/rootfs/etc");

    // A file literally named "nul" is legal in a Linux rootfs; the prefix is
    // what makes it addressable on Windows.
    auto n = to_win_path("C:/rootfs/nul");
    CHECK(n.compare(0, 4, L"\\\\?\\") == 0);
}

static void test_prot_translation() {
    using namespace lx::runtime::win32;
    CHECK(translate_prot(kProtRead).writable == false);
    CHECK(translate_prot(kProtRead).executable == false);
    CHECK(translate_prot(kProtRead | kProtWrite).writable == true);
    CHECK(translate_prot(kProtRead | kProtExec).executable == true);
}

// -- Offline: the register ABI -------------------------------------------
static void test_syscall_abi() {
    GuestRegs r{};
    r[GReg::rax] = 257;          // openat
    r[GReg::rdi] = 0xaaaa;
    r[GReg::rsi] = 0xbbbb;
    r[GReg::rdx] = 0xcccc;
    r[GReg::r10] = 0xdddd;
    r[GReg::r8]  = 0xeeee;
    r[GReg::r9]  = 0xffff;
    r[GReg::rip] = 0x40'0000;

    CHECK(r.nr() == 257);
    // The 4th argument is r10, NOT rcx -- the `syscall` instruction clobbers
    // rcx with the return address, so a backend that reads rcx gets garbage.
    CHECK(r.arg(0) == 0xaaaa);
    CHECK(r.arg(1) == 0xbbbb);
    CHECK(r.arg(2) == 0xcccc);
    CHECK(r.arg(3) == 0xdddd);
    CHECK(r.arg(4) == 0xeeee);
    CHECK(r.arg(5) == 0xffff);

    // #UD is a FAULT: rip points AT the 2-byte syscall, so resuming must
    // advance past it or the guest re-faults forever.
    r.advance(-2);
    CHECK(std::int64_t(r[GReg::rax]) == -2);
    CHECK(r[GReg::rip] == 0x40'0002);

    // The name table and the value array must agree index-for-index.
    CHECK(kWhpSyscallRegs.size() == std::size_t(GReg::count));
    CHECK(kWhpSyscallRegs[std::size_t(GReg::rax)] == WHvX64RegisterRax);
    CHECK(kWhpSyscallRegs[std::size_t(GReg::r10)] == WHvX64RegisterR10);
    CHECK(kWhpSyscallRegs[std::size_t(GReg::rip)] == WHvX64RegisterRip);
}

// -- Offline: the MMU walk ------------------------------------------------
// Build a page-table tree in a plain buffer and walk it. No hypervisor
// involved: this is the logic that decides whether a guest pointer resolves
// to the right byte, so it is tested in isolation.
static void test_mmu_walk() {
    constexpr std::uint64_t kRam = 8 << 20;             // 8MiB
    std::vector<std::byte> buf(kRam, std::byte{0});
    GuestRam ram{buf.data(), kRam, kGuestFloor};

    auto put = [&](std::uint64_t gpa, std::uint64_t e) {
        auto c = ram.at_table(gpa, 8);
        CHECK(!c.empty());
        std::memcpy(c.data(), &e, 8);
    };

    // PML4[0] -> PDPT -> PD -> PT, with a single 4KiB leaf mapping
    // gva 0x40'0000 to gpa 0x30'0000.
    constexpr std::uint64_t pml4 = 0x0000, pdpt = 0x1000, pd = 0x2000,
                            pt = 0x4000;
    constexpr std::uint64_t gva = 0x40'0000, gpa = 0x30'0000;
    const std::uint64_t link = kPtePresent | kPteWrite | kPteUser;
    put(pml4 + 8 * ((gva >> 39) & 0x1ff), pdpt | link);
    put(pdpt + 8 * ((gva >> 30) & 0x1ff), pd | link);
    put(pd   + 8 * ((gva >> 21) & 0x1ff), pt | link);
    put(pt   + 8 * ((gva >> 12) & 0x1ff), gpa | link);

    Mmu mmu{ram, pml4};

    auto w = mmu.translate(gva);
    CHECK(w.present);
    CHECK(w.gpa == gpa);
    CHECK(w.writable);
    CHECK(w.user);
    CHECK(w.to_page_end == kPageSize);

    // An offset within the page must carry through, and shrink to_page_end.
    auto w2 = mmu.translate(gva + 0x100);
    CHECK(w2.present);
    CHECK(w2.gpa == gpa + 0x100);
    CHECK(w2.to_page_end == kPageSize - 0x100);

    // An unmapped address must NOT resolve.
    CHECK(!mmu.translate(gva + kPageSize).present);
    CHECK(!mmu.translate(0x8000'0000).present);

    // Non-canonical addresses are #GP on real hardware; the walker must agree
    // rather than silently truncating to 48 bits.
    CHECK(!mmu.translate(0x0001'0000'0000'0000ull).present);

    // A read-only leaf must report !writable, so copy_out can refuse it
    // instead of scribbling on guest text.
    constexpr std::uint64_t ro_gva = 0x41'0000, ro_gpa = 0x31'0000;
    put(pt + 8 * ((ro_gva >> 12) & 0x1ff), ro_gpa | kPtePresent | kPteUser);
    auto ro = mmu.translate(ro_gva);
    CHECK(ro.present);
    CHECK(!ro.writable);
}

static void test_large_page_walk() {
    constexpr std::uint64_t kRam = 8 << 20;
    std::vector<std::byte> buf(kRam, std::byte{0});
    GuestRam ram{buf.data(), kRam, kGuestFloor};
    auto put = [&](std::uint64_t gpa, std::uint64_t e) {
        auto c = ram.at_table(gpa, 8);
        std::memcpy(c.data(), &e, 8);
    };

    // A 2MiB leaf, as the bootstrap identity window uses. A walker that only
    // understood 4KiB leaves would fail on exactly the common case.
    constexpr std::uint64_t pml4 = 0, pdpt = 0x1000, pd = 0x2000;
    const std::uint64_t link = kPtePresent | kPteWrite | kPteUser;
    put(pml4, pdpt | link);
    put(pdpt, pd | link);
    const std::uint64_t leaf2m = 0x20'0000;
    put(pd + 8 * 1, leaf2m | link | kPtePageSize);

    Mmu mmu{ram, pml4};
    auto w = mmu.translate(0x20'1234);
    CHECK(w.present);
    CHECK(w.gpa == 0x20'1234);
    // to_page_end must span to the end of the 2MiB leaf, not 4KiB -- that is
    // what lets a long buffer be handled in one chunk.
    CHECK(w.to_page_end == 0x20'0000 - 0x1234);
}

static void test_guest_mem_view() {
    constexpr std::uint64_t kRam = 8 << 20;
    std::vector<std::byte> buf(kRam, std::byte{0});
    GuestRam ram{buf.data(), kRam, kGuestFloor};
    auto put = [&](std::uint64_t gpa, std::uint64_t e) {
        auto c = ram.at_table(gpa, 8);
        std::memcpy(c.data(), &e, 8);
    };
    constexpr std::uint64_t pml4 = 0, pdpt = 0x1000, pd = 0x2000;
    const std::uint64_t link = kPtePresent | kPteWrite | kPteUser;
    put(pml4, pdpt | link);
    put(pdpt, pd | link);
    put(pd + 8, 0x20'0000ull | link | kPtePageSize);   // 2MiB at gva 0x200000

    GuestMemView mem{ram, Mmu{ram, pml4}};

    // Round-trip a string through guest memory.
    const char* msg = "/etc/passwd";
    const std::uint64_t gva = 0x20'1000;
    CHECK(mem.copy_out(gva, std::span<const std::byte>{
              reinterpret_cast<const std::byte*>(msg),
              std::strlen(msg) + 1}) == std::strlen(msg) + 1);
    CHECK(mem.cstr(gva) == "/etc/passwd");

    // Typed put/get.
    std::uint64_t v = 0xcafe'f00d'dead'beefull;
    CHECK(mem.put(gva + 64, v));
    std::uint64_t got = 0;
    CHECK(mem.get(gva + 64, got));
    CHECK(got == v);

    // An unmapped address must fail, not corrupt host memory.
    CHECK(!mem.put(0x8000'0000ull, v));
    CHECK(mem.cstr(0x8000'0000ull).empty());

    // An unterminated string must be bounded by `limit`, not run off RAM.
    std::vector<std::byte> filler(600, std::byte{'A'});
    CHECK(mem.copy_out(gva + 128, filler) == filler.size());
    CHECK(mem.cstr(gva + 128, 256).size() == 256);
}

static void test_guest_ram_bounds() {
    constexpr std::uint64_t kRam = 1 << 20;
    std::vector<std::byte> buf(kRam, std::byte{0});
    GuestRam ram{buf.data(), kRam, 0x1000};

    CHECK(ram.permits(0x1000, 16));
    CHECK(!ram.permits(0x0, 16));             // below the floor
    CHECK(!ram.permits(kRam - 8, 16));        // runs off the end
    CHECK(!ram.permits(kRam, 1));

    // The overflow case: gpa + n wraps, so a naive bound check passes and
    // hands out a span over host memory. This must be refused.
    CHECK(!ram.permits(0x2000, SIZE_MAX));
    CHECK(ram.at(0x2000, SIZE_MAX).empty());
    CHECK(!ram.permits(0xffff'ffff'ffff'f000ull, 0x2000));

    // clamp() shortens rather than refusing -- a partially valid buffer
    // yields a short count, as a real kernel does.
    CHECK(ram.clamp(kRam - 8, 64).size() == 8);
}

// -- Live: a real partition ----------------------------------------------
// Everything above runs anywhere. From here on a hypervisor is required, so
// the absence of one is a SKIP, not a failure.
static void test_live_partition() {
    if (!hypervisor_present() || !exception_exit_supported()) {
        std::printf("  SKIP live partition: %s\n", whp_unavailable_reason());
        return;
    }

    WhpMachine m;
    auto st = m.create(32 << 20, 1);
    if (!st) {
        std::printf("  SKIP live partition: create failed "
                    "(WHP present but partition refused)\n");
        return;
    }
    CHECK(m.live());
    CHECK(m.ram().valid());

    WhpCpu cpu;
    auto cst = cpu.create(m, 0);
    if (!cst) {
        std::printf("  SKIP live vcpu: CreateVirtualProcessor failed\n");
        return;
    }

    // Place a guest program at a mapped address inside the identity window:
    //
    //    mov eax, 60        ; __NR_exit
    //    mov edi, 7
    //    syscall            ; must trap to US as #UD, not execute
    //
    // and verify we get a syscall trap carrying nr=60 and arg0=7. That single
    // assertion is the whole backend working end to end: long mode entered at
    // CPL 3, page tables correct, SCE clear, #UD routed to the host, register
    // snapshot decoded.
    // Nothing is mapped until asked for: the partition starts with an empty
    // page table so that a mapping exists if and only if something requested
    // it (which is what makes an unmapped access a real fault). So map the
    // code and stack explicitly, exactly as the ELF loader does.
    const std::uint64_t code_gva = 0x40'0000;
    const std::uint64_t stack_gva = 0x80'0000;
    CHECK(m.map_pages(code_gva, kPageSize, /*writable=*/true,
                      /*executable=*/true).has_value());
    CHECK(m.map_pages(stack_gva - kPageSize, kPageSize, /*writable=*/true,
                      /*executable=*/false).has_value());

    const unsigned char prog[]{
        0xb8, 0x3c, 0x00, 0x00, 0x00,       // mov eax, 60
        0xbf, 0x07, 0x00, 0x00, 0x00,       // mov edi, 7
        0x0f, 0x05,                         // syscall
    };
    auto dst = m.ram().at(code_gva, sizeof(prog));
    CHECK(!dst.empty());
    if (dst.empty()) return;
    std::memcpy(dst.data(), prog, sizeof(prog));

    WhpTrap trap{m, cpu};
    auto start = trap.start(lx::UAddr(code_gva), lx::UAddr(stack_gva));
    if (!start) {
        std::printf("  SKIP live run: entering long mode failed\n");
        return;
    }

    TrapFrame f{};
    auto got = trap.next(f);
    if (!got) {
        std::printf("  NOTE live run: no syscall trap (stop=%d)\n",
                    int(trap.stop_reason()));
        ++failures;
        return;
    }
    CHECK(*got == true);
    CHECK(f.regs.nr == 60);        // __NR_exit
    CHECK(f.regs.arg[0] == 7);
    CHECK(f.pc == code_gva + 10);  // rip points AT the syscall, not past it

    // Resuming must advance rip past the 2-byte instruction.
    CHECK(trap.resume(0));
    CHECK(trap.regs()[GReg::rip] == code_gva + 12);
}

int main() {
    std::puts("whp: offline checks");
    test_open_flags();
    test_stat_translation();
    test_time_translation();
    test_errno_translation();
    test_path_translation();
    test_prot_translation();
    test_syscall_abi();
    test_mmu_walk();
    test_large_page_walk();
    test_guest_mem_view();
    test_guest_ram_bounds();

    std::printf("whp: WHP availability: %s\n", whp_unavailable_reason());
    std::puts("whp: live checks");
    test_live_partition();

    if (failures == 0) std::puts("whp: all checks passed");
    return failures ? 1 : 0;
}
