// linuxity/runtime/linux/fastpath.hpp
//
// The supervisor side of the in-guest fast path: puts the blob into a guest
// process, patches its hot syscall sites, and keeps the shared table in step
// with the dispatcher's state.
//
// WHY. A ptrace stop costs ~3.4us on an x86 laptop and 13-26us on a Pixel
// 6a; the stat it services costs 0.3-1us. Measured alternatives:
//   * seccomp RET_TRAP + an in-process SIGSYS handler: 0.9us, but a traced
//     task's every signal stops in the tracer first, so under ptrace it is
//     back to 3.4us.
//   * SIGSYS + a shared-memory request to the supervisor: 3.7us (x86) and
//     18-41us (phone) with futex wakeups; fast only when both sides spin.
//   * doing the query inside the guest (the blob, here): an overlay stat is
//     ~1us on x86 and ~1.9us on the phone, with no stop at all.
// So the guest answers what it safely can, the way gVisor's systrap and
// lazypoline do: the first few times a syscall site traps, the supervisor
// rewrites it into a call to the blob.
//
// SAFETY. The blob only answers read-only path queries, and only when the
// table proves the dispatcher would give the same answer; otherwise the
// stub runs the original instruction and the call traps exactly as before.
// Patching is skipped for anything it can't do atomically and exactly (see
// patch_site), and every failure leaves the site as it was.
#pragma once

#include "linuxity/runtime/linux/fastpath_abi.h"
#include "linuxity/runtime/linux/fastpath_table.hpp"

#include <sys/mman.h>
#include <sys/uio.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Linked in by the linuxity binary (CMakeLists.txt); weak so that a test
// binary without it builds and simply runs with the fast path off.
extern "C" __attribute__((weak)) const unsigned char lx_fastpath_blob[];
extern "C" __attribute__((weak)) const unsigned char lx_fastpath_blob_end[];

namespace lx::runtime::fastpath {

// The syscalls the blob answers, or does natively in the guest. A site that
// trapped on one of these gets patched.
[[nodiscard]] inline bool handled(abi::Sysno sc) noexcept {
    using S = abi::Sysno;
    switch (sc) {
        case S::stat: case S::lstat: case S::newfstatat: case S::statx: case S::fstat:
        case S::readlink: case S::readlinkat:
        case S::getxattr: case S::lgetxattr: case S::listxattr: case S::llistxattr:
        case S::open: case S::openat: case S::close:
        case S::dup: case S::dup2: case S::dup3: case S::fcntl:
        case S::getdents64: case S::lseek:
        case S::access: case S::faccessat: case S::faccessat2:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] inline std::span<const unsigned char> blob() {
    if (!lx_fastpath_blob || !lx_fastpath_blob_end) return {};
    return {lx_fastpath_blob, static_cast<std::size_t>(lx_fastpath_blob_end - lx_fastpath_blob)};
}

// What a mapped region looks like in one process.
struct Region {
    std::uint64_t base{0};           // 0: not mapped (yet)
    bool failed{false};              // tried and gave up: never again
    bool verified{false};            // base checked to be mapped in this mm
    bool owner{false};               // its fd map describes this process's fds
    bool shared{false};              // shares memory with parent_tg (vfork)
    ::pid_t parent_tg{0};            // the process it was copied from at fork
    int privileged{-1};              // last value written to the proc page
    std::uint32_t ev_seen{0};        // stats.ev[slot] when last drained
    std::uint32_t calls{0};          // handled calls trapped before a region exists
    // per fd: the blob's event counter when the dispatcher last (un)bound it
    std::unordered_map<int, std::uint32_t> fd_mark;
    // stub pages near patched code, by 64K-aligned window
    std::map<std::uint64_t, std::uint64_t> near;   // window -> page base
    std::map<std::uint64_t, std::uint32_t> used;   // page base -> slots used
    std::unordered_set<std::uint64_t> patched;     // syscall-site pcs (or ones to skip)
    std::unordered_set<std::uint64_t> near_rx;     // stub pages already made r-x
    std::unordered_map<std::uint64_t, std::uint32_t> hits;
};

// The blob's layout facts, read from its header.
struct Layout {
    std::uint32_t common{0}, guard_start{0}, guard_end{0}, fault_ret{0};
    bool ok{false};
};
inline const Layout& layout() {
    static const Layout l = [] {
        Layout l;
        const auto b = blob();
        if (b.size() < sizeof(lx_fp_header) || b.size() > LX_FP_CODE_MAX) return l;
        lx_fp_header h;
        std::memcpy(&h, b.data(), sizeof h);
        if (h.magic != LX_FP_MAGIC || h.version != LX_FP_VERSION) return l;
        l.common = h.common;
        l.guard_start = h.guard_start;
        l.guard_end = h.guard_end;
        l.fault_ret = h.fault_ret;
        l.ok = h.common < b.size() && h.guard_end <= b.size();
        return l;
    }();
    return l;
}

// -- per-arch stub and patch encodings ---------------------------------------
//
// A site is the instruction right BEFORE a syscall instruction; that one
// instruction is replaced by a jump to a stub, and the syscall instruction
// itself is left alone. The stub runs the moved instruction, calls the
// blob, and then jumps back: past the syscall if the blob answered, or TO
// the original syscall if it didn't. So a call the blob leaves alone runs
// at its own address, which matters: glibc's pthread_cancel looks at the
// pc of a blocked call to decide whether to act now, and the trap and any
// signal frame see the pc they always did. A branch straight to the
// syscall instruction also still works, since it was never touched.
//
// x86-64: the moved instruction is 5 bytes, one of
//    b8 imm32         mov $nr, %eax          (glibc's plain wrappers)
//    4c 89 5c 24 08   mov %r11, 0x8(%rsp)    (__syscall_cancel_arch: open,
//                                             close, read... nr in eax)
//    4c 8b 4c 24 08   mov 0x8(%rsp), %r9     (syscall(2))
// replaced by `jmp rel32`, written as part of one aligned 8-byte word when
// other threads could be running it.
// aarch64: `mov x8, #nr` or `mov x8, xN` before `svc #0`, replaced by `b`.

#if defined(__x86_64__)
inline constexpr std::size_t kSiteLen = 7;   // moved instruction + syscall
inline constexpr std::size_t kMoveLen = 5;
// `nr` is what the trap saw in rax. A `mov $imm,%eax` that doesn't load it
// isn't what ran before this syscall.
[[nodiscard]] inline bool site_ok(const unsigned char* b, std::uint32_t nr) {
    if (b[5] != 0x0f || b[6] != 0x05) return false;
    if (b[0] == 0xb8) {
        std::uint32_t imm;
        std::memcpy(&imm, b + 1, 4);
        return imm == nr;
    }
    static constexpr unsigned char kR11[] = {0x4c, 0x89, 0x5c, 0x24, 0x08};
    static constexpr unsigned char kR9[] = {0x4c, 0x8b, 0x4c, 0x24, 0x08};
    return std::memcmp(b, kR11, 5) == 0 || std::memcmp(b, kR9, 5) == 0;
}
// Stub for the site at `site`, whose first 5 bytes were `moved`.
[[nodiscard]] inline std::vector<unsigned char> make_stub(std::uint64_t stub, std::uint64_t common,
                                                         const unsigned char* moved, std::uint64_t site) {
    std::vector<unsigned char> s;
    auto u32 = [&](std::uint32_t v) { for (int i = 0; i < 4; ++i) s.push_back(static_cast<unsigned char>(v >> (8 * i))); };
    auto u64 = [&](std::uint64_t v) { for (int i = 0; i < 8; ++i) s.push_back(static_cast<unsigned char>(v >> (8 * i))); };
    // the moved instruction, with the stack as the site had it
    s.insert(s.end(), moved, moved + kMoveLen);
    // lea -128(%rsp),%rsp            skip the red zone
    s.insert(s.end(), {0x48, 0x8d, 0x64, 0x24, 0x80});
    // call *common(%rip)             eax = nr
    s.insert(s.end(), {0xff, 0x15}); u32(0);
    const std::size_t call_disp = s.size() - 4;
    // lea 128(%rsp),%rsp
    s.insert(s.end(), {0x48, 0x8d, 0xa4, 0x24}); u32(128);
    // the blob sets rcx = 1 when it answered (a syscall clobbers rcx anyway)
    s.insert(s.end(), {0x85, 0xc9});             // test %ecx,%ecx
    s.insert(s.end(), {0x74, 0x00});             // jz fallback
    const std::size_t jz_disp = s.size() - 1;
    s.insert(s.end(), {0xff, 0x25}); u32(0);     // jmp *after(%rip)
    const std::size_t after_disp = s.size() - 4;
    const std::size_t fb = s.size();
    s.insert(s.end(), {0xff, 0x25}); u32(0);     // fallback: jmp *orig(%rip)
    const std::size_t orig_disp = s.size() - 4;
    while (s.size() % 8) s.push_back(0xcc);
    const std::size_t lit_common = s.size(); u64(common);
    const std::size_t lit_after = s.size(); u64(site + kSiteLen);
    const std::size_t lit_orig = s.size(); u64(site + kMoveLen);
    auto set32 = [&](std::size_t at, std::int64_t v) {
        const auto x = static_cast<std::uint32_t>(static_cast<std::int32_t>(v));
        for (int i = 0; i < 4; ++i) s[at + static_cast<std::size_t>(i)] = static_cast<unsigned char>(x >> (8 * i));
    };
    set32(call_disp, static_cast<std::int64_t>(lit_common) - static_cast<std::int64_t>(call_disp + 4));
    set32(after_disp, static_cast<std::int64_t>(lit_after) - static_cast<std::int64_t>(after_disp + 4));
    set32(orig_disp, static_cast<std::int64_t>(lit_orig) - static_cast<std::int64_t>(orig_disp + 4));
    s[jz_disp] = static_cast<unsigned char>(fb - (jz_disp + 1));
    (void)stub;
    return s;
}
// The jump that replaces the moved instruction.
[[nodiscard]] inline std::vector<unsigned char> make_jump(std::uint64_t site, std::uint64_t stub) {
    const std::int64_t rel = static_cast<std::int64_t>(stub) - static_cast<std::int64_t>(site + 5);
    std::vector<unsigned char> j{0xe9, 0, 0, 0, 0};
    const auto r32 = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));
    std::memcpy(j.data() + 1, &r32, 4);
    return j;
}
#elif defined(__aarch64__)
inline constexpr std::size_t kSiteLen = 8;   // moved instruction + svc
inline constexpr std::size_t kMoveLen = 4;
[[nodiscard]] inline bool site_ok(const unsigned char* b, std::uint32_t nr) {
    std::uint32_t mv, svc;
    std::memcpy(&mv, b, 4);
    std::memcpy(&svc, b + 4, 4);
    if (svc != 0xd4000001u) return false;               // svc #0
    if ((mv & 0x7fe0001fu) == 0x52800008u)              // movz x8|w8, #imm16
        return ((mv >> 5) & 0xffffu) == nr;
    return (mv & 0xffe0ffffu) == 0xaa0003e8u;           // mov x8, xN (orr x8, xzr, xN)
}
[[nodiscard]] inline std::vector<unsigned char> make_stub(std::uint64_t stub, std::uint64_t common,
                                                         const unsigned char* moved, std::uint64_t site) {
    std::vector<std::uint32_t> w;
    std::uint32_t mv;
    std::memcpy(&mv, moved, 4);
    w.push_back(mv);                                     // the moved mov to x8
    w.push_back(0xa9bf7bf0u);                            // stp x16, x30, [sp, #-16]!
    const std::size_t ldr_common = w.size(); w.push_back(0x58000010u);   // ldr x16, lit
    w.push_back(0xd63f0200u);                            // blr x16
    const std::size_t cbz = w.size(); w.push_back(0xb4000010u);          // cbz x16, fallback
    w.push_back(0xa8c17bf0u);                            // ldp x16, x30, [sp], #16
    const std::size_t b1 = w.size(); w.push_back(0x14000000u);          // b site+8
    const std::size_t fb = w.size();
    w.push_back(0xa8c17bf0u);                            // ldp x16, x30, [sp], #16
    const std::size_t b2 = w.size(); w.push_back(0x14000000u);          // b site+4 (the svc)
    if (w.size() % 2) w.push_back(0xd503201fu);          // nop, align the literal
    const std::size_t lit = w.size();
    w.push_back(static_cast<std::uint32_t>(common));
    w.push_back(static_cast<std::uint32_t>(common >> 32));
    auto imm19 = [](std::size_t from, std::size_t to) {
        return (static_cast<std::uint32_t>(static_cast<std::int64_t>(to) - static_cast<std::int64_t>(from)) & 0x7ffffu) << 5;
    };
    auto imm26 = [&](std::size_t from_word, std::uint64_t target) {
        const std::int64_t d = (static_cast<std::int64_t>(target) -
                                static_cast<std::int64_t>(stub + from_word * 4)) / 4;
        return static_cast<std::uint32_t>(d) & 0x3ffffffu;
    };
    w[ldr_common] |= imm19(ldr_common, lit);
    w[cbz] |= imm19(cbz, fb);
    w[b1] |= imm26(b1, site + kSiteLen);
    w[b2] |= imm26(b2, site + kMoveLen);
    std::vector<unsigned char> s(w.size() * 4);
    std::memcpy(s.data(), w.data(), s.size());
    return s;
}
[[nodiscard]] inline std::vector<unsigned char> make_jump(std::uint64_t site, std::uint64_t stub) {
    const std::int64_t rel = (static_cast<std::int64_t>(stub) - static_cast<std::int64_t>(site)) / 4;
    const std::uint32_t b = 0x14000000u | (static_cast<std::uint32_t>(rel) & 0x3ffffffu);
    std::vector<unsigned char> j(4);
    std::memcpy(j.data(), &b, 4);
    return j;
}
#endif

// Range check for the jump from a site to its stub.
[[nodiscard]] inline bool in_branch_range(std::uint64_t from, std::uint64_t to) {
    const std::int64_t d = static_cast<std::int64_t>(to) - static_cast<std::int64_t>(from);
#if defined(__x86_64__)
    return d > -0x7fff0000LL && d < 0x7fff0000LL;
#else
    return d > -0x7f00000LL && d < 0x7f00000LL;   // b: +-128MB
#endif
}

}  // namespace lx::runtime::fastpath
