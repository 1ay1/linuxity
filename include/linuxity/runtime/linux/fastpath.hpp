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

// The syscalls the blob answers.
[[nodiscard]] inline bool handled(abi::Sysno sc) noexcept {
    using S = abi::Sysno;
    switch (sc) {
        case S::stat: case S::lstat: case S::newfstatat: case S::statx: case S::fstat:
        case S::readlink: case S::readlinkat:
        case S::getxattr: case S::lgetxattr: case S::listxattr: case S::llistxattr:
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
// x86-64 site:   b8 NN NN NN NN    mov $nr, %eax
//                0f 05             syscall
// becomes        e9 rel32          jmp stub        (5 bytes, over the mov)
//                0f 05             (left, unreachable except by a jump into it)
// The patch writes 8 aligned bytes in one ptrace POKE, so a thread that
// later runs it sees all of it or none of it.
//
// aarch64 site:  svc #0          (one 4-byte word, always atomic)
// becomes        b stub
//
// The stub saves what the call clobbers, calls the blob's common entry, and
// on fallback runs the original instruction(s) there, so the real syscall's
// pc (what the trap and the guest's own signal frames see) is the stub's.

#if defined(__x86_64__)
inline constexpr std::size_t kSiteLen = 7;   // mov + syscall
[[nodiscard]] inline bool site_ok(const unsigned char* b, std::uint32_t nr) {
    std::uint32_t imm;
    std::memcpy(&imm, b + 1, 4);
    return b[0] == 0xb8 && imm == nr && b[5] == 0x0f && b[6] == 0x05;
}
// Stub for one site. `ret` is the address after the site's syscall.
[[nodiscard]] inline std::vector<unsigned char> make_stub(std::uint64_t stub, std::uint64_t common,
                                                         std::uint32_t nr, std::uint64_t ret) {
    std::vector<unsigned char> s;
    auto u32 = [&](std::uint32_t v) { for (int i = 0; i < 4; ++i) s.push_back(static_cast<unsigned char>(v >> (8 * i))); };
    auto u64 = [&](std::uint64_t v) { for (int i = 0; i < 8; ++i) s.push_back(static_cast<unsigned char>(v >> (8 * i))); };
    // lea -128(%rsp),%rsp            skip the red zone
    s.insert(s.end(), {0x48, 0x8d, 0x64, 0x24, 0x80});
    // mov $nr,%eax
    s.push_back(0xb8); u32(nr);
    // call *common(%rip)
    s.insert(s.end(), {0xff, 0x15}); u32(0);   // patched below
    const std::size_t call_disp = s.size() - 4;
    // lea 128(%rsp),%rsp  (lea keeps the flags)
    s.insert(s.end(), {0x48, 0x8d, 0xa4, 0x24}); u32(128);
    // test %ecx,%ecx ; jz fallback   -- test clobbers flags; restore below
    // The blob returns rcx=1 when it answered. rcx and r11 are clobbered by
    // a real syscall anyway.
    s.insert(s.end(), {0x85, 0xc9});
    s.insert(s.end(), {0x74, 0x00});           // jz rel8, patched below
    const std::size_t jz_disp = s.size() - 1;
    // jmp *ret(%rip)
    s.insert(s.end(), {0xff, 0x25}); u32(0);
    const std::size_t ret_disp = s.size() - 4;
    // fallback: syscall ; jmp *ret(%rip)
    const std::size_t fb = s.size();
    s.insert(s.end(), {0x0f, 0x05});
    s.insert(s.end(), {0xff, 0x25}); u32(0);
    const std::size_t ret_disp2 = s.size() - 4;
    while (s.size() % 8) s.push_back(0xcc);
    const std::size_t lit_common = s.size(); u64(common);
    const std::size_t lit_ret = s.size(); u64(ret);
    auto set32 = [&](std::size_t at, std::int64_t v) {
        const auto x = static_cast<std::uint32_t>(static_cast<std::int32_t>(v));
        for (int i = 0; i < 4; ++i) s[at + static_cast<std::size_t>(i)] = static_cast<unsigned char>(x >> (8 * i));
    };
    set32(call_disp, static_cast<std::int64_t>(lit_common) - static_cast<std::int64_t>(call_disp + 4));
    set32(ret_disp, static_cast<std::int64_t>(lit_ret) - static_cast<std::int64_t>(ret_disp + 4));
    set32(ret_disp2, static_cast<std::int64_t>(lit_ret) - static_cast<std::int64_t>(ret_disp2 + 4));
    s[jz_disp] = static_cast<unsigned char>(fb - (jz_disp + 1));
    (void)stub;
    return s;
}
// The fallback's `syscall` sits at this offset in every stub.
inline std::size_t stub_syscall_off() {
    static const std::size_t off = [] {
        const auto s = make_stub(0, 0, 0, 0);
        for (std::size_t i = 0; i + 1 < s.size(); ++i)
            if (s[i] == 0x0f && s[i + 1] == 0x05) return i;
        return std::size_t{0};
    }();
    return off;
}
#elif defined(__aarch64__)
inline constexpr std::size_t kSiteLen = 4;   // svc #0
[[nodiscard]] inline bool site_ok(const unsigned char* b, std::uint32_t) {
    std::uint32_t w;
    std::memcpy(&w, b, 4);
    return w == 0xd4000001u;   // svc #0
}
[[nodiscard]] inline std::vector<unsigned char> make_stub(std::uint64_t stub, std::uint64_t common,
                                                         std::uint32_t, std::uint64_t ret) {
    std::vector<std::uint32_t> w;
    // stp x16, x30, [sp, #-16]!
    w.push_back(0xa9bf7bf0u);
    // ldr x16, lit_common
    const std::size_t ldr_common = w.size(); w.push_back(0x58000010u);
    // blr x16
    w.push_back(0xd63f0200u);
    // cbz x16, fallback   (x16 = 0 means "run the real call")
    const std::size_t cbz = w.size(); w.push_back(0xb4000010u);
    // ldp x16, x30, [sp], #16
    w.push_back(0xa8c17bf0u);
    // b ret
    const std::size_t b1 = w.size(); w.push_back(0x14000000u);
    // fallback: ldp x16, x30, [sp], #16 ; svc #0 ; b ret
    const std::size_t fb = w.size();
    w.push_back(0xa8c17bf0u);
    w.push_back(0xd4000001u);
    const std::size_t b2 = w.size(); w.push_back(0x14000000u);
    if (w.size() % 2) w.push_back(0xd503201fu);   // nop, align the literal
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
    w[b1] |= imm26(b1, ret);
    w[b2] |= imm26(b2, ret);
    std::vector<unsigned char> s(w.size() * 4);
    std::memcpy(s.data(), w.data(), s.size());
    return s;
}
inline std::size_t stub_syscall_off() { return 7 * 4; }
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
