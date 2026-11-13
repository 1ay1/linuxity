// linuxity/runtime/darwin/exec.hpp
//
// execve(2) for the HVF backend: load a program the way the Linux kernel does.
//
// The kernel's exec contract for a dynamic program is NOT "run ld.so with
// the program as an argument". It maps BOTH the program and its PT_INTERP
// loader, enters the loader, and tells it where the program already is via
// the auxiliary vector (AT_PHDR/AT_ENTRY describe the PROGRAM, AT_BASE is
// the loader's load address). ld.so then sees /proc/self/exe, argv[0] and
// AT_EXECFN exactly as on a real system -- which matters: busybox and
// coreutils multi-call binaries dispatch on argv[0], and `ld.so prog` would
// shift argv by one.
//
// Doing it properly also gives #! scripts for free: the kernel rule is
// "interp [arg] script args...", resolved recursively (bounded).
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/abi/result.hpp"
#include "linuxity/loader/elf.hpp"
#include "linuxity/loader/interp.hpp"
#include "linuxity/runtime/darwin/load.hpp"
#include "linuxity/runtime/darwin/vdso.hpp"
#include "linuxity/runtime/darwin/vm.hpp"

#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace lx::runtime {

// Where things go in guest memory. Programs and loaders are both PIEs on
// every modern distro, so their placement is OUR choice: the program above
// any fixed-address (ET_EXEC) image, the loader a fixed distance above it,
// far enough that the program's brk heap can grow.
struct ExecLayout {
    static constexpr std::uint64_t interp_gap = 0x1000'0000;     // 256 MiB
    [[nodiscard]] static constexpr std::uint64_t program_base(std::uint64_t) noexcept {
        return HvfLayout::program_base;
    }
    [[nodiscard]] static constexpr std::uint64_t interp_base(std::uint64_t ram) noexcept {
        return program_base(ram) + interp_gap;
    }
};

// Translate a guest path to the host path it names.
using ResolvePath = std::function<std::string(const std::string& guest_path)>;

struct ExecResult {
    std::uint64_t entry{};       // where the vCPU starts (the loader, if any)
    std::uint64_t sp{};          // initial stack pointer
    std::uint64_t brk_base{};    // where the program's heap begins
    std::vector<HvfImage::Segment> segments;   // for the VMA map
    // For /proc/<pid>/maps: the first `program_segments` of `segments` are
    // the program's (guest path `program`), the rest the loader's.
    std::size_t program_segments{0};
    std::string program, interp;
    std::string environ;        // envp, NUL-separated, as /proc/<pid>/environ
    std::string auxv;           // the aux vector's bytes, as /proc/<pid>/auxv
    std::string cmdline;        // argv, each NUL-terminated, as /proc/<pid>/cmdline
};

// Load `path` into a FRESH address space (execve replaces the image). Handles
// static programs, dynamic programs (with PT_INTERP), and #! scripts.
[[nodiscard]] inline Result<ExecResult> hvf_exec(HvfMachine& vm,
                                                 const ResolvePath& resolve,
                                                 std::string guest_path,
                                                 std::vector<std::string> argv,
                                                 const std::vector<std::string>& envp) {
    // -- #! scripts: rewrite to "interp [arg] script args...", up to 4 deep
    //    (the kernel's BINPRM_MAX_RECURSION).
    for (int depth = 0;; ++depth) {
        if (depth == 4) return err<ExecResult>(Errno::eloop);
        const std::string host = resolve(guest_path);
        if (host.empty()) return err<ExecResult>(Errno::enoent);
        loader::Shebang sh = loader::read_shebang(host);
        if (sh.interp.empty()) break;
        std::vector<std::string> next{sh.interp};
        if (!sh.arg.empty()) next.push_back(sh.arg);
        next.push_back(guest_path);
        for (std::size_t i = 1; i < argv.size(); ++i) next.push_back(argv[i]);
        argv = std::move(next);
        guest_path = sh.interp;
    }

    const std::string prog_host = resolve(guest_path);
    auto prog = hvf_load_elf(vm, prog_host, ExecLayout::program_base(vm.mem_size()));
    if (!prog) return err<ExecResult>(prog.error());

    ExecResult out;
    out.brk_base = prog->image_end;
    out.segments = prog->segments;
    out.program_segments = out.segments.size();
    out.program = guest_path;
    for (const auto& e : envp) { out.environ += e; out.environ.push_back('\0'); }
    for (const auto& a : argv) { out.cmdline += a; out.cmdline.push_back('\0'); }
    std::uint64_t entry = prog->entry;
    std::uint64_t at_base = 0;

    // -- PT_INTERP: map the loader too, and enter IT. The aux vector still
    //    describes the PROGRAM (AT_PHDR/AT_ENTRY), plus AT_BASE = loader.
    if (std::string interp = loader::read_elf_interp(prog_host); !interp.empty()) {
        const std::string ih = resolve(interp);
        if (ih.empty()) return err<ExecResult>(Errno::enoent);
        auto ld = hvf_load_elf(vm, ih, ExecLayout::interp_base(vm.mem_size()));
        if (!ld) return err<ExecResult>(ld.error());
        entry = ld->entry;
        at_base = ld->load_bias;
        out.interp = interp;
        out.segments.insert(out.segments.end(), ld->segments.begin(),
                            ld->segments.end());
    }

    auto sp = hvf_build_stack(vm, *prog, argv, envp, at_base, guest_path,
                              vdso::install(vm), &out.auxv);
    if (!sp) return err<ExecResult>(sp.error());
    out.entry = entry;
    out.sp = *sp;
    return ok(std::move(out));
}

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
