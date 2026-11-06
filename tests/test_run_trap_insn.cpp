// A guest that executes a TRAP instruction must die, not spin forever.
//
// The attach-stop arm of the trap loop swallows SIGSTOP/SIGTRAP and resumes
// with signal 0. That is right for the initial stop of a newly attached task,
// but a SIGTRAP from a real trap instruction -- __builtin_trap(), a
// breakpoint, an assert that compiles down to brk -- must be delivered. Eat
// one and the guest re-executes the same instruction at the same pc forever:
// it never dies, never progresses, and the trace grows without bound (the bug
// filled 8 MB of log in a few seconds).
//
// The two are told apart by siginfo: a real trap reports si_code TRAP_BRKPT
// or TRAP_TRACE, the attach stop does not.
//
// The probe just traps. Native, that is death by SIGTRAP -- 128+5 = 133 as a
// shell-style status -- so the guest must report the same, promptly.
#include "guest_harness.hpp"
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"

#include <cstdio>

using namespace lx;

// The probe raises a genuine BREAKPOINT, not an undefined instruction.
// __builtin_trap() compiles to ud2 on x86-64, which is SIGILL and travels a
// different arm of the loop; int3 / brk #0 is what reports si_code
// TRAP_BRKPT and so exercises the swallowing bug.
static const char* kProbe =
    "#include <stdio.h>\n"
    "int main(void){\n"
    "  printf(\"alive\\n\");\n"
    "  fflush(stdout);\n"
    "#if defined(__x86_64__)\n"
    "  __asm__ __volatile__(\"int3\");\n"
    "#elif defined(__aarch64__)\n"
    "  __asm__ __volatile__(\"brk #0\");\n"
    "#else\n"
    "  __builtin_trap();\n"
    "#endif\n"
    "  return 0;\n"
    "}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_trap_insn: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("trapinsn", /*overlay=*/false, "",
                                        "/bin/trapinsn");
    if (!lxtest::compile_guest("run_trap_insn", tree, kProbe)) return 0;

    auto r = lxtest::run_guest(tree, [&](auto& k) {
        kernel::ProcInfo init;
        init.pid = 1;
        init.cmdline = tree.exec;
        k.procs().upsert(init);
    });
    lxtest::remove_tree(tree);

    if (!r) { std::puts("run_trap_insn: skipped (ptrace unavailable)"); return 0; }
    const int code = *r;

    // The guest must have DIED on the trap. Anything that looks like a normal
    // exit means the signal was swallowed -- and before the fix that was not
    // even reachable, because the guest span forever and the harness timed
    // out instead of returning at all.
    if (code != 128 + SIGTRAP && code != 128 + SIGILL) {
        std::printf("run_trap_insn: FAIL code=%d (expected %d SIGTRAP or %d "
                    "SIGILL; a clean exit means the trap-instruction signal "
                    "was swallowed and the guest was resumed with signal 0)\n",
                    code, 128 + SIGTRAP, 128 + SIGILL);
        return 1;
    }
    std::puts("run_trap_insn: a trap instruction kills the guest instead of "
              "looping forever on the same pc");
    return 0;
#endif
}
