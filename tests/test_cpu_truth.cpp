// What the guest BELIEVES about the CPU must be true of the CPU it runs on.
//
// THE GAP THIS CLOSES. The differential conformance suite compares syscall
// results against a live kernel, which is the right oracle for almost
// everything -- and is structurally blind to this bug class.
//
// `gpg --import` died with SIGILL on a Snapdragon. No syscall returned a wrong
// value: /proc/cpuinfo returned a perfectly well-formed string. It just said
// the CPU had sha3 and sha512, because the arm64 feature line was hardcoded
// from an Apple M-series chip. libgcrypt read it, selected a SHA3 code path,
// and executed instructions the silicon does not implement. The damage was a
// CPU fault, not a bad syscall return, so a differ comparing observations
// would have seen two identical, equally wrong answers.
//
// A golden cannot express it either: the correct feature list is different on
// every machine, so there is nothing to record. What is constant is the
// RELATIONSHIP -- the guest executes natively, so anything it is told about
// the CPU has to be true of the host CPU.
//
// Hence an invariant test, checked against the live host rather than a
// recording:
//
//     features(guest) is a SUBSET of features(host)
//
// Claiming FEWER features than the host is safe (a program takes a slower
// path). Claiming MORE is a crash waiting for the right input.
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/kernel/machine.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>
#include <string>

using namespace lx;

namespace {

#if defined(__linux__)   // the helpers serve the Linux-host oracle only
std::string bytes_to_string(const std::vector<std::byte>& b) {
    std::string s;
    s.reserve(b.size());
    for (auto x : b) s.push_back(static_cast<char>(x));
    return s;
}

// The space-separated token set on the single line starting with `key`.
std::set<std::string> features_from(const std::string& text,
                                    const std::string& key) {
    std::set<std::string> out;
    std::istringstream in{text};
    for (std::string line; std::getline(in, line);) {
        if (line.rfind(key, 0) != 0) continue;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::istringstream toks{line.substr(colon + 1)};
        for (std::string t; toks >> t;) out.insert(t);
        break;                    // the first processor block is enough
    }
    return out;
}

std::string slurp(const char* path) {
    std::ifstream in{path};
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}
#endif

} // namespace

int main() {
#if !defined(__linux__)
    std::puts("cpu_truth: skipped (needs a Linux host to be the oracle)");
    return 0;
#else
    // arm64 spells it "Features", x86-64 spells it "flags". Only arm64 had
    // the hardcoded list, but the invariant is written for whichever this
    // host uses so the test is meaningful on both.
    const std::string host = slurp("/proc/cpuinfo");
    if (host.empty()) {
        std::puts("cpu_truth: skipped (no /proc/cpuinfo on this host)");
        return 0;
    }
#if defined(__aarch64__)
    const char* key = "Features";
#else
    const char* key = "flags";
#endif

    const auto host_set = features_from(host, key);
    if (host_set.empty()) {
        std::printf("cpu_truth: skipped (host /proc/cpuinfo has no '%s' line)\n",
                    key);
        return 0;
    }

    // Build the guest's view exactly as the runtime does.
    kernel::ProcessTable procs;
    kernel::ProcInfo init;
    init.pid = 1;
    init.cmdline = "/init";
    procs.upsert(init);

    static kernel::MachineSpec mach;      // the DEFAULTS, deliberately
    kernel::FileNamespace files;
    files.mount_virtual("/proc", vfs::make_procfs(procs, mach));

    auto ci = files.produce("/proc/cpuinfo");
    assert(ci.has_value() && "the guest must have a /proc/cpuinfo");
    const auto guest_set = features_from(bytes_to_string(ci->bytes), key);

    // THE INVARIANT. Every feature the guest advertises must be one the host
    // really has. A default MachineSpec is used on purpose: main.cpp fills
    // the real list from the host at startup, so the DEFAULT is what a host
    // we failed to read falls back to, and it must be safe on its own.
    int extra = 0;
    for (const auto& f : guest_set) {
        if (host_set.count(f)) continue;
        std::printf("cpu_truth: guest advertises '%s', host does NOT have it\n",
                    f.c_str());
        ++extra;
    }

    if (extra) {
        std::printf("cpu_truth: FAIL -- %d feature(s) advertised but absent. "
                    "The guest runs NATIVELY on this CPU, so a program that "
                    "believes this line will execute an instruction the "
                    "silicon lacks and take SIGILL (this is how gpg --import "
                    "died on a Snapdragon: a hardcoded Apple M-series list "
                    "promised sha3/sha512).\n", extra);
        return 1;
    }

    std::printf("cpu_truth: every CPU feature the guest advertises (%zu) is "
                "really present on the host (%zu) -- belief is a subset of "
                "reality\n", guest_set.size(), host_set.size());

    // -- the arm64 line, checked on EVERY host --------------------------
    //
    // The bug was in the arm64 "Features" string, and on an x86-64 host the
    // check above never looks at it: this host reports "flags", so a wrong
    // arm64 default would sail through CI and only crash on a phone. That
    // is the same blind spot that let the bug ship.
    //
    // So pin the DEFAULT arm64 list directly. It cannot be compared against
    // this host's CPU -- different architecture -- but it can be held to the
    // rule that makes it safe: the fallback used when we cannot read the
    // host must be the ARMv8.0 baseline that every arm64 Linux CPU has, and
    // must not name an optional extension. Optional features are exactly
    // what made libgcrypt pick an instruction the silicon lacked.
    {
        static kernel::MachineSpec arm;
        arm.machine_arch = "aarch64";
        arm.ncpu = 1;
        kernel::ProcessTable aprocs;
        aprocs.upsert(init);
        kernel::FileNamespace afiles;
        afiles.mount_virtual("/proc", vfs::make_procfs(aprocs, arm));

        auto aci = afiles.produce("/proc/cpuinfo");
        assert(aci.has_value());
        const auto arm_set =
            features_from(bytes_to_string(aci->bytes), "Features");

        // Mandatory in ARMv8.0, so always safe to advertise.
        const std::set<std::string> baseline{
            "fp", "asimd", "evtstrm", "aes", "pmull", "sha1", "sha2", "crc32"};

        int unsafe = 0;
        for (const auto& f : arm_set) {
            if (baseline.count(f)) continue;
            std::printf("cpu_truth: the arm64 DEFAULT advertises optional "
                        "feature '%s'\n", f.c_str());
            ++unsafe;
        }
        if (unsafe) {
            std::printf("cpu_truth: FAIL -- the arm64 fallback names %d "
                        "optional extension(s). It is used when the host's "
                        "cpuinfo cannot be read, so it must assume nothing "
                        "beyond the ARMv8.0 baseline: a guest told it has "
                        "sha3/sha512 will execute those instructions and take "
                        "SIGILL on a CPU without them.\n", unsafe);
            return 1;
        }
        std::printf("cpu_truth: the arm64 fallback (%zu features) stays "
                    "within the ARMv8.0 baseline\n", arm_set.size());
    }

    return 0;
#endif
}
