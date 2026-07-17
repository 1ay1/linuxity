// Resource policy: the pure-logic half of the bound-the-guest layer — human
// size parsing and, crucially, the DERIVATION of the advertised machine
// (MachineSpec) from the enforced policy (ResourceSpec). The enforcement half
// (cgroup v2 / setrlimit) needs a live host and privilege state, so it is
// proven by hand under `--memory`/`--cpus`; here we lock down the invariant
// that "belief == the number you asked to be bounded to".
#include "linuxity/kernel/resources.hpp"

#include <cassert>
#include <cstdio>

using namespace lx::kernel;

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("resources: FAIL %s\n", msg); ++fails; } } while (0)

int main() {
    // -- parse_bytes: binary suffixes, bare numbers, malformed --------------
    CHECK(parse_bytes("512M") == (std::uint64_t{512} << 20), "512M");
    CHECK(parse_bytes("2G")   == (std::uint64_t{2}   << 30), "2G");
    CHECK(parse_bytes("1500k")== (std::uint64_t{1500}<< 10), "1500k");
    CHECK(parse_bytes("1073741824") == 1073741824ull, "bare bytes");
    CHECK(parse_bytes("1T")   == (std::uint64_t{1}   << 40), "1T");
    CHECK(!parse_bytes("").has_value(),      "empty rejected");
    CHECK(!parse_bytes("M").has_value(),     "lone suffix rejected");
    CHECK(!parse_bytes("12x").has_value(),   "bad suffix rejected");
    CHECK(!parse_bytes("1.5G").has_value(),  "non-integer rejected");

    // -- advertise: belief derived from enforced reality --------------------
    MachineSpec base;                // defaults: 2 GiB, ncpu default
    base.ncpu = 16;
    base.mem_total = std::uint64_t{8192} << 20;   // host says 8 GiB / 16 CPU

    {   // memory bound folds straight into MemTotal
        ResourceSpec r; r.mem_max = std::uint64_t{512} << 20;
        auto m = r.advertise(base);
        CHECK(m.mem_total == (std::uint64_t{512} << 20), "mem_max -> mem_total");
        CHECK(m.ncpu == 16, "cpus untouched when only mem set");
    }
    {   // integer cpus -> exact ncpu
        ResourceSpec r; r.cpus = 2.0;
        auto m = r.advertise(base);
        CHECK(m.ncpu == 2, "cpus=2 -> ncpu 2");
    }
    {   // fractional cpus round UP (so a runtime can thread + be time-sliced)
        ResourceSpec r; r.cpus = 1.5;
        auto m = r.advertise(base);
        CHECK(m.ncpu == 2, "cpus=1.5 -> ncpu 2 (ceil)");
    }
    {   // sub-core still advertises at least 1 CPU
        ResourceSpec r; r.cpus = 0.25;
        auto m = r.advertise(base);
        CHECK(m.ncpu == 1, "cpus=0.25 -> ncpu 1 (floor 1)");
    }
    {   // both bounds together
        ResourceSpec r; r.cpus = 4.0; r.mem_max = std::uint64_t{1} << 30;
        auto m = r.advertise(base);
        CHECK(m.ncpu == 4 && m.mem_total == (std::uint64_t{1} << 30),
              "cpus+mem both advertised");
    }
    {   // empty spec leaves the host machine untouched
        ResourceSpec r;
        auto m = r.advertise(base);
        CHECK(m.ncpu == 16 && m.mem_total == (std::uint64_t{8192} << 20),
              "empty spec keeps host capacity");
        CHECK(!r.any(), "empty spec reports any()==false");
    }

    // -- cpu.max quota derivation (100ms period) ----------------------------
    {   ResourceSpec r; r.cpus = 1.0;
        CHECK(r.cpu_quota_us() == 100'000, "1.0 core -> 100000us/100000us");
    }
    {   ResourceSpec r; r.cpus = 0.5;
        CHECK(r.cpu_quota_us() == 50'000, "0.5 core -> 50000us");
    }
    {   ResourceSpec r; r.cpus = 2.5;
        CHECK(r.cpu_quota_us() == 250'000, "2.5 cores -> 250000us");
    }

    if (fails == 0)
        std::puts("resources: parse_bytes + advertise (belief==enforced reality) OK");
    return fails ? 1 : 0;
}
