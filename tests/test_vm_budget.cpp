// The tree-wide VM budget (runtime/darwin/proc.hpp): Hypervisor.framework
// allows a fixed number of VMs at once, and parked zygotes may only use what
// real processes leave free. A budget that leaks a reservation, or lets spares
// crowd out real forks, turns a deep process tree into fork failures -- which
// is what a 341-process tree did before it existed.
#include "linuxity/runtime/darwin/proc.hpp"

#include <cstdio>

using lx::runtime::PidSpace;

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("vm_budget: FAIL %s\n", msg); ++fails; } } while (0)

int main() {
    PidSpace pids;
    CHECK(pids.valid(), "a pid space");
    CHECK(pids.live_processes() == 1, "the root process is live");
    const int spare_cap = PidSpace::kMaxVms - PidSpace::kKeepFree;

    // spares fill exactly up to what the root leaves of the cap, no further
    int got = 0;
    while (got < PidSpace::kMaxVms && pids.reserve_warm_vm()) ++got;
    CHECK(got == spare_cap - 1, "spares stop at kMaxVms - kKeepFree - live");

    // releasing gives the slot back
    pids.release_warm_vm();
    CHECK(pids.reserve_warm_vm(), "a released slot is reusable");
    for (int k = 0; k < got; ++k) pids.release_warm_vm();

    // live processes shrink what spares may take
    std::vector<std::int32_t> live;
    for (int k = 0; k < 50; ++k) live.push_back(pids.allocate(10000 + k));
    CHECK(pids.live_processes() >= 50, "live processes are counted");
    got = 0;
    while (got < PidSpace::kMaxVms && pids.reserve_warm_vm()) ++got;
    CHECK(got == spare_cap - pids.live_processes(), "spares give way to live processes");
    for (int k = 0; k < got; ++k) pids.release_warm_vm();

    // a tree at the cap parks nothing, and real forks keep kKeepFree
    for (int k = 50; pids.live_processes() < spare_cap; ++k) live.push_back(pids.allocate(10000 + k));
    CHECK(!pids.reserve_warm_vm(), "a full tree parks no spares");
    for (const auto g : live) pids.release(g);

    if (fails == 0) std::puts("vm_budget: spares fit the cap, give way to live processes, and come back");
    return fails ? 1 : 0;
}
