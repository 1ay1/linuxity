// src/host_run.hpp -- what each host supplies to the ONE main (src/main.cpp).
//
// There is one linuxity command line: one flag parser, one usage text, one
// set of verbs, one Options (options.hpp). What genuinely differs per host
// is only how a guest is RUN -- ptrace+seccomp on Linux, Hypervisor.framework
// on macOS, WHP on Windows -- and the private re-entry modes a host uses to
// start its own helper processes. Those are the three functions below,
// defined once per host in src/run_<host>.cpp and nowhere else.
#pragma once

#include "options.hpp"

namespace lx::cli {

// Which host this binary was built for, for help text and `linuxity info`.
[[nodiscard]] const char* host_name() noexcept;

// Can this host keep an environment running in the background (`linuxity
// up`), with sessions joining it? Where it can't, a session is a foreground
// run of the environment instead -- same files, same settings, its own
// kernel. The one answer the CLI asks before choosing either.
[[nodiscard]] bool host_runs_instances() noexcept;

// Run the guest `o` describes (o.argv, or an instance when o.instance) to
// completion. argc/argv are the process's own, for hosts that re-exec
// themselves (cgroup delegation, fork children). Returns the exit status.
[[nodiscard]] int host_run(Options& o, int argc, char** argv);

// A private re-entry mode the host starts itself in (a macOS fork child or
// zygote, Windows' --check). Returns the exit status if argv[i] names one,
// or -1 to let main carry on. Called before anything else is parsed.
[[nodiscard]] int host_internal(const Options& o, int argc, char** argv, int i);

}  // namespace lx::cli
