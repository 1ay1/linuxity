// src/options.hpp -- everything one linuxity run is told, from flags or env.vibe.
#pragma once

#include "linuxity/env/config.hpp"
#include "linuxity/kernel/resources.hpp"

#include <string>
#include <utility>
#include <vector>

namespace lx::cli {

struct Options {
    // filesystem
    std::string root;
    std::string persist;            // durable upper; "" = ephemeral
    bool pacman_overwrite{true};
    bool private_tmp{true};
    std::vector<std::pair<std::string, std::string>> binds;   // host, guest

    // machine
    bool host_pids{false};
    kernel::ResourceSpec res;
    std::string hostname{"linuxity"};
    std::string release{"6.6.0-linuxity"};
    bool host_hw{true};

    // login
    std::string user{"root"};
    std::string shell;              // "" = the user's from /etc/passwd
    std::string cwd;                // "" = the user's home (instance) / "/" (run)
    std::string timezone;
    std::string locale;
    unsigned umask{022};
    bool clean_env{false};
    std::vector<std::string> pass_env;
    std::vector<std::pair<std::string, std::string>> env;

    // network
    std::vector<std::string> dns;
    bool manage_dns{true};

    // compat / debug (become the LINUXITY_* variables the runtime reads)
    bool seccomp{true};
    bool emulate_fifos{false}, emulate_sysv{false}, emulate_nl80211{false}, emulate_hardlinks{false};
    std::string trace;

    // reporting
    int status_fd{-1};
    bool quiet{false};

    // instance mode
    bool instance{false};
    std::string env_name;
    env::EnvConfig cfg;             // the whole config, for services and reload
    std::string config_path;
    std::string control_path;
    std::string run_dir;
    std::string logs_dir;
    std::string pid_path;
    int ready_fd{-1};               // a daemon tells its launcher it is up

    std::vector<std::string> argv;  // the program; empty in instance mode
};

// Fill `o` from a loaded env config. Flags given after it still override.
inline void apply_config(const env::EnvConfig& c, Options& o) {
    o.root = c.rootfs;
    o.persist = c.persist ? c.upper : std::string{};
    o.pacman_overwrite = c.pacman_overwrite;
    o.private_tmp = c.private_tmp;
    for (const auto& m : c.mounts) o.binds.emplace_back(m.host, m.at);
    o.host_pids = c.host_pids;
    o.res = c.limits;
    o.hostname = c.hostname;
    o.release = c.kernel_release;
    o.host_hw = c.host_hardware;
    o.user = c.user;
    o.shell = c.shell;
    o.cwd = c.cwd;
    o.timezone = c.timezone;
    o.locale = c.locale;
    o.umask = env::umask_value(c);
    o.clean_env = c.clean_env;
    o.pass_env = c.pass_env;
    o.env = c.env;
    o.dns = c.dns;
    o.manage_dns = c.manage_dns;
    o.seccomp = c.seccomp;
    o.emulate_fifos = c.emulate_fifos;
    o.emulate_sysv = c.emulate_sysv;
    o.emulate_nl80211 = c.emulate_nl80211;
    o.emulate_hardlinks = c.emulate_hardlinks;
    o.trace = c.trace;
    o.cfg = c;
}

}  // namespace lx::cli
