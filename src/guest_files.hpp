// src/guest_files.hpp -- the files a guest finds in /etc that linuxity serves.
//
// A pristine rootfs ships /etc/resolv.conf empty or absent, and /etc/hostname
// and /etc/hosts that know nothing of the name the environment was given.
// linuxity serves those three as virtual files (it never mutates the image).
// That was done only by the Linux runner, so on a Mac every fresh
// environment had no DNS at all: `apk add git` said "DNS: transient error"
// and every first command failed. It is policy over the rootfs and Options,
// not over how a guest runs, so every host calls this.
#pragma once

#include "options.hpp"

#include "linuxity/env/json.hpp"
#include "linuxity/env/status.hpp"
#include "linuxity/env/store.hpp"
#include "linuxity/kernel/resolver.hpp"

#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>

namespace lx::cli {

namespace detail {
[[nodiscard]] inline kernel::VirtualFile text_file(std::string_view body) {
    kernel::VirtualFile vf;
    vf.bytes.assign(reinterpret_cast<const std::byte*>(body.data()),
                    reinterpret_cast<const std::byte*>(body.data() + body.size()));
    return vf;
}
}  // namespace detail

// Mount /etc/resolv.conf, /etc/hostname and /etc/hosts into `k` for a
// rootfs run. Returns the served resolv.conf body, shared so `linuxity
// reload` can change it live. `quiet_events` is for a fork child, which
// rebuilds the same namespace and must not repeat the parent's notices.
template <class K>
std::shared_ptr<std::string> mount_guest_files(K& k, const Options& o, bool quiet_events = false) {
    auto resolv = std::make_shared<std::string>();
    if (o.root.empty()) return resolv;
    auto& st = env::status();

    // DNS: kernel/resolver.hpp picks the nameservers (network.dns / --dns or
    // LINUXITY_DNS > the image's own > the host's resolv.conf > public).
    // The image's own needs no help: then the file is left alone, options
    // and all. Opt out with network.manage-dns=false or LINUXITY_NO_DNS=1.
    if (o.manage_dns && !std::getenv("LINUXITY_NO_DNS")) {
        const auto gpc = k.files().classify("/etc/resolv.conf");
        const std::string guest_resolv =
            gpc.realm == kernel::Realm2::host_backed ? gpc.host_path : std::string{};
        std::string dns_spec;
        for (const auto& s : o.dns) dns_spec += (dns_spec.empty() ? "" : ",") + s;
        const auto choice = kernel::choose_nameservers(
            dns_spec.empty() ? std::getenv("LINUXITY_DNS") : dns_spec.c_str(),
            "/etc/resolv.conf", guest_resolv);
        if (choice.origin != kernel::ResolverOrigin::guest_file && !choice.empty()) {
            *resolv = kernel::render_resolv_conf(choice.servers);
            k.files().mount_virtual("/etc/resolv.conf",
                [resolv](std::string_view) -> Result<kernel::VirtualFile> {
                    return detail::text_file(*resolv);
                });
        }
        if (!quiet_events) {
            const std::string origin{kernel::origin_name(choice.origin)};
            st.event("dns", choice.empty() ? std::string{"no nameservers found"}
                                           : "dns from " + origin + " (" + choice.servers.front() + ")",
                     [&](env::Json& j) { j.kv("origin", origin).kv("servers", choice.servers); });
        }
    }

    // /etc/hostname follows system.hostname (and a live reload). With an env
    // the config owns the name; a bare --root run keeps the image's file if
    // it has one. Read from the machine on every open, like uname.
    {
        const auto hpc = k.files().classify("/etc/hostname");
        if (hpc.realm != kernel::Realm2::host_backed || !o.env_name.empty())
            k.files().mount_virtual("/etc/hostname", [&k](std::string_view) -> Result<kernel::VirtualFile> {
                return detail::text_file(k.machine().nodename + "\n");
            });
    }

    // /etc/hosts: the image's own, plus the hostname when it lacks it, so
    // sudo and friends can resolve it (WSL and Docker do the same). Live, so
    // a hostname change shows up at once. network.manage-hosts=false turns
    // it off and leaves the file editable.
    if (o.manage_hosts) {
        const auto hpc = k.files().classify("/etc/hosts");
        const std::string image_hosts = hpc.realm == kernel::Realm2::host_backed ? hpc.host_path : std::string{};
        k.files().mount_virtual("/etc/hosts", [&k, image_hosts](std::string_view) -> Result<kernel::VirtualFile> {
            std::string body = image_hosts.empty() ? std::string{} : env::slurp(image_hosts).value_or("");
            if (body.empty()) body = "127.0.0.1\tlocalhost\n::1\t\tlocalhost ip6-localhost ip6-loopback\n";
            if (body.back() != '\n') body.push_back('\n');
            const std::string& h = k.machine().nodename;
            bool named = false;
            std::size_t at = 0;
            while (!named && (at = body.find(h, at)) != std::string::npos) {
                const bool left = at == 0 || body[at - 1] == ' ' || body[at - 1] == '\t';
                const std::size_t e = at + h.size();
                const bool right = e == body.size() || body[e] == ' ' || body[e] == '\t' || body[e] == '\n' || body[e] == '.';
                named = left && right;
                at = e;
            }
            if (!named) body += "127.0.1.1\t" + h + "\n";
            return detail::text_file(body);
        });
    }
    return resolv;
}

}  // namespace lx::cli
