// linuxity/env/catalog.hpp
//
// The images `linuxity new` knows: official minimal root filesystems, pinned
// to a release with the checksum its publisher lists. Pinned, not "latest",
// so an image is reproducible and verified; bump the entries to move on.
// Anything else comes in with `linuxity import <tarball>`.
#pragma once

#include "linuxity/env/json.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace lx::env {

struct Image {
    std::string_view distro;        // what you type: "ubuntu"
    std::string_view version;       // "24.04"
    std::string_view arch;          // "aarch64" | "x86_64"
    std::string_view title;         // "Ubuntu 24.04 LTS"
    std::string_view url;
    std::string_view algo;          // "sha256" | "md5"
    std::string_view checksum;      // hex; empty = fetch checksum_url
    std::string_view checksum_url;  // a "<hex>  <file>" file next to the image
    std::string_view strip;         // top directory inside the tarball
    std::string_view setup;         // sh run as root once it's unpacked
    int size_mb;                    // download size, roughly
    std::string_view note;
};

#if defined(__aarch64__)
inline constexpr std::string_view kHostArch = "aarch64";
#else
inline constexpr std::string_view kHostArch = "x86_64";
#endif

// Arch needs a mirror and a keyring before pacman can do anything.
inline constexpr std::string_view kArchSetup =
    "f=/etc/pacman.d/mirrorlist; "
    "grep -q '^Server' $f 2>/dev/null || "
    "printf 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\\n' >> $f; "
    "pacman-key --init >/dev/null 2>&1 && pacman-key --populate >/dev/null 2>&1";
inline constexpr std::string_view kAlarmSetup =
    "pacman-key --init >/dev/null 2>&1 && pacman-key --populate archlinuxarm >/dev/null 2>&1";

inline constexpr Image kImages[] = {
    {"alpine", "3.24", "aarch64", "Alpine Linux 3.24",
     "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.4-aarch64.tar.gz",
     "sha256", "4b14c18f7e90a063b61462ea1462a5732c154bf6adad594974fe6487cd98a8de", "", "", "", 4,
     "tiny and fast; musl, apk"},
    {"alpine", "3.24", "x86_64", "Alpine Linux 3.24",
     "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.4-x86_64.tar.gz",
     "sha256", "cdaa38cb8de3537967ee5b6c9b6cd00cc962da2b018e6eea48696bb274923012", "", "", "", 4,
     "tiny and fast; musl, apk"},
    {"ubuntu", "24.04", "aarch64", "Ubuntu 24.04 LTS",
     "https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.5-base-arm64.tar.gz",
     "sha256", "a91d5a93010193712d346d761372b7c9db6dfcf093893161c64ca107f05914f2", "", "", "", 30,
     "the familiar one; glibc, apt"},
    {"ubuntu", "24.04", "x86_64", "Ubuntu 24.04 LTS",
     "https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.5-base-amd64.tar.gz",
     "sha256", "e77b6f10c2590cef872b33ee9f635a0e3fd1f57fb074c0e52b5c7f56147a0c86", "", "", "", 30,
     "the familiar one; glibc, apt"},
    {"arch", "latest", "aarch64", "Arch Linux ARM",
     "https://fl.us.mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz",
     "md5", "", "https://fl.us.mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz.md5",
     "", kAlarmSetup, 830, "rolling release; pacman. A large download"},
    {"arch", "2026.11.01", "x86_64", "Arch Linux",
     "https://archive.archlinux.org/iso/2026.11.01/archlinux-bootstrap-2026.11.01-x86_64.tar.zst",
     "sha256", "655bc99849b80859173fa39338a6c910185e952173f6a1a61526cfa34ab8339c", "", "root.x86_64",
     kArchSetup, 150, "rolling release; pacman. Needs zstd to unpack"},
};

// The image for `ref` ("ubuntu", "ubuntu:24.04") on this machine.
[[nodiscard]] inline const Image* find_image(std::string_view ref) {
    const auto colon = ref.find(':');
    const std::string_view d = ref.substr(0, colon);
    const std::string_view v = colon == std::string_view::npos ? std::string_view{} : ref.substr(colon + 1);
    for (const auto& i : kImages)
        if (i.distro == d && i.arch == kHostArch && (v.empty() || v == i.version || v == "latest")) return &i;
    return nullptr;
}

[[nodiscard]] inline std::string image_file_name(const Image& i) {
    const auto s = i.url.rfind('/');
    return std::string{i.url.substr(s + 1)};
}

[[nodiscard]] inline std::string images_json() {
    Json j;
    j.obj().kv("arch", kHostArch).key("images").arr();
    for (const auto& i : kImages) {
        if (i.arch != kHostArch) continue;
        j.obj().kv("distro", i.distro).kv("version", i.version).kv("title", i.title)
            .kv("url", i.url).kv("file", image_file_name(i)).kv("algo", i.algo)
            .kv("checksum", i.checksum).kv("checksum_url", i.checksum_url)
            .kv("size_mb", i.size_mb).kv("note", i.note).end();
    }
    return j.end().end().take();
}

}  // namespace lx::env
