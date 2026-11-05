// The one linux_dirent64 encoder. Every assertion here is about the FROZEN
// kernel ABI, so it holds on every host and needs no VM to check.
#include "linuxity/abi/wire/dirent64.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace lx::abi::wire;

// -- layout is ABI, so pin it at compile time -----------------------------
static_assert(kDirentHeader == 19);
static_assert(static_cast<std::uint8_t>(DType::dir) == 4);
static_assert(static_cast<std::uint8_t>(DType::regular) == 8);
static_assert(static_cast<std::uint8_t>(DType::symlink) == 10);
static_assert(static_cast<std::uint8_t>(DType::unknown) == 0);

// reclen = header + name + NUL, rounded up to 8.
static_assert(dirent_reclen(0) == 24);   // 19 + 0 + 1 = 20 -> 24
static_assert(dirent_reclen(1) == 24);   // 21 -> 24
static_assert(dirent_reclen(4) == 24);   // 24 -> 24
static_assert(dirent_reclen(5) == 32);   // 25 -> 32
static_assert(dirent_reclen(19) == 40);  // "iana-etc-20260617-1"
static_assert(dirent_reclen(12) == 32);  // "zlib-1:1.3.2"
// Always 8-aligned, always big enough for header + name + NUL.
static_assert(dirent_reclen(37) % 8 == 0);
static_assert(dirent_reclen(37) >= 19 + 37 + 1);

static int failures = 0;
static void check(bool cond, const char* what) {
    if (!cond) { std::fprintf(stderr, "FAIL: %s\n", what); ++failures; }
}

// Decode a record the way a guest (or libalpm) would.
struct Decoded {
    std::uint64_t ino;
    std::int64_t  off;
    std::uint16_t reclen;
    std::uint8_t  type;
    std::string   name;
};
static Decoded decode(const std::byte* p) {
    Decoded d{};
    std::memcpy(&d.ino, p + 0, 8);
    std::memcpy(&d.off, p + 8, 8);
    std::memcpy(&d.reclen, p + 16, 2);
    d.type = static_cast<std::uint8_t>(p[18]);
    d.name = reinterpret_cast<const char*>(p + 19);
    return d;
}

int main() {
    std::vector<std::byte> buf(4096);

    // -- a single entry round-trips every field ---------------------------
    {
        Dirent e{12338029, 141, DType::dir, "zlib-1:1.3.2-4"};
        const std::size_t n = encode_dirent64(buf, e);
        check(n == dirent_reclen(e.name.size()), "reclen matches the helper");
        const Decoded d = decode(buf.data());
        check(d.ino == 12338029, "d_ino is the value given, not a counter");
        check(d.off == 141, "d_off round-trips");
        check(d.reclen == n, "d_reclen is the encoded length");
        check(d.type == 4, "d_type is DT_DIR");
        check(d.name == "zlib-1:1.3.2-4", "d_name round-trips with its NUL");
    }

    // -- THE REGRESSION. This is the pacman bug, as a test.
    // libalpm enumerates a directory, stats each name, and matches st_ino
    // against the d_ino it saw. If the encoder substitutes a positional
    // counter, every comparison fails and `pacman -Q` reports 0 packages on
    // an intact database. So: what goes in is what comes out.
    {
        const std::uint64_t real_inodes[] = {12338029, 12337989, 12338000, 7, 1};
        std::size_t off = 0;
        for (std::size_t i = 0; i < 5; ++i) {
            Dirent e{real_inodes[i], static_cast<std::int64_t>(i + 1),
                     DType::dir, "pkg"};
            off += encode_dirent64(std::span{buf}.subspan(off), e);
        }
        std::size_t pos = 0;
        for (std::size_t i = 0; i < 5; ++i) {
            const Decoded d = decode(buf.data() + pos);
            check(d.ino == real_inodes[i],
                  "d_ino is never replaced by the entry's position");
            check(d.ino != i + 1 || real_inodes[i] == i + 1,
                  "a positional counter would have been caught here");
            pos += d.reclen;
        }
    }

    // -- d_type is never silently downgraded ------------------------------
    // The Windows copy wrote DT_UNKNOWN for everything, which makes `find
    // -type d` and any readdir-driven tree walk fall back to a stat per
    // entry (or miss entries entirely). The encoder must pass it through.
    {
        const DType types[] = {DType::dir, DType::regular, DType::symlink,
                               DType::fifo, DType::sock, DType::unknown};
        for (DType t : types) {
            Dirent e{1, 1, t, "x"};
            encode_dirent64(buf, e);
            check(decode(buf.data()).type == static_cast<std::uint8_t>(t),
                  "d_type passes through unchanged");
        }
    }

    // -- a full buffer ends the batch, it is not an error ------------------
    {
        Dirent e{1, 1, DType::dir, "some-name"};
        const std::size_t need = dirent_reclen(e.name.size());
        std::vector<std::byte> tight(need);
        check(encode_dirent64(tight, e) == need, "exact fit succeeds");
        std::vector<std::byte> small(need - 1);
        check(encode_dirent64(small, e) == 0, "one byte short writes nothing");
        std::vector<std::byte> none(0);
        check(encode_dirent64(none, e) == 0, "empty buffer writes nothing");
    }

    // -- pad bytes are zeroed, not leaked ---------------------------------
    // The record is padded to 8; those bytes go to the guest, so they must
    // not carry whatever the buffer previously held.
    {
        std::vector<std::byte> dirty(64, std::byte{0xAB});
        Dirent e{1, 1, DType::regular, "ab"};      // 19+2+1=22 -> pad to 24
        const std::size_t n = encode_dirent64(dirty, e);
        check(n == 24, "reclen padded to 8");
        bool clean = true;
        for (std::size_t i = 19 + 2; i < n; ++i)
            if (dirty[i] != std::byte{0}) clean = false;
        check(clean, "name NUL and pad bytes are zeroed");
    }

    // -- entries pack back-to-back with no gap ----------------------------
    {
        std::size_t off = 0;
        const char* names[] = {"a", "bb", "ccc", "dddddddddddddddddddd"};
        for (int i = 0; i < 4; ++i) {
            Dirent e{static_cast<std::uint64_t>(100 + i),
                     i + 1, DType::regular, names[i]};
            const std::size_t n = encode_dirent64(std::span{buf}.subspan(off), e);
            check(n > 0, "entry fits");
            off += n;
        }
        std::size_t pos = 0;
        for (int i = 0; i < 4; ++i) {
            const Decoded d = decode(buf.data() + pos);
            check(d.name == names[i], "stream walks by d_reclen exactly");
            check(d.ino == static_cast<std::uint64_t>(100 + i), "ino per entry");
            check(d.reclen != 0, "d_reclen is never 0 (a guest would spin)");
            pos += d.reclen;
        }
        check(pos == off, "no gaps: sum of reclens == bytes written");
    }

    if (failures == 0) std::puts("dirent64: all checks passed");
    return failures == 0 ? 0 : 1;
}
