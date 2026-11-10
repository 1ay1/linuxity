// The abi/wire layer: kernel ABI structs encoded in exactly one place.
// kernel ABI, so it holds on every host and needs no VM to check.
#include "linuxity/abi/wire/at_flags.hpp"
#include "linuxity/abi/wire/dirent64.hpp"
#include "linuxity/abi/wire/fd_flags.hpp"
#include "linuxity/abi/wire/iovec.hpp"
#include "linuxity/abi/wire/mmap.hpp"
#include "linuxity/abi/wire/open_flags.hpp"
#include "linuxity/abi/wire/path.hpp"
#include "linuxity/abi/wire/stat.hpp"

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
            (void)encode_dirent64(buf, e);
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

    // -- struct stat layout, the OTHER thing abi/wire owns ----------------
    // x86-64 and asm-generic genuinely disagree about struct stat, which is
    // why three independent copies of these offsets was dangerous: every copy
    // was correct, so a drift in one reports a plausible WRONG mode rather
    // than failing. Both backends' LinuxStat structs static_assert against
    // these, and the dispatcher's scrub reads them.
    {
        using namespace lx::abi;
        check(wire::stat_layout(lx::abi::Arch::x86_64).mode == 24, "x86-64 st_mode @24");
        check(wire::stat_layout(lx::abi::Arch::x86_64).uid == 28,  "x86-64 st_uid @28");
        check(wire::stat_layout(lx::abi::Arch::x86_64).size == 144, "x86-64 stat is 144");
        // aarch64 puts st_nlink AFTER st_mode, so everything shifts.
        check(wire::stat_layout(lx::abi::Arch::aarch64).mode == 16, "aarch64 st_mode @16");
        check(wire::stat_layout(lx::abi::Arch::aarch64).uid == 24,  "aarch64 st_uid @24");
        check(wire::stat_layout(lx::abi::Arch::aarch64).size == 128, "aarch64 stat is 128");
        // The two MUST differ -- if they ever agree, one is wrong.
        check(wire::stat_layout(lx::abi::Arch::x86_64).mode !=
              wire::stat_layout(lx::abi::Arch::aarch64).mode,
              "the two stat layouts are genuinely different");
        // statx is one fixed layout, with a NARROWER mode field. Reading 4
        // bytes at stx_mode would pick up the following pad.
        check(wire::kStatx.mode == 28, "statx stx_mode @28");
        check(wire::kStatx.mode_width == 2, "statx mode is u16, not u32");
        check(wire::kStatX86_64.mode_width == 4, "stat mode is u32");
    }

    // -- open(2) flags, the third thing abi/wire owns ----------------------
    // These decide whether a path is opened FOR WRITE, which selects the
    // copy-on-write branch in the overlay. Getting one wrong silently writes
    // into the pristine lower layer. Values verified against this host's own
    // <fcntl.h>, then pinned here.
    {
        using namespace lx::abi::wire;
        check(bits(OpenFlag::creat) == 0100, "O_CREAT is 0100");
        check(bits(OpenFlag::excl) == 0200, "O_EXCL is 0200");
        check(bits(OpenFlag::trunc) == 01000, "O_TRUNC is 01000");
        check(bits(OpenFlag::directory) == 0200000, "O_DIRECTORY is 0200000");
        check(bits(OpenFlag::cloexec) == 02000000, "O_CLOEXEC is 02000000");
        check(bits(OpenFlag::tmpfile) == 020200000, "O_TMPFILE is 020200000");

        // The access mode is the low two bits, NOT a bitmask: O_RDONLY is 0,
        // so `flags & O_RDONLY` is always false. This is the classic bug.
        check(bits(OpenFlag::rdonly) == 0, "O_RDONLY is 0, not a bit");
        check(!writable(bits(OpenFlag::rdonly)), "a plain read is not a write");
        check(writable(bits(OpenFlag::wronly)), "O_WRONLY is a write");
        check(writable(bits(OpenFlag::rdwr)), "O_RDWR is a write");

        // A read-only open that CREATES or TRUNCATES still mutates the tree,
        // so it must take the copy-up path.
        check(writable(bits(OpenFlag::rdonly) | bits(OpenFlag::creat)),
              "O_RDONLY|O_CREAT must count as a write");
        check(writable(bits(OpenFlag::rdonly) | bits(OpenFlag::trunc)),
              "O_RDONLY|O_TRUNC must count as a write");
        // ...but these must NOT make it writable, or every open copies up.
        check(!writable(bits(OpenFlag::cloexec)), "O_CLOEXEC is not a write");
        check(!writable(bits(OpenFlag::directory)), "O_DIRECTORY is not a write");
        check(!writable(bits(OpenFlag::nonblock)), "O_NONBLOCK is not a write");

        // O_TMPFILE contains O_DIRECTORY, so a "is this a directory open"
        // test must exclude it or it treats a tmpfile create as a dir open.
        check((bits(OpenFlag::tmpfile) & bits(OpenFlag::directory)) != 0,
              "O_TMPFILE contains O_DIRECTORY (a real trap)");
    }

    // -- path normalization ------------------------------------------------
    // One implementation now (it was two: kernel/file_namespace.hpp and
    // windows/sys.hpp, structured differently). This is security-relevant: a
    // `..` that escapes the root means the overlay translates a guest path to
    // a host path ABOVE the rootfs.
    {
        using lx::abi::wire::normalize_path;
        using lx::abi::wire::absolutize_path;
        auto eq = [&](std::string_view in, std::string_view want) {
            const std::string got = normalize_path(in);
            if (got != want) {
                std::fprintf(stderr, "FAIL normalize(%.*s) = [%s], want [%s]\n",
                             int(in.size()), in.data(), got.c_str(),
                             std::string(want).c_str());
                ++failures;
            }
        };
        eq("/", "/");
        eq("/a", "/a");
        eq("/a/b", "/a/b");
        eq("/a//b", "/a/b");            // duplicate separators collapse
        eq("///a", "/a");
        eq("/a/./b", "/a/b");           // "." drops
        eq("/a/./././b", "/a/b");
        eq("/./", "/");
        eq("/a/", "/a");                // trailing slash, except root
        eq("/a/b/", "/a/b");
        eq("/a/../b", "/b");            // ".." pops
        eq("/a/b/../..", "/");
        eq("/...", "/...");             // "..." is a normal name, not ".."
        eq("/a/..b", "/a/..b");
        eq("/..a/b", "/..a/b");

        // THE SECURITY CASES: ".." at or above the root must clamp, never
        // escape. If any of these returned something starting with ".." or
        // escaping upward, a guest could read outside the rootfs.
        eq("/..", "/");
        eq("/../..", "/");
        eq("/a/b/../../..", "/");
        eq("/../../../etc/passwd", "/etc/passwd");
        eq("/a/../../../../b", "/b");

        // Every result is absolute, has no trailing slash (bar root), and no
        // empty or dot components.
        const char* probes[] = {"/", "/a", "/a//b/", "/../x", "/a/./b/../c",
                                "/./.././a//./b/", "//////", "/a/b/c/../../.."};
        for (const char* s : probes) {
            const std::string r = normalize_path(s);
            check(!r.empty() && r.front() == '/', "result is absolute");
            check(r == "/" || r.back() != '/', "no trailing slash but root");
            check(r.find("//") == std::string::npos, "no empty components");
            check(r.find("/./") == std::string::npos, "no dot components");
            check(r.find("/../") == std::string::npos, "no dotdot left");
            check(r.size() < 3 || r.compare(r.size() - 3, 3, "/..") != 0,
                  "no trailing dotdot");
        }

        // absolutize: a relative path joins the cwd, an absolute one ignores
        // it, and an empty path means the cwd itself (AT_EMPTY_PATH).
        check(absolutize_path("b", "/a") == "/a/b", "relative joins cwd");
        check(absolutize_path("/b", "/a") == "/b", "absolute ignores cwd");
        check(absolutize_path("", "/a/b") == "/a/b", "empty path is the cwd");
        check(absolutize_path("../c", "/a/b") == "/a/c", "relative dotdot");
        check(absolutize_path("b", "/") == "/b", "cwd root does not double up");
        // A relative path must not escape the root either.
        check(absolutize_path("../../../x", "/a") == "/x", "relative clamps");
    }

    // -- iovec -------------------------------------------------------------
    {
        using lx::abi::wire::Iovec;
        check(sizeof(Iovec) == 16, "iovec is 16 bytes on LP64");
        check(alignof(Iovec) == 8, "iovec is 8-aligned");
        check(lx::abi::wire::kIovMax == 1024, "IOV_MAX is 1024");
    }

    // -- mmap prot / flags -------------------------------------------------
    // Values checked against this host's <sys/mman.h> before being written
    // down. MAP_* is a near-miss family -- 0x2000 LOCKED, 0x4000 NORESERVE,
    // 0x8000 POPULATE -- so mistaking one for another changes mapping
    // semantics silently instead of failing.
    {
        using namespace lx::abi::wire;
        check(bits(Prot::read) == 1 && bits(Prot::write) == 2 &&
              bits(Prot::exec) == 4, "PROT_* are 1/2/4");
        check(bits(Prot::none) == 0, "PROT_NONE is 0, not a bit");
        check(bits(MapFlag::shared) == 0x01, "MAP_SHARED");
        check(bits(MapFlag::priv) == 0x02, "MAP_PRIVATE");
        check(bits(MapFlag::fixed) == 0x10, "MAP_FIXED");
        check(bits(MapFlag::anonymous) == 0x20, "MAP_ANONYMOUS");
        check(bits(MapFlag::locked) == 0x2000, "MAP_LOCKED");
        check(bits(MapFlag::noreserve) == 0x4000, "MAP_NORESERVE");
        check(bits(MapFlag::populate) == 0x8000, "MAP_POPULATE");
        check(bits(MapFlag::stack) == 0x20000, "MAP_STACK");
        check(bits(MapFlag::fixed_noreplace) == 0x100000, "MAP_FIXED_NOREPLACE");

        // The near-miss neighbours must stay distinct.
        check(bits(MapFlag::locked) != bits(MapFlag::noreserve), "LOCKED != NORESERVE");
        check(bits(MapFlag::noreserve) != bits(MapFlag::populate), "NORESERVE != POPULATE");

        // An anonymous mapping ignores the fd. A backend that misses this
        // tries to map fd -1 and fails a valid allocation.
        check(is_anonymous(bits(MapFlag::anonymous) | bits(MapFlag::priv)),
              "MAP_ANONYMOUS|MAP_PRIVATE is anonymous");
        check(!is_anonymous(bits(MapFlag::priv)), "MAP_PRIVATE alone is not");

        // MAP_FIXED replaces an existing mapping; MAP_FIXED_NOREPLACE returns
        // EEXIST. Treating the second as the first is silent data loss.
        check(wants_fixed(bits(MapFlag::fixed)), "MAP_FIXED pins the address");
        check(wants_fixed(bits(MapFlag::fixed_noreplace)), "so does NOREPLACE");
        check(!wants_fixed(bits(MapFlag::priv)), "MAP_PRIVATE does not");
        check(fixed_must_not_replace(bits(MapFlag::fixed_noreplace)),
              "NOREPLACE must not clobber an existing mapping");
        check(!fixed_must_not_replace(bits(MapFlag::fixed)),
              "plain MAP_FIXED may clobber");
    }

    // -- *at() flags -------------------------------------------------------
    // These were redeclared inline at five points of use (twice in the same
    // file). Values checked against this host's <fcntl.h>.
    {
        using namespace lx::abi::wire;
        check(kAtFdCwd == -100, "AT_FDCWD is -100");
        // It's a SENTINEL fd, not a flag: stored unsigned it becomes a huge
        // positive number that no fd table will ever match.
        check(kAtFdCwd < 0, "AT_FDCWD must stay negative");
        check(is_cwd_fd(kAtFdCwd), "AT_FDCWD is recognized");
        check(!is_cwd_fd(0) && !is_cwd_fd(3), "a real fd is not AT_FDCWD");

        check(bits(AtFlag::symlink_nofollow) == 0x100, "AT_SYMLINK_NOFOLLOW");
        check(bits(AtFlag::removedir) == 0x200, "AT_REMOVEDIR");
        check(bits(AtFlag::symlink_follow) == 0x400, "AT_SYMLINK_FOLLOW");
        check(bits(AtFlag::no_automount) == 0x800, "AT_NO_AUTOMOUNT");
        check(bits(AtFlag::empty_path) == 0x1000, "AT_EMPTY_PATH");

        // THE TRAP: AT_REMOVEDIR and AT_EACCESS are the same bit. They're
        // disjoint only because no syscall takes both (unlinkat vs faccessat),
        // so testing this bit without knowing the syscall reads "remove a
        // directory" out of an access check.
        check(bits(AtFlag::removedir) == bits(AtFlag::eaccess),
              "AT_REMOVEDIR and AT_EACCESS share 0x200 (deliberate)");
        // Opposite requests must never be the same bit.
        check(bits(AtFlag::symlink_nofollow) != bits(AtFlag::symlink_follow),
              "nofollow and follow are distinct");

        check(has_at(bits(AtFlag::empty_path), AtFlag::empty_path), "has_at hits");
        check(!has_at(bits(AtFlag::removedir), AtFlag::empty_path),
              "has_at does not cross-match");
    }

    // -- S_IF* file-type bits ----------------------------------------------
    // These were spelled three times (twice inline in syscall.hpp, plus bare
    // octal in dtype_from_mode). They're OCTAL: writing 0040000 as 40000
    // decimal is a silent plausible wrong answer.
    {
        using namespace lx::abi::wire;
        check(bits(FileType::dir) == 0040000u, "S_IFDIR is 0040000");
        check(bits(FileType::regular) == 0100000u, "S_IFREG is 0100000");
        check(bits(FileType::symlink) == 0120000u, "S_IFLNK is 0120000");
        check(kFileTypeMask == 0170000u, "S_IFMT is 0170000");

        // The type mask must not overlap the permission bits, or a chmod
        // would change a file's TYPE.
        check((kFileTypeMask & 0777u) == 0u, "type mask misses the perm bits");

        // is_type works with permissions OR'd in, which is how it's used.
        check(is_type(bits(FileType::dir) | 0755u, FileType::dir),
              "a 0755 directory is a directory");
        check(!is_type(bits(FileType::regular) | 0755u, FileType::dir),
              "a 0755 regular file is not a directory");
        check(is_type(bits(FileType::symlink) | 0777u, FileType::symlink),
              "a 0777 symlink is a symlink");

        // dtype_from_mode bridges S_IF* to the dirent d_type space, which
        // uses DIFFERENT numbers for the same concepts (DT_DIR 4 vs
        // S_IFDIR 0040000). A mix-up here is how `find -type d` goes blind.
        check(dtype_from_mode(bits(FileType::dir) | 0755u) == DType::dir,
              "S_IFDIR -> DT_DIR");
        check(dtype_from_mode(bits(FileType::regular) | 0644u) == DType::regular,
              "S_IFREG -> DT_REG");
        check(dtype_from_mode(bits(FileType::symlink) | 0777u) == DType::symlink,
              "S_IFLNK -> DT_LNK");
        check(dtype_from_mode(0) == DType::unknown, "no type bits -> DT_UNKNOWN");
        check(static_cast<std::uint32_t>(DType::dir) != bits(FileType::dir),
              "DT_DIR and S_IFDIR are genuinely different numbers");
    }

    // -- descriptor-creation flags -----------------------------------------
    // `kCloexec` was declared FIVE times in darwin/trap.hpp with TWO
    // different values. Four were the same number written in two bases;
    // the fifth (MFD_CLOEXEC) was a different constant wearing the same
    // name. Values verified against this host's headers.
    {
        using namespace lx::abi::wire;
        // Octal/hex is how the duplication hid: these look unrelated.
        check(kOCloexec == 0x80000, "O_CLOEXEC is 0x80000");
        check(02000000 == 0x80000, "02000000 and 0x80000 are the same number");
        check(kONonblock == 0x800, "O_NONBLOCK is 0x800");
        check(04000 == 0x800, "04000 and 0x800 are the same number");

        // The aliases share the bit on purpose, so an open-like call can
        // pass one flag word.
        check(kEpollCloexec == kOCloexec, "EPOLL_CLOEXEC shares O_CLOEXEC");
        check(kSockCloexec == kOCloexec, "SOCK_CLOEXEC shares it");
        check(kEfdCloexec == kOCloexec, "EFD_CLOEXEC shares it");
        check(kTfdCloexec == kOCloexec, "TFD_CLOEXEC shares it");
        check(kSockNonblock == kONonblock, "SOCK_NONBLOCK shares O_NONBLOCK");

        // THE BUG THIS PREVENTS: MFD_CLOEXEC and FD_CLOEXEC are 1, NOT
        // 0x80000. Using the open-flag bit for memfd_create silently fails
        // to set close-on-exec, and the leaked fd survives every later exec.
        // I hit this exact bug with a careless regex while writing this
        // commit, which is why the assertion exists.
        check(kMfdCloexec == 1, "MFD_CLOEXEC is 1");
        check(kFdCloexec == 1, "FD_CLOEXEC is 1");
        check(kMfdCloexec != kOCloexec,
              "MFD_CLOEXEC must NOT be unified onto O_CLOEXEC");
        check(kFdCloexec != kOCloexec,
              "FD_CLOEXEC must NOT be unified onto O_CLOEXEC");
    }

    // -- the permission mask -----------------------------------------------
    // `07777` was spelled at four sites (two chmod paths in syscall.hpp, four
    // in meta_store). The digit that matters is the top one.
    {
        using namespace lx::abi::wire;
        check(kPermMask == 07777, "the perm mask is 07777");
        check(kPermMask == 0xfff, "...which is 0xfff");

        // 07777, NOT 0777. The top digit carries setuid/setgid/sticky, and
        // masking with 0777 silently strips setuid from every file the shadow
        // store remembers -- that's how su and sudo lose their privilege bits
        // across a run.
        check(kPermMask != 0777, "0777 would drop the set-id bits");
        check((kPermMask & 04000) == 04000, "setuid is inside the mask");
        check((kPermMask & 02000) == 02000, "setgid is inside the mask");
        check((kPermMask & 01000) == 01000, "sticky is inside the mask");
        check((0777u & 04000u) == 0, "...and 0777 really would miss setuid");

        // Perm and type must be disjoint, or a chmod changes a file's TYPE.
        check((kPermMask & kFileTypeMask) == 0, "perm and type are disjoint");
        // And together they cover the low 16 bits with no gap -- a bit in
        // neither mask would be dropped by every chmod path.
        check((kPermMask | kFileTypeMask) == 0177777u, "no gap between them");

        // A realistic round-trip: setuid-root 4755 on a regular file.
        const std::uint32_t m = bits(FileType::regular) | 04755u;
        check((m & kPermMask) == 04755u, "4755 survives the perm mask");
        check(is_type(m, FileType::regular), "...and it is still a regular file");
    }

    if (failures == 0) std::puts("wire: all checks passed");
    return failures == 0 ? 0 : 1;
}
