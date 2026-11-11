// linuxity/runtime/darwin/tty.hpp
//
// Terminal ioctls: Linux termios on a Darwin tty.
//
// An interactive shell lives or dies by about six ioctls. bash's readline
// calls tcgetattr (TCGETS) at startup and, if it fails, decides stdin is not a
// terminal and exits at the first prompt -- which is exactly what an ENOSYS
// here produced. Then it wants raw mode (TCSETS*), the window size
// (TIOCGWINSZ) to wrap lines, and the foreground process group (TIOCGPGRP /
// TIOCSPGRP) for job control.
//
// Linux and Darwin both implement POSIX termios, but every ABI detail
// differs: the ioctl request numbers, the struct layout (Linux packs c_cc
// into 19 bytes after a line-discipline byte; Darwin uses 20 c_cc slots and
// 64-bit flag words), the c_cc INDICES (VMIN is 6 on Linux, 16 on Darwin),
// and most flag bit positions. So each field is translated by name, never
// copied by layout.
#pragma once

#if defined(__APPLE__)

#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <utility>

namespace lx::runtime::tty {

// Linux asm-generic ioctl requests (identical on aarch64 and x86-64).
// L_-prefixed: Darwin <sys/ioctl.h> #defines the bare names (with Darwin
// values), which would silently substitute the WRONG numbers here.
enum Req : std::uint64_t {
    L_TCGETS = 0x5401, L_TCSETS = 0x5402, L_TCSETSW = 0x5403, L_TCSETSF = 0x5404,
    L_TIOCSCTTY = 0x540E, L_TIOCGPGRP = 0x540F, L_TIOCSPGRP = 0x5410,
    L_TIOCGWINSZ = 0x5413, L_TIOCSWINSZ = 0x5414, L_FIONREAD = 0x541B,
    L_TIOCNOTTY = 0x5422, L_TIOCGSID = 0x5429, L_FIONBIO = 0x5421,
    L_FIOCLEX = 0x5451, L_FIONCLEX = 0x5450, L_TCFLSH = 0x540B, L_TCXONC = 0x540A,
    L_TCSBRK = 0x5409, L_TCSBRKP = 0x5425,
    L_TIOCGPTN = 0x80045430, L_TIOCSPTLCK = 0x40045431, L_TIOCGPTPEER = 0x5441,
    // termios2 (glibc >= 2.42 uses these instead of TCGETS/TCSETS*): the
    // same leading fields as struct termios, plus explicit input/output
    // speeds. _IOR/_IOW('T', 0x2A..0x2D, struct termios2[44]).
    L_TCGETS2 = 0x802c542a, L_TCSETS2 = 0x402c542b, L_TCSETSW2 = 0x402c542c,
    L_TCSETSF2 = 0x402c542d,
};

// Requests about the terminal's line discipline and size -- what Linux
// answers on a pty MASTER as on its slave, and Darwin refuses there.
[[nodiscard]] constexpr bool is_termios_request(std::uint64_t r) noexcept {
    switch (r) {
        case L_TCGETS: case L_TCSETS: case L_TCSETSW: case L_TCSETSF:
        case L_TCGETS2: case L_TCSETS2: case L_TCSETSW2: case L_TCSETSF2:
        case L_TIOCGWINSZ: case L_TIOCSWINSZ: case L_TCFLSH: case L_TCXONC:
            return true;
        default:
            return false;
    }
}

// struct termios as the Linux kernel ABI defines it (NOT glibc's, which adds
// speed fields the kernel never sees).
struct LinuxTermios {
    std::uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    std::uint8_t c_line;
    std::uint8_t c_cc[19];
};
static_assert(sizeof(LinuxTermios) == 36);

struct LinuxWinsize { std::uint16_t row, col, xpixel, ypixel; };

// struct termios2: termios + c_ispeed/c_ospeed (Linux's BOTHER interface).
struct LinuxTermios2 {
    LinuxTermios base;
    std::uint32_t c_ispeed, c_ospeed;
};
static_assert(sizeof(LinuxTermios2) == 44);

// A flag translation table: (linux bit, darwin bit) pairs for one flag word.
// The arrays below ARE the specification; to_darwin/from_linux just walk
// them, so adding a flag is a one-line change with no logic to get wrong.
using FlagMap = std::span<const std::pair<std::uint32_t, tcflag_t>>;

inline constexpr std::pair<std::uint32_t, tcflag_t> kIflag[] = {
    {0000001, IGNBRK}, {0000002, BRKINT}, {0000004, IGNPAR}, {0000010, PARMRK},
    {0000020, INPCK},  {0000040, ISTRIP}, {0000100, INLCR},  {0000200, IGNCR},
    {0000400, ICRNL},  {0002000, IXON},   {0004000, IXANY},  {0010000, IXOFF},
    {0020000, IMAXBEL}, {0040000, IUTF8},
};
inline constexpr std::pair<std::uint32_t, tcflag_t> kOflag[] = {
    {0000001, OPOST}, {0000004, ONLCR}, {0000010, OCRNL}, {0000020, ONOCR},
    {0000040, ONLRET},
};
inline constexpr std::pair<std::uint32_t, tcflag_t> kLflag[] = {
    {0000001, ISIG},   {0000002, ICANON}, {0000010, ECHO},    {0000020, ECHOE},
    {0000040, ECHOK},  {0000100, ECHONL}, {0000200, NOFLSH},  {0000400, TOSTOP},
    {0001000, ECHOCTL}, {0002000, ECHOPRT}, {0004000, ECHOKE}, {0100000, IEXTEN},
};
inline constexpr std::pair<std::uint32_t, tcflag_t> kCflag[] = {
    {0000060, 0}, // CSIZE handled specially below
    {0000100, CSTOPB}, {0000200, CREAD}, {0000400, PARENB}, {0001000, PARODD},
    {0002000, HUPCL},  {0004000, CLOCAL},
};

// c_cc: Linux index -> Darwin index.
inline constexpr std::pair<int, int> kCc[] = {
    {0, VINTR}, {1, VQUIT}, {2, VERASE}, {3, VKILL}, {4, VEOF}, {5, VTIME},
    {6, VMIN}, {8, VSTART}, {9, VSTOP}, {10, VSUSP}, {11, VEOL}, {12, VREPRINT},
    {14, VWERASE}, {15, VLNEXT}, {16, VEOL2},
};

[[nodiscard]] inline tcflag_t map_out(std::uint32_t l, FlagMap m) {
    tcflag_t d = 0;
    for (auto [lb, db] : m) if (l & lb) d |= db;
    return d;
}
[[nodiscard]] inline std::uint32_t map_in(tcflag_t d, FlagMap m) {
    std::uint32_t l = 0;
    for (auto [lb, db] : m) if (db && (d & db)) l |= lb;
    return l;
}

// Linux's baud codes (CBAUD, cflag & 010017) and the rates they name. Darwin
// keeps the rate itself in c_ispeed/c_ospeed (B9600 == 9600), so this one
// table is the whole translation, both ways. The rate round-trips: a guest
// that sets B9600 reads B9600 back (stty, minicom, tests all check).
struct Baud { std::uint32_t code; speed_t rate; };
inline constexpr Baud kBaud[] = {
    {0000000, 0}, {0000001, 50}, {0000002, 75}, {0000003, 110}, {0000004, 134},
    {0000005, 150}, {0000006, 200}, {0000007, 300}, {0000010, 600}, {0000011, 1200},
    {0000012, 1800}, {0000013, 2400}, {0000014, 4800}, {0000015, 9600},
    {0000016, 19200}, {0000017, 38400}, {0010001, 57600}, {0010002, 115200},
    {0010003, 230400},
};
inline constexpr std::uint32_t kCbaud = 0010017;
[[nodiscard]] inline std::uint32_t baud_code(speed_t rate) {
    for (auto b : kBaud) if (b.rate == rate) return b.code;
    return 0000017;                                // unknown: B38400
}
[[nodiscard]] inline speed_t baud_rate(std::uint32_t code) {
    for (auto b : kBaud) if (b.code == (code & kCbaud)) return b.rate;
    return 38400;
}

[[nodiscard]] inline LinuxTermios from_darwin(const struct ::termios& t) {
    LinuxTermios l{};
    l.c_iflag = map_in(t.c_iflag, kIflag);
    l.c_oflag = map_in(t.c_oflag, kOflag);
    l.c_lflag = map_in(t.c_lflag, kLflag);
    l.c_cflag = map_in(t.c_cflag, kCflag);
    switch (t.c_cflag & CSIZE) {                 // CS5..CS8 -> Linux 0000060 field
        case CS5: break;
        case CS6: l.c_cflag |= 0000020; break;
        case CS7: l.c_cflag |= 0000040; break;
        default:  l.c_cflag |= 0000060; break;
    }
    l.c_cflag |= baud_code(::cfgetospeed(&t));    // the real rate, as a Linux code
    for (auto [li, di] : kCc) l.c_cc[li] = t.c_cc[di];
    return l;
}

inline void to_darwin(const LinuxTermios& l, struct ::termios& t) {
    t.c_iflag = map_out(l.c_iflag, kIflag);
    t.c_oflag = map_out(l.c_oflag, kOflag);
    t.c_lflag = map_out(l.c_lflag, kLflag);
    constexpr tcflag_t kFraming = CSIZE | CSTOPB | CREAD | PARENB | PARODD | HUPCL | CLOCAL;
    const tcflag_t keep_speed = t.c_cflag & ~kFraming;
    t.c_cflag = keep_speed | map_out(l.c_cflag, kCflag);
    switch (l.c_cflag & 0000060) {
        case 0000000: t.c_cflag |= CS5; break;
        case 0000020: t.c_cflag |= CS6; break;
        case 0000040: t.c_cflag |= CS7; break;
        default:      t.c_cflag |= CS8; break;
    }
    for (auto [li, di] : kCc) t.c_cc[di] = l.c_cc[li];
    // Linux has one baud field for both directions in c_cflag
    (void)::cfsetspeed(&t, baud_rate(l.c_cflag));
}

} // namespace lx::runtime::tty

#endif // __APPLE__
