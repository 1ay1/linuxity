// linuxity/runtime/hvf_tty.hpp
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
    L_TIOCGPTN = 0x80045430,
    // termios2 (glibc >= 2.42 uses these instead of TCGETS/TCSETS*): the
    // same leading fields as struct termios, plus explicit input/output
    // speeds. _IOR/_IOW('T', 0x2A..0x2D, struct termios2[44]).
    L_TCGETS2 = 0x802c542a, L_TCSETS2 = 0x402c542b, L_TCSETSW2 = 0x402c542c,
    L_TCSETSF2 = 0x402c542d,
};

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
    l.c_cflag |= 0000017;                        // B38400: report a sane baud
    for (auto [li, di] : kCc) l.c_cc[li] = t.c_cc[di];
    return l;
}

inline void to_darwin(const LinuxTermios& l, struct ::termios& t) {
    t.c_iflag = map_out(l.c_iflag, kIflag);
    t.c_oflag = map_out(l.c_oflag, kOflag);
    t.c_lflag = map_out(l.c_lflag, kLflag);
    const tcflag_t keep_speed = t.c_cflag & ~(CSIZE | CSTOPB | CREAD | PARENB | PARODD | HUPCL | CLOCAL);
    t.c_cflag = keep_speed | map_out(l.c_cflag, kCflag);
    switch (l.c_cflag & 0000060) {
        case 0000000: t.c_cflag |= CS5; break;
        case 0000020: t.c_cflag |= CS6; break;
        case 0000040: t.c_cflag |= CS7; break;
        default:      t.c_cflag |= CS8; break;
    }
    for (auto [li, di] : kCc) t.c_cc[di] = l.c_cc[li];
}

} // namespace lx::runtime::tty

#endif // __APPLE__
