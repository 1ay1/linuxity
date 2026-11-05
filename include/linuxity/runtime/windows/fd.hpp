// linuxity/runtime/windows/fd.hpp
//
// The guest file-descriptor table, over Win32 HANDLEs.
//
// On the ptrace backend the guest is a separate host process, so its fd table
// IS a host fd table and nothing can leak. Here the guest runs inside
// linuxity's own process, and the naive design (guest fd == host handle) is
// wrong in a way that only shows up late: coreutils closes stdout at exit,
// and with a shared table that closes LINUXITY'S stdout -- every later line
// the host prints silently vanishes. So the guest gets its own table:
// guest fd -> refcounted Win32 handle, with stdio DUPLICATED at construction.
//
// This mirrors hvf_fd.hpp deliberately, including two lessons that were
// expensive to learn there and would be just as expensive to relearn here:
//
//   * stdio is duplicated, so a guest closing 0/1/2 never touches the host's.
//   * guest fds 3..8 are RESERVED, so the guest's own descriptors begin at 9,
//     exactly like a program launched from a real login session (which always
//     inherits a terminal, journal and dbus socket). This is load-bearing,
//     not cosmetic -- see reserve_low_fds() below.
//
// WHAT DIFFERS FROM POSIX, and why each is handled rather than ignored:
//
//   NO FILE OFFSET SHARING FOR FREE. On Linux a dup() shares the file offset
//   because both fds name one "open file description". Win32 keeps the
//   position in the HANDLE, and DuplicateHandle shares it -- so dup() maps
//   onto refcounting the SAME handle, which gets the Linux semantics right.
//   (Opening the path twice would NOT: the offsets would diverge.)
//
//   NO O_APPEND. Win32 has FILE_APPEND_DATA but it does not survive the
//   generic-access mapping cleanly, so append is emulated by seeking to EOF
//   before each write -- which is what O_APPEND guarantees atomically. We
//   are single-threaded per guest-fd here, so the emulation is sound.
//
//   DIRECTORY HANDLES need FILE_FLAG_BACKUP_SEMANTICS; without it
//   CreateFileW fails ERROR_ACCESS_DENIED on any directory. The flag is set
//   in whp_win32.hpp's translate_open, and getdents64 is served by a
//   FindFirstFileW enumeration cached per directory fd (a guest reads a
//   directory incrementally and expects a stable sequence across calls).
#pragma once

#if defined(_WIN32)

#include "linuxity/runtime/windows/win32.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace lx::runtime {

// One Win32 handle, closed when the last guest fd referring to it goes away.
// dup()/dup2() share the same WinFd, exactly like the open file description
// they share on Linux -- including the file position, which lives in the
// handle.
class WinFd {
public:
    explicit WinFd(HANDLE h) noexcept : h_{h} {}
    WinFd(const WinFd&) = delete;
    WinFd& operator=(const WinFd&) = delete;
    ~WinFd() {
        if (h_ != INVALID_HANDLE_VALUE && h_ != nullptr) ::CloseHandle(h_);
    }
    [[nodiscard]] HANDLE get() const noexcept { return h_; }
private:
    HANDLE h_;
};

// Per-descriptor state that is NOT shared by a dup: Linux keeps O_APPEND and
// O_NONBLOCK in the open file description (shared), but the directory
// enumeration cursor is ours and must not be shared, or two guest fds reading
// the same directory would consume each other's entries.
struct DirCursor {
    std::vector<std::string> names;   // snapshot taken at first getdents
    std::size_t pos{0};
    bool loaded{false};
};

class FdTable {
public:
    static constexpr int kMaxFds = 1024;   // matches the RLIMIT_NOFILE we report

    // Seed 0/1/2 from DUPLICATES of the host's standard handles, so the guest
    // owns its copies and can close or redirect them freely.
    FdTable() {
        const DWORD std_ids[3]{STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
                               STD_ERROR_HANDLE};
        for (int fd = 0; fd < 3; ++fd) {
            HANDLE src = ::GetStdHandle(std_ids[fd]);
            HANDLE dup = INVALID_HANDLE_VALUE;
            if (src && src != INVALID_HANDLE_VALUE &&
                ::DuplicateHandle(::GetCurrentProcess(), src,
                                  ::GetCurrentProcess(), &dup, 0, FALSE,
                                  DUPLICATE_SAME_ACCESS)) {
                install_at(fd, std::make_shared<WinFd>(dup), false);
                slots_[std::size_t(fd)].is_tty =
                    ::GetFileType(dup) == FILE_TYPE_CHAR;
            } else {
                // No console (a GUI subsystem parent, or a closed handle).
                // Leave the slot EMPTY rather than installing a bogus handle:
                // the guest then gets EBADF, which is truthful, instead of
                // writes that silently vanish.
                install_at(fd, nullptr, false);
            }
        }
    }

    // Occupy guest fds 3..8 with harmless NUL handles, so the guest's own
    // descriptors begin at 9 -- exactly like a program launched from a real
    // login session, which always inherits a few (terminal, journal, dbus).
    //
    // This is load-bearing, not cosmetic. The macOS backend learned it the
    // hard way: pacman's download worker closes a low descriptor and
    // immediately reopens that SAME number for core.db, while sibling threads
    // still believe the number is the old libcurl wakeup channel and keep
    // writing 8-byte wakeups to it. In a bare 0,1,2-only process the two
    // collide on fd 3 and the wakeups land INSIDE the database. Both other
    // backends reserve these slots; this one must agree or it will reproduce
    // the same corruption.
    void reserve_low_fds() {
        for (int want = 3; want <= 8; ++want) {
            HANDLE h = ::CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     nullptr, OPEN_EXISTING, 0, nullptr);
            if (h == INVALID_HANDLE_VALUE) return;
            if (install(h, false) != want) return;   // dense from 0, so this holds
        }
    }

    // Handle backing guest fd `g`, or nullopt (EBADF).
    [[nodiscard]] std::optional<HANDLE> host(int g) const noexcept {
        if (g < 0 || std::size_t(g) >= slots_.size()) return std::nullopt;
        const Slot& s = slots_[std::size_t(g)];
        if (!s.file) return std::nullopt;
        return s.file->get();
    }

    // Adopt a freshly opened handle under the lowest free guest fd (POSIX's
    // lowest-free rule, which real programs depend on).
    [[nodiscard]] int install(HANDLE h, bool cloexec) {
        auto file = std::make_shared<WinFd>(h);
        for (std::size_t g = 0; g < slots_.size(); ++g)
            if (!slots_[g].file) {
                slots_[g] = Slot{std::move(file), cloexec};
                return int(g);
            }
        if (slots_.size() >= kMaxFds) return -win32::LMFILE;
        slots_.push_back(Slot{std::move(file), cloexec});
        return int(slots_.size() - 1);
    }

    // close(g): drop this guest fd's reference. EBADF if unknown.
    [[nodiscard]] int close(int g) {
        if (!host(g)) return -win32::LBADF;
        slots_[std::size_t(g)] = Slot{};
        return 0;
    }

    // dup(g) -> lowest free; dup2/dup3(g, to) -> exactly `to`.
    [[nodiscard]] int dup(int g, std::optional<int> to, bool cloexec) {
        if (!host(g)) return -win32::LBADF;
        const Slot& src = slots_[std::size_t(g)];
        // Share the WinFd, so the file POSITION is shared as Linux requires.
        auto file = src.file;
        const bool append = src.append;
        const bool tty = src.is_tty;
        if (!to) {
            for (std::size_t i = 0; i < slots_.size(); ++i)
                if (!slots_[i].file) {
                    slots_[i] = Slot{std::move(file), cloexec, append, tty};
                    return int(i);
                }
            if (slots_.size() >= kMaxFds) return -win32::LMFILE;
            slots_.push_back(Slot{std::move(file), cloexec, append, tty});
            return int(slots_.size() - 1);
        }
        if (*to < 0 || *to >= kMaxFds) return -win32::LBADF;
        if (*to == g) return g;
        install_at(*to, std::move(file), cloexec);
        slots_[std::size_t(*to)].append = append;
        slots_[std::size_t(*to)].is_tty = tty;
        return *to;
    }

    [[nodiscard]] bool cloexec(int g) const noexcept {
        return host(g) && slots_[std::size_t(g)].cloexec;
    }
    void set_cloexec(int g, bool on) noexcept {
        if (host(g)) slots_[std::size_t(g)].cloexec = on;
    }

    [[nodiscard]] bool is_append(int g) const noexcept {
        return host(g) && slots_[std::size_t(g)].append;
    }
    void set_append(int g, bool on) noexcept {
        if (host(g)) slots_[std::size_t(g)].append = on;
    }

    // isatty(3) / the TCGETS ioctl: a guest libc decides whether to
    // line-buffer based on this, so getting it wrong makes output appear in
    // the wrong order (or not at all until exit).
    [[nodiscard]] bool is_tty(int g) const noexcept {
        return host(g) && slots_[std::size_t(g)].is_tty;
    }
    void set_tty(int g, bool on) noexcept {
        if (host(g)) slots_[std::size_t(g)].is_tty = on;
    }

    // The directory-enumeration cursor for getdents64. Per-fd, not shared by
    // dup, so two fds on one directory do not consume each other's entries.
    [[nodiscard]] DirCursor* dir(int g) noexcept {
        if (!host(g)) return nullptr;
        Slot& s = slots_[std::size_t(g)];
        if (!s.dir) s.dir = std::make_unique<DirCursor>();
        return s.dir.get();
    }

    // The guest path this fd was opened with. openat(dirfd, relative) needs
    // it to rebuild the absolute path, and so does /proc/self/fd.
    void set_path(int g, std::string p) {
        if (host(g)) slots_[std::size_t(g)].path = std::move(p);
    }
    [[nodiscard]] const std::string& path(int g) const noexcept {
        static const std::string empty;
        if (!host(g)) return empty;
        return slots_[std::size_t(g)].path;
    }

    // execve: drop every FD_CLOEXEC descriptor.
    void on_exec() {
        for (auto& s : slots_)
            if (s.cloexec) s = Slot{};
    }

    [[nodiscard]] int count() const noexcept {
        int n = 0;
        for (const auto& s : slots_) if (s.file) ++n;
        return n;
    }

private:
    struct Slot {
        std::shared_ptr<WinFd> file;
        bool cloexec{false};
        bool append{false};
        bool is_tty{false};
        std::string path;
        std::unique_ptr<DirCursor> dir;
    };

    void install_at(int g, std::shared_ptr<WinFd> file, bool cloexec) {
        if (std::size_t(g) >= slots_.size())
            slots_.resize(std::size_t(g) + 1);
        slots_[std::size_t(g)] = Slot{std::move(file), cloexec};
    }

    std::vector<Slot> slots_;
};

} // namespace lx::runtime

#endif // _WIN32
