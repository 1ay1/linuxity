// linuxity/runtime/shared/fd_slots.hpp
//
// Guest fd number -> host descriptor: the allocation and lifetime logic, once.
//
// WHY THIS FILE EXISTS. runtime/darwin/fd.hpp and runtime/windows/fd.hpp each
// carry a full FdTable, and the overlapping half is line-for-line identical:
//
//   install()          lowest-free-slot scan, grow, EMFILE at the cap
//   close()            drop the slot, EBADF if unknown
//   dup()/dup2()       share the same underlying file via shared_ptr
//   cloexec/set_cloexec
//   on_exec()          drop every slot whose cloexec bit is set
//   reserve_low_fds()  keep 0/1/2 from being handed out
//
// Only two things genuinely differ: the HANDLE type (`int` on Darwin, `HANDLE`
// on Win32) and the per-slot EXTRA state each backend needs (Darwin tracks an
// eventfd write-end `peer`; Windows tracks append mode, tty-ness, the guest
// path and a directory cursor).
//
// So this is a template over exactly those two axes. Everything a backend
// still owns -- opening a host descriptor, closing it, what "tty" means -- it
// keeps; what it no longer owns is the fd-number bookkeeping, which is where
// the bugs live. An off-by-one in the lowest-free scan, or forgetting to clear
// a slot on close, is the kind of fault that shows up as a guest reading the
// wrong file much later.
//
// POSIX guarantees the LOWEST free descriptor, and real programs depend on it
// (a shell builds pipelines assuming 0/1/2 and then the next free numbers).
// That guarantee is implemented here once rather than twice.
#pragma once

#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

#include "linuxity/abi/result.hpp"

namespace lx::runtime {

// `File` is the backend's reference-counted host descriptor (HostFd / WinFd).
// `Extra` is whatever else that backend keeps per slot; it must be default
// constructible and is otherwise opaque here.
template <class File, class Extra>
class FdSlots {
public:
    // Matches the RLIMIT_NOFILE linuxity reports to the guest. A guest that
    // raises its own limit past this gets EMFILE, which is honest: we cannot
    // hand out a descriptor we have no slot for.
    static constexpr int kMaxFds = 1024;

    struct Slot {
        std::shared_ptr<File> file;
        bool                  cloexec{false};
        Extra                 extra{};

        [[nodiscard]] bool occupied() const noexcept { return file != nullptr; }
    };

    // Install at the LOWEST free guest fd -- POSIX requires it, and programs
    // depend on it. Returns the fd, or -EMFILE when the table is full.
    [[nodiscard]] int install(std::shared_ptr<File> file, bool cloexec,
                              Extra extra = {}) {
        for (std::size_t g = 0; g < slots_.size(); ++g) {
            if (!slots_[g].occupied()) {
                slots_[g] = Slot{std::move(file), cloexec, std::move(extra)};
                return static_cast<int>(g);
            }
        }
        if (slots_.size() >= static_cast<std::size_t>(kMaxFds))
            return -static_cast<int>(Errno::emfile);
        slots_.push_back(Slot{std::move(file), cloexec, std::move(extra)});
        return static_cast<int>(slots_.size() - 1);
    }

    // Install at a SPECIFIC guest fd (dup2, and the 0/1/2 seeding), growing
    // the table if needed. Any existing occupant is replaced, which is dup2's
    // defined behaviour: it closes the target first.
    void install_at(int g, std::shared_ptr<File> file, bool cloexec,
                    Extra extra = {}) {
        if (g < 0) return;
        const auto i = static_cast<std::size_t>(g);
        if (i >= slots_.size()) slots_.resize(i + 1);
        slots_[i] = Slot{std::move(file), cloexec, std::move(extra)};
    }

    [[nodiscard]] int close(int g) {
        Slot* s = at(g);
        if (!s || !s->occupied()) return -static_cast<int>(Errno::ebadf);
        *s = Slot{};
        return 0;
    }

    // dup: share the same underlying file, so both fds see one file offset --
    // that shared offset is the whole point of dup, and copying the File
    // instead of the pointer would silently give each fd its own.
    //
    // The per-slot Extra is NOT copied implicitly, because a backend's Extra
    // may be move-only: Windows keeps a `unique_ptr<DirCursor>` there. (The
    // compiler proved this -- a `dup()` that copied Extra simply failed to
    // instantiate for a move-only one.) So the caller passes the Extra the
    // new slot should get, which also forces the real question to be answered
    // explicitly: a dup'd DIRECTORY fd needs its OWN enumeration cursor, not
    // a shared one, or two fds reading the same directory consume each
    // other's entries.
    [[nodiscard]] int dup(int from, bool cloexec, Extra extra = {}) {
        Slot* s = at(from);
        if (!s || !s->occupied()) return -static_cast<int>(Errno::ebadf);
        auto file = s->file;
        return install(std::move(file), cloexec, std::move(extra));
    }

    // dup2/dup3: a FIXED target. Returns the target, or EBADF if the source
    // is unknown. Dup'ing a fd onto itself is a documented no-op that must
    // NOT clear the cloexec bit.
    [[nodiscard]] int dup_to(int from, int to, bool cloexec, Extra extra = {}) {
        Slot* s = at(from);
        if (!s || !s->occupied()) return -static_cast<int>(Errno::ebadf);
        if (from == to) return to;
        auto file = s->file;
        install_at(to, std::move(file), cloexec, std::move(extra));
        return to;
    }

    [[nodiscard]] Slot* at(int g) noexcept {
        if (g < 0) return nullptr;
        const auto i = static_cast<std::size_t>(g);
        return i < slots_.size() ? &slots_[i] : nullptr;
    }
    [[nodiscard]] const Slot* at(int g) const noexcept {
        if (g < 0) return nullptr;
        const auto i = static_cast<std::size_t>(g);
        return i < slots_.size() ? &slots_[i] : nullptr;
    }

    [[nodiscard]] bool valid(int g) const noexcept {
        const Slot* s = at(g);
        return s && s->occupied();
    }

    [[nodiscard]] bool cloexec(int g) const noexcept {
        const Slot* s = at(g);
        return s && s->occupied() && s->cloexec;
    }

    void set_cloexec(int g, bool on) noexcept {
        if (Slot* s = at(g); s && s->occupied()) s->cloexec = on;
    }

    // execve: every descriptor with close-on-exec set is dropped. Missing
    // this leaks fds into the new image -- which is a real sandbox concern,
    // not just untidiness, since the leaked fd may be outside the guest root.
    void on_exec() {
        for (auto& s : slots_)
            if (s.occupied() && s.cloexec) s = Slot{};
    }

    // NOTE: reserving the low fds is deliberately NOT here. Both backends do
    // it by OPENING real host descriptors (/dev/null) for 0..8, because the
    // point is that a later open() cannot be handed a low number -- an empty
    // slot would still be handed out by the lowest-free scan above. Opening a
    // host descriptor is a host operation, so it stays in the backend; only
    // the numbering it relies on lives here.

    [[nodiscard]] std::size_t size() const noexcept { return slots_.size(); }
    [[nodiscard]] std::vector<Slot>& raw() noexcept { return slots_; }
    [[nodiscard]] const std::vector<Slot>& raw() const noexcept { return slots_; }

private:
    std::vector<Slot> slots_;
};

} // namespace lx::runtime
