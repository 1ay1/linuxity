// linuxity/kernel/meta_store.hpp
//
// The shadow metadata store: a coherent uid-0 world with per-path permission
// and ownership overlay.
//
// WHY THIS EXISTS
// ---------------
// linuxity runs an UNPRIVILEGED host process but presents the guest a world in
// which it is root. That illusion has two holes the host filesystem can't back:
//
//   * ownership — the rootfs on disk is owned by whoever unpacked it; a guest
//     `chown 1000:1000 f` cannot really change owner (the host process lacks
//     CAP_CHOWN), and a later `stat f` must still report 1000:1000 or package
//     scripts and `tar -p`/`install`/`useradd` verification fail.
//
//   * privileged mode bits — a guest `chmod 04755 f` (setuid) or `chmod 0000 f`
//     may be silently dropped by the host (it can refuse setuid on a file it
//     doesn't own, or clamp bits under a restrictive mount), so a follow-up
//     `stat` sees the HOST mode, not the guest-intended one.
//
// proot solves this with a `.proot-meta-file.<name>` SIDECAR next to every
// touched file. That pollutes the guest-visible tree (every `ls`, every `tar`,
// every checksum must filter the sidecars) and scatters state across the rootfs.
//
// linuxity already has an overlay UPPER directory (the writable scratch layer
// stacked over the read-only rootfs). So we keep a SINGLE consolidated journal
// there — `.linuxity-meta` — that is never part of any guest mount and never
// visible to the guest. In memory it is one hash map: normalized guest path ->
// the guest-intended (mode, uid, gid). On chmod/chown we record; on stat we
// overlay. The journal is append-on-change and reloaded at start, so guest
// permission state survives across runs exactly like the copied-up files do.
//
// This is strictly a SUPERSET of proot's fake_id0 model, minus the tree
// pollution and the per-file open/parse cost.
#pragma once

#include <sys/stat.h>
#include "linuxity/abi/wire/stat.hpp"
#include "linuxity/kernel/journal_tail.hpp"
#include "linuxity/host/win_posix.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace lx::kernel {

// One shadow record. Each field is authoritative ONLY when its bit is set in
// `have`, so a lone `chown` doesn't clobber a mode the guest never set (and
// vice versa). `mode` holds the FULL guest-intended permission bits including
// setuid/setgid/sticky (07000) and the low 0777; it never carries file-TYPE
// bits (S_IFMT) — those always come from the real host inode at stat time.
struct MetaRecord {
    std::uint32_t mode{0};
    std::uint32_t uid{0};
    std::uint32_t gid{0};
    // st_nlink, when a hardlink had to be EMULATED. Some hosts refuse
    // link(2) outright -- Android denies the SELinux `link` permission on
    // /data, for every process -- so linuxity copies the content instead and
    // records here how many names the guest believes share the inode. Zero
    // means "ask the host", which is the normal case.
    std::uint32_t nlink{0};
    enum Have : std::uint8_t { kMode = 1, kUid = 2, kGid = 4, kNlink = 8, kFifo = 16 };
    std::uint8_t have{0};
};

class MetaStore {
public:
    // Point the store at the overlay upper directory. The journal lives at
    // <upper>/.linuxity-meta; if it exists we replay it into memory. Called
    // once at mount time. An empty upper (no COW layer) leaves the store
    // purely in-memory (still coherent within a single run).
    void attach(std::string upper_dir, bool compact = false) {
        if (!upper_dir.empty() && upper_dir.back() == '/') upper_dir.pop_back();
        upper_ = std::move(upper_dir);
        if (upper_.empty()) return;
        journal_path_ = upper_ + "/.linuxity-meta";
        const std::size_t lines = replay();
        // Root-only: drop records the host inode already satisfies (written
        // by older versions before set_mode checked the landed mode), and a
        // mode on a symlink (always 0777, never consulted). One lstat per
        // record -- so only when the journal changed since the last pass
        // left it clean (its size then is in <upper>/.linuxity-meta.ok).
        std::size_t pruned = 0;
        if (compact && journal_size() == clean_size()) compact = false;
        if (compact) {
            for (auto it = table_.begin(); it != table_.end();) {
                MetaRecord& r = it->second;
                if (r.have & MetaRecord::kMode) {
                    struct ::stat st{};
                    bool ok = false;
                    for (const std::string& base : host_bases_) {
                        if (::lstat((base + it->first).c_str(), &st) == 0) { ok = true; break; }
                    }
                    if (ok && (S_ISLNK(st.st_mode) || (st.st_mode & abi::wire::kPermMask) == r.mode))
                        r.have &= static_cast<std::uint8_t>(~MetaRecord::kMode);
                }
                if (is_redundant(r)) { it = table_.erase(it); ++pruned; }
                else ++it;
            }
        }
        // The journal is append-only (crash-safe, last writer wins), so it
        // grows without bound: a few pacman upgrades left 148k lines for 18
        // live records, and EVERY fork child replayed all of it -- 8.5 MB
        // parsed per fork, most of screenfetch's 10 s. The root process
        // rewrites it to the live set (atomically: temp + rename) when it
        // is mostly dead weight.
        if (compact && (pruned || (lines > 1024 && lines > table_.size() * 4))) rewrite();
        if (compact) note_clean();
    }
    // The journal's size, or -1.
    [[nodiscard]] long long journal_size() const {
        struct ::stat st{};
        return ::stat(journal_path_.c_str(), &st) == 0 ? static_cast<long long>(st.st_size) : -1;
    }
    // The size the journal had when a compaction pass last found it clean.
    [[nodiscard]] long long clean_size() const {
        long long v = -2;
        if (std::FILE* f = std::fopen((journal_path_ + ".ok").c_str(), "r")) {
            if (std::fscanf(f, "%lld", &v) != 1) v = -2;
            std::fclose(f);
        }
        return v;
    }
    void note_clean() const {
        const std::string tmp = journal_path_ + ".ok.tmp";
        if (std::FILE* f = std::fopen(tmp.c_str(), "w")) {
            std::fprintf(f, "%lld\n", journal_size());
            std::fclose(f);
            (void)std::rename(tmp.c_str(), (journal_path_ + ".ok").c_str());
        }
    }
    // Host directories a guest path may live in (upper first, then lower),
    // for compaction's "does the inode already carry this mode" check.
    void set_host_bases(std::vector<std::string> b) { host_bases_ = std::move(b); }

    // The overlay journal filename, relative to the upper dir — the ONE name
    // the directory-union enumeration must hide so the guest never sees it.
    static constexpr std::string_view journal_leaf() noexcept {
        return ".linuxity-meta";
    }

    // Record a guest chmod: the guest-intended permission bits (07777 mask;
    // file-type bits are ignored). Idempotent per path.
    //
    // `host_mode` (if known) is what the host inode carries AFTER the caller
    // applied the chmod to it. When the inode already holds exactly the
    // requested bits, and no owner is recorded, the overlay adds nothing --
    // stat reads the inode -- so nothing is journaled. Ordinary 0644/0755
    // chmods from package installs (13k of them here) all land in this case.
    void set_mode(const std::string& guest_path, std::uint32_t mode,
                  std::uint32_t host_mode = 0xffffffffu) {
        catch_up();
        if (host_mode != 0xffffffffu && (host_mode & abi::wire::kPermMask) == (mode & abi::wire::kPermMask)) {
            auto it = table_.find(guest_path);
            if (it == table_.end()) return;
            it->second.have &= static_cast<std::uint8_t>(~MetaRecord::kMode);
            if (is_redundant(it->second)) { table_.erase(it); append_tombstone(guest_path); }
            else append(guest_path, it->second);
            return;
        }
        auto& r = table_[guest_path];
        r.mode = mode & abi::wire::kPermMask;
        r.have |= MetaRecord::kMode;
        append(guest_path, r);
    }

    // Record a guest chown. Either component may be -1 (0xffffffff) meaning
    // "leave unchanged", exactly like chown(2); we then keep the prior value
    // (or root's 0 if none was recorded).
    //
    // root:root is what every file already reports (the guest runs as uid 0
    // over a world it owns), so chown to 0:0 on a path with no record is a
    // no-op and is NOT journaled. pacman chowns every file it installs to
    // root, which left 53k redundant records that every fork re-parsed.
    void set_owner(const std::string& guest_path, std::uint32_t uid,
                   std::uint32_t gid) {
        catch_up();
        auto it = table_.find(guest_path);
        if (it == table_.end() && (uid == 0 || uid == 0xffffffffu) &&
            (gid == 0 || gid == 0xffffffffu))
            return;
        auto& r = table_[guest_path];
        if (uid != 0xffffffffu) { r.uid = uid; r.have |= MetaRecord::kUid; }
        if (gid != 0xffffffffu) { r.gid = gid; r.have |= MetaRecord::kGid; }
        if (is_redundant(r)) { table_.erase(guest_path); append_tombstone(guest_path); return; }
        append(guest_path, r);
    }

    // A FIFO the host wouldn't let us create (Android forbids them), kept as
    // an empty regular file that the guest sees as S_IFIFO.
    void set_fifo(const std::string& guest_path) {
        catch_up();
        auto& r = table_[guest_path];
        r.have |= MetaRecord::kFifo;
        append(guest_path, r);
    }
    [[nodiscard]] bool is_fifo(const std::string& guest_path) const {
        catch_up();
        auto it = table_.find(guest_path);
        return it != table_.end() && (it->second.have & MetaRecord::kFifo) != 0;
    }

    // A record that says nothing the default view doesn't already: owner
    // root (or unset) and no mode. Such records are dropped.
    [[nodiscard]] static bool is_redundant(const MetaRecord& r) noexcept {
        const bool owner_default = (!(r.have & MetaRecord::kUid) || r.uid == 0) &&
                                   (!(r.have & MetaRecord::kGid) || r.gid == 0);
        return owner_default && !(r.have & MetaRecord::kMode) &&
               !(r.have & MetaRecord::kNlink) && !(r.have & MetaRecord::kFifo);
    }

    // On rename/link the metadata should travel with the file. Move any record
    // from `from` to `to` (overwriting `to`'s prior record if present).
    void rename(const std::string& from, const std::string& to) {
        catch_up();
        auto it = table_.find(from);
        // Always journal the removal of `to`'s and `from`'s old state so a
        // replay reconstructs the post-rename world exactly (even if `from`
        // had no record, `to`'s prior record must be cleared).
        if (it == table_.end()) { forget(to); table_.erase(from); return; }
        MetaRecord rec = it->second;
        table_.erase(it);
        table_[to] = rec;
        append_tombstone(from);
        append(to, rec);
    }

    // Drop a record (unlink/rmdir): future stats of a re-created file at the
    // same path start fresh at the host defaults. Journaled as a tombstone so
    // a later replay does NOT resurrect the stale record.
    void forget(const std::string& guest_path) {
        catch_up();
        bool had = table_.erase(guest_path) != 0;
        if (had) append_tombstone(guest_path);
    }

    // Nothing recorded at all (after catching up once): the common case,
    // which lets a per-component walk skip every lookup.
    [[nodiscard]] bool empty() const { catch_up(); return table_.empty(); }
    // The record for a path in the table as it stands (no catch-up): for a
    // walk that already caught up through empty().
    [[nodiscard]] const MetaRecord* peek(const std::string& guest_path) const {
        auto it = table_.find(guest_path);
        return it == table_.end() ? nullptr : &it->second;
    }

    // The recorded overlay for a path, or nullopt if the guest never touched
    // its metadata (so the host inode's real values stand).
    //
    // The journal is the store's truth and the table a cache of it. Where
    // every guest process is its own linuxity (macOS: fork = new process),
    // each has its own cache, so it first catches up on lines OTHER
    // processes appended -- or `su nobody -c 'touch f'` would leave the
    // parent seeing f as root's. One stat when nothing changed.
    [[nodiscard]] std::optional<MetaRecord> lookup(
        const std::string& guest_path) const {
        catch_up();
        auto it = table_.find(guest_path);
        if (it == table_.end()) return std::nullopt;
        return it->second;
    }

    // Every path with a record, and a sink for paths given one from now on
    // (the in-guest handler must leave those to the dispatcher).
    template <class F> void for_each_path(F&& f) const {
        catch_up();
        for (const auto& [p, r] : table_) f(p);
    }
    void set_change_log(std::vector<std::string>* log) { changed_ = log; }

    // Given the mode the HOST inode reports (full st_mode incl. S_IFMT) and
    // this store's record for a path, compute the mode a guest stat should
    // see: the host file-type and any sticky/set-id bits the host managed to
    // keep, unioned with the guest-intended permission bits when recorded.
    [[nodiscard]] static std::uint32_t effective_mode(std::uint32_t host_mode,
                                                      const MetaRecord& r) {
        // the placeholder is a regular file on the host; anything else there
        // now replaced it and says what it is
        if ((r.have & MetaRecord::kFifo) && (host_mode & abi::wire::kFileTypeMask) == 0100000u)
            host_mode = (host_mode & ~abi::wire::kFileTypeMask) | 0010000u;
        if (!(r.have & MetaRecord::kMode)) return host_mode;
        // Keep the host's file-type; take the guest's permission+special bits.
        return (host_mode & abi::wire::kFileTypeMask) | (r.mode & abi::wire::kPermMask);
    }

private:
    // Append one record to the journal (line: "<octal-mode> <uid> <gid> <have>
    // <path>\n"). Best-effort and crash-tolerant: a torn tail line is skipped
    // on replay. We rewrite the whole map only rarely (never, in practice —
    // append-only with last-writer-wins on replay keeps it correct and cheap).
    void append(const std::string& path, const MetaRecord& r) {
        if (changed_) changed_->push_back(path);
        if (journal_path_.empty()) return;
        std::FILE* fp = std::fopen(journal_path_.c_str(), "a");
        if (!fp) return;
        write_line(fp, path, r);
        std::fclose(fp);
        // seen_ is NOT advanced: another process may have appended before
        // us, and jumping to the end would skip its line (a parent kept the
        // stale owner a child had just changed). The next catch_up replays
        // from seen_ -- theirs and ours; ours again is harmless, last wins.
    }

    // nlink goes LAST and only when set, so a journal written before this
    // field existed still parses (the reader asks for 4 fields and takes
    // a 5th if it is there) and the common record stays the same size.
    static void write_line(std::FILE* fp, const std::string& path, const MetaRecord& r) {
        if ((r.have & MetaRecord::kNlink) != 0)
            std::fprintf(fp, "%o %u %u %u %u %s\n", r.mode, r.uid, r.gid,
                         static_cast<unsigned>(r.have), r.nlink, path.c_str());
        else
            std::fprintf(fp, "%o %u %u %u %s\n", r.mode, r.uid, r.gid,
                         static_cast<unsigned>(r.have), path.c_str());
    }

    // A TOMBSTONE line (have==0xff sentinel) records a removal: replay drops any
    // record for the path. This keeps append-only journaling accurate across
    // unlink/rmdir/rename without ever rewriting the file.
    void append_tombstone(const std::string& path) {
        if (journal_path_.empty()) return;
        std::FILE* fp = std::fopen(journal_path_.c_str(), "a");
        if (!fp) return;
        std::fprintf(fp, "0 0 0 255 %s\n", path.c_str());
        std::fclose(fp);   // seen_ stays: see append
    }

    // Fold in what other processes appended (kernel/journal_tail.hpp: one
    // stat when nothing changed; a replaced journal is read whole).
    void catch_up() const {
        (void)tail_.follow([this] { table_.clear(); },
                           [this](std::string_view l) { apply_line(l); });
    }
    std::size_t replay() {
        tail_.set_path(journal_path_);
        return tail_.reload([this] { table_.clear(); },
                            [this](std::string_view l) { apply_line(l); });
    }
    // One journal line: "%o %u %u %u [nlink] path", or a tombstone.
    void apply_line(std::string_view sv) const {
        const std::string line{sv};
        unsigned mode = 0, uid = 0, gid = 0, have = 0;
        int off = 0;
        // "%o %u %u %u " then the rest (which may contain spaces) is the
        // path -- unless `have` says a 5th number (nlink) comes first.
        if (std::sscanf(line.c_str(), "%o %u %u %u %n", &mode, &uid, &gid, &have, &off) < 4) return;
        unsigned nlink = 0;
        if (have != 255u && (have & MetaRecord::kNlink) != 0) {
            int off2 = 0;
            if (std::sscanf(line.c_str() + off, "%u %n", &nlink, &off2) == 1) off += off2;
        }
        std::string path = line.substr(static_cast<std::size_t>(off));
        if (path.empty()) return;
        if (have == 255u) { table_.erase(path); return; }   // tombstone
        MetaRecord r;
        r.mode = mode; r.uid = uid; r.gid = gid; r.nlink = nlink;
        r.have = static_cast<std::uint8_t>(have);
        if (is_redundant(r)) { table_.erase(path); return; }
        table_[path] = r;   // last line for a path wins
    }

    std::string upper_;
    std::vector<std::string> host_bases_;
    std::string journal_path_;
    // A cache of the journal (see lookup); mutable so a const lookup can
    // catch up on other processes' appends.
    mutable std::unordered_map<std::string, MetaRecord> table_;
    mutable JournalTail tail_;           // how much of the journal table_ holds
    std::vector<std::string>* changed_{nullptr};

    // Rewrite the journal to exactly the live records, atomically.
    void rewrite() {
        const std::string tmp = journal_path_ + ".tmp";
        std::FILE* fp = std::fopen(tmp.c_str(), "w");
        if (!fp) return;
        for (const auto& [path, r] : table_) write_line(fp, path, r);
        if (std::fclose(fp) == 0) std::rename(tmp.c_str(), journal_path_.c_str());
        else std::remove(tmp.c_str());
        // the table IS this file now: don't re-read it as someone else's
        tail_.adopt();
    }
};

} // namespace lx::kernel
