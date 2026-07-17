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

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

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
    enum Have : std::uint8_t { kMode = 1, kUid = 2, kGid = 4 };
    std::uint8_t have{0};
};

class MetaStore {
public:
    // Point the store at the overlay upper directory. The journal lives at
    // <upper>/.linuxity-meta; if it exists we replay it into memory. Called
    // once at mount time. An empty upper (no COW layer) leaves the store
    // purely in-memory (still coherent within a single run).
    void attach(std::string upper_dir) {
        if (!upper_dir.empty() && upper_dir.back() == '/') upper_dir.pop_back();
        upper_ = std::move(upper_dir);
        if (upper_.empty()) return;
        journal_path_ = upper_ + "/.linuxity-meta";
        replay();
    }

    // The overlay journal filename, relative to the upper dir — the ONE name
    // the directory-union enumeration must hide so the guest never sees it.
    static constexpr std::string_view journal_leaf() noexcept {
        return ".linuxity-meta";
    }

    // Record a guest chmod: the guest-intended permission bits (07777 mask;
    // file-type bits are ignored). Idempotent per path.
    void set_mode(const std::string& guest_path, std::uint32_t mode) {
        auto& r = table_[guest_path];
        r.mode = mode & 07777u;
        r.have |= MetaRecord::kMode;
        append(guest_path, r);
    }

    // Record a guest chown. Either component may be -1 (0xffffffff) meaning
    // "leave unchanged", exactly like chown(2); we then keep the prior value
    // (or root's 0 if none was recorded).
    void set_owner(const std::string& guest_path, std::uint32_t uid,
                   std::uint32_t gid) {
        auto& r = table_[guest_path];
        if (uid != 0xffffffffu) { r.uid = uid; r.have |= MetaRecord::kUid; }
        if (gid != 0xffffffffu) { r.gid = gid; r.have |= MetaRecord::kGid; }
        append(guest_path, r);
    }

    // On rename/link the metadata should travel with the file. Move any record
    // from `from` to `to` (overwriting `to`'s prior record if present).
    void rename(const std::string& from, const std::string& to) {
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
        bool had = table_.erase(guest_path) != 0;
        if (had) append_tombstone(guest_path);
    }

    // The recorded overlay for a path, or nullopt if the guest never touched
    // its metadata (so the host inode's real values stand).
    [[nodiscard]] std::optional<MetaRecord> lookup(
        const std::string& guest_path) const {
        auto it = table_.find(guest_path);
        if (it == table_.end()) return std::nullopt;
        return it->second;
    }

    // Given the mode the HOST inode reports (full st_mode incl. S_IFMT) and
    // this store's record for a path, compute the mode a guest stat should
    // see: the host file-type and any sticky/set-id bits the host managed to
    // keep, unioned with the guest-intended permission bits when recorded.
    [[nodiscard]] static std::uint32_t effective_mode(std::uint32_t host_mode,
                                                      const MetaRecord& r) {
        if (!(r.have & MetaRecord::kMode)) return host_mode;
        // Keep the host's file-type; take the guest's permission+special bits.
        return (host_mode & S_IFMT) | (r.mode & 07777u);
    }

private:
    // Append one record to the journal (line: "<octal-mode> <uid> <gid> <have>
    // <path>\n"). Best-effort and crash-tolerant: a torn tail line is skipped
    // on replay. We rewrite the whole map only rarely (never, in practice —
    // append-only with last-writer-wins on replay keeps it correct and cheap).
    void append(const std::string& path, const MetaRecord& r) {
        if (journal_path_.empty()) return;
        std::FILE* fp = std::fopen(journal_path_.c_str(), "a");
        if (!fp) return;
        std::fprintf(fp, "%o %u %u %u %s\n", r.mode, r.uid, r.gid,
                     static_cast<unsigned>(r.have), path.c_str());
        std::fclose(fp);
    }

    // A TOMBSTONE line (have==0xff sentinel) records a removal: replay drops any
    // record for the path. This keeps append-only journaling accurate across
    // unlink/rmdir/rename without ever rewriting the file.
    void append_tombstone(const std::string& path) {
        if (journal_path_.empty()) return;
        std::FILE* fp = std::fopen(journal_path_.c_str(), "a");
        if (!fp) return;
        std::fprintf(fp, "0 0 0 255 %s\n", path.c_str());
        std::fclose(fp);
    }

    // Replay the journal into memory, last-writer-wins (a later append for the
    // same path supersedes the earlier one — so append-only is self-healing).
    void replay() {
        std::FILE* fp = std::fopen(journal_path_.c_str(), "r");
        if (!fp) return;
        char line[8192];
        while (std::fgets(line, sizeof line, fp)) {
            unsigned mode = 0, uid = 0, gid = 0, have = 0;
            int off = 0;
            // "%o %u %u %u " then the rest (which may contain spaces) is the path.
            if (std::sscanf(line, "%o %u %u %u %n", &mode, &uid, &gid, &have,
                            &off) < 4)
                continue;
            std::string path = line + off;
            while (!path.empty() && (path.back() == '\n' || path.back() == '\r'))
                path.pop_back();
            if (path.empty()) continue;
            if (have == 255u) { table_.erase(path); continue; }  // tombstone
            MetaRecord r;
            r.mode = mode; r.uid = uid; r.gid = gid;
            r.have = static_cast<std::uint8_t>(have);
            table_[path] = r;   // last line for a path wins
        }
        std::fclose(fp);
    }

    std::string upper_;
    std::string journal_path_;
    std::unordered_map<std::string, MetaRecord> table_;
};

} // namespace lx::kernel
