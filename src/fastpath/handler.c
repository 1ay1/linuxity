/* In-guest fast path: answers read-only path queries (stat, statx,
 * readlink, get/list xattr) the way the supervisor would, without a ptrace
 * stop. Freestanding: no libc, general registers only, no writable data.
 *
 * It is only a shortcut. Anything it can't prove it answers exactly like the
 * supervisor (a symlink to follow, a chmod'd file, a virtual mount, a
 * relative path with no known cwd, an unusual error) returns LX_FP_FALLBACK
 * and the stub runs the real syscall, which traps as before.
 */
#include <stddef.h>
#include <stdint.h>

#include "linuxity/runtime/linux/fastpath_abi.h"

#define AT_FDCWD_ (-100)
#define AT_SYMLINK_NOFOLLOW_ 0x100
#define AT_NO_AUTOMOUNT_ 0x800
#define AT_EMPTY_PATH_ 0x1000
#define AT_STATX_SYNC_MASK_ 0x6000

#define ENOENT_ 2
#define EINVAL_ 22
#define ERANGE_ 34
#define ENODATA_ 61
#define ENOTSUP_ 95

#define S_IFMT_ 0170000u
#define S_IFLNK_ 0120000u

#if defined(__x86_64__)
enum {
    NR_stat = 4, NR_lstat = 6, NR_newfstatat = 262, NR_statx = 332,
    NR_readlink = 89, NR_readlinkat = 267,
    NR_getxattr = 191, NR_lgetxattr = 192, NR_listxattr = 194, NR_llistxattr = 195,
    NR_rt_sigprocmask = 14, NR_getpid = 39, NR_fstat = 5,
};
struct kstat {
    uint64_t dev, ino, nlink;
    uint32_t mode, uid, gid, pad0;
    uint64_t rdev;
    int64_t size, blksize, blocks;
    uint64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
    int64_t reserved[3];
};
/* lx_fp_common's frame, from the pointer it passes: rax rdi rsi rdx r10 r8 r9
   pushed in that order, so arg i sits at index 5 - i. */
#define ARG(f, i) ((f)[5 - (i)])
#elif defined(__aarch64__)
enum {
    NR_stat = -1, NR_lstat = -2, NR_newfstatat = 79, NR_statx = 291,
    NR_readlink = -3, NR_readlinkat = 78,
    NR_getxattr = 8, NR_lgetxattr = 9, NR_listxattr = 11, NR_llistxattr = 12,
    NR_rt_sigprocmask = 135, NR_getpid = 172, NR_fstat = 80,
};
struct kstat {
    uint64_t dev, ino;
    uint32_t mode, nlink, uid, gid;
    uint64_t rdev, pad1;
    int64_t size;
    int32_t blksize, pad2;
    int64_t blocks;
    int64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
    uint32_t unused[2];
};
#define ARG(f, i) ((f)[(i)])
#else
#error "fast path: x86-64 and aarch64 only"
#endif

struct kstatx_ts { int64_t sec; uint32_t nsec; int32_t pad; };
struct kstatx {
    uint32_t mask, blksize;
    uint64_t attributes;
    uint32_t nlink, uid, gid;
    uint16_t mode, spare0;
    uint64_t ino, size, blocks, attributes_mask;
    struct kstatx_ts atime, btime, ctime, mtime;
    uint32_t rdev_major, rdev_minor, dev_major, dev_minor;
    uint64_t mnt_id, spare2;
    uint64_t spare3[12];
};
_Static_assert(sizeof(struct kstatx) == 256, "statx layout");

/* entry asm */
char* lx_fp_base(void);
long lx_fp_gate(long nr, long a0, long a1, long a2, long a3, const uint64_t* key);
long lx_fp_copy(void* dst, const void* src, unsigned long n);
long lx_fp_strcpy(char* dst, const char* src, unsigned long max);
long lx_fp_on_stack(long (*fn)(void*), void* arg, void* top);

#define FALLBACK LX_FP_FALLBACK

static inline uint32_t load_acq(const uint32_t* p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
static inline uint64_t load_acq64(const uint64_t* p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }

static void zero(void* p, unsigned long n) {
    volatile char* c = (volatile char*)p;
    while (n--) *c++ = 0;
}
static void move(char* d, const char* s, unsigned long n) {
    while (n--) *d++ = *s++;
}
/* The compiler may turn struct copies into these calls. */
void* memcpy(void* d, const void* s, unsigned long n) {
    volatile char* dc = (volatile char*)d;
    const volatile char* sc = (const volatile char*)s;
    while (n--) *dc++ = *sc++;
    return d;
}
void* memset(void* d, int c, unsigned long n) {
    volatile char* dc = (volatile char*)d;
    while (n--) *dc++ = (char)c;
    return d;
}

#define FNV_INIT 1469598103934665603ULL
static inline uint64_t fnv_step(uint64_t h, unsigned char c) { return (h ^ c) * 1099511628211ULL; }
static inline uint64_t fnv_finish(uint64_t h, uint32_t n) {
    h ^= (uint64_t)n << 56;
    return h ? h : 1;
}

struct env {
    const struct lx_fp_table* t;
    struct lx_fp_proc* p;
    const struct lx_fp_fd* fds;
    struct lx_fp_stats* s;
    const uint64_t* key;
};

static int exc_has(const struct env* e, uint64_t h) {
    const uint64_t* x = e->t->exc;
    const uint32_t i = (uint32_t)h & (LX_FP_EXC_SLOTS - 1);
    for (uint32_t k = 0; k < LX_FP_PROBES; ++k) {
        const uint64_t v = load_acq64(&x[(i + k) & (LX_FP_EXC_SLOTS - 1)]);
        if (v == h) return 1;
        if (v == 0) return 0;
    }
    return 1;   /* a long run: can't tell, so assume it is there */
}

static int dir_clean(const struct env* e, uint64_t h, uint32_t len) {
    const uint32_t gen = load_acq(&e->t->dir_gen);
    const uint32_t i = (uint32_t)h & (LX_FP_DIR_SLOTS - 1);
    for (uint32_t k = 0; k < LX_FP_PROBES; ++k) {
        const struct lx_fp_dir* d = &e->t->dirs[(i + k) & (LX_FP_DIR_SLOTS - 1)];
        const uint32_t g1 = load_acq(&d->gen);
        if (g1 == 0) return 0;
        const uint64_t dh = load_acq64(&d->hash);
        const uint32_t dl = d->len;
        if (load_acq(&d->gen) != g1) return 0;
        if (g1 == gen && dh == h && dl == len) return 1;
    }
    return 0;
}

/* "/a/b": absolute, no empty, "." or ".." component, no trailing slash.
   Anything else is the supervisor's business. */
static int canonical(const char* p, uint32_t n) {
    if (n == 0 || p[0] != '/') return 0;
    if (n == 1) return 1;
    if (p[n - 1] == '/') return 0;
    for (uint32_t i = 0; i < n; ++i) {
        if (p[i] != '/') continue;
        const char* c = p + i + 1;
        const uint32_t left = n - i - 1;
        if (left == 0 || c[0] == '/') return 0;
        if (c[0] == '.' && (left == 1 || c[1] == '/')) return 0;
        if (c[0] == '.' && left >= 2 && c[1] == '.' && (left == 2 || c[2] == '/')) return 0;
    }
    return 1;
}

static const struct lx_fp_mount* deepest(const struct env* e, const char* p, uint32_t n) {
    const struct lx_fp_mount* best = 0;
    uint32_t best_len = 0;
    const uint32_t nm = e->t->n_mounts;
    for (uint32_t i = 0; i < nm && i < LX_FP_MAX_MOUNTS; ++i) {
        const struct lx_fp_mount* m = &e->t->mounts[i];
        const uint32_t pl = m->prefix_len;
        int match;
        if (pl == 1 && m->prefix[0] == '/') {
            match = 1;
        } else {
            match = pl <= n && (pl == n || p[pl] == '/');
            for (uint32_t k = 0; match && k < pl; ++k) match = p[k] == m->prefix[k];
        }
        if (match && pl >= best_len) { best = m; best_len = pl; }
    }
    return best;
}

/* base + "/" + rel, like FileNamespace::join_host. */
static int join(char* out, const char* base, uint32_t bl, const char* rel, uint32_t rl) {
    if (bl + 1 + rl + 1 > LX_FP_HOST_MAX) return -1;
    move(out, base, bl);
    uint32_t n = bl;
    if (rl) {
        if (n == 0 || out[n - 1] != '/') out[n++] = '/';
        move(out + n, rel, rl);
        n += rl;
    }
    out[n] = 0;
    return (int)n;
}

static uint32_t dev_major(uint64_t d) { return (uint32_t)(((d >> 8) & 0xfffu) | ((d >> 32) & 0xfffff000u)); }
static uint32_t dev_minor(uint64_t d) { return (uint32_t)((d & 0xffu) | ((d >> 12) & 0xffffff00u)); }

static int starts_dir(const char* p, int n, const char* d, int dn) {
    if (n < dn) return 0;
    for (int i = 0; i < dn; ++i) if (p[i] != d[i]) return 0;
    return n == dn || p[dn] == '/';
}
static int host_special(const char* p, int n) {
    return starts_dir(p, n, "/proc", 5) || starts_dir(p, n, "/dev", 4);
}

struct ctx { const struct env* e; uint64_t* frame; long nr; };

enum op { OP_STAT, OP_STATX, OP_READLINK, OP_XATTR };

/* The fd map entry for `fd`, if the fd still refers to the same file:
   copies its path into `out` (NUL-terminated) and returns its length, or
   -1. `st` gets the fd's own host stat. */
static long fd_path(const struct env* e, long fd, char* out, struct kstat* st, int want_dir) {
    if (fd < 0 || fd >= (long)LX_FP_FDS) return -1;
    const struct lx_fp_fd* ent = &e->fds[fd];
    const uint32_t s1 = load_acq(&ent->seq);
    const uint32_t len = ent->len;
    if ((s1 & 1) || len == 0 || len >= LX_FP_FD_PATH) return -1;
    if (want_dir && !ent->is_dir) return -1;
    if (ent->gen != load_acq(&e->t->dir_gen)) return -1;
    const uint64_t dev = ent->dev, ino = ent->ino;
    move(out, ent->path, len);
    out[len] = 0;
    if (load_acq(&ent->seq) != s1) return -1;
    if (lx_fp_gate(NR_fstat, fd, (long)st, 0, 0, e->key) != 0) return -1;
    if (st->dev != dev || st->ino != ino) return -1;
    return (long)len;
}

static long work(void* arg) {
    const struct ctx* c = (const struct ctx*)arg;
    const struct env* e = c->e;
    uint64_t* f = c->frame;
    const long nr = c->nr;

    enum op op;
    long dirfd = AT_FDCWD_;
    uint64_t path_ptr = 0, buf, size = 0, name = 0;
    int follow = 1;
    int by_fd = 0;   /* stat the fd itself (fstat, AT_EMPTY_PATH with "") */
    if (nr == NR_stat || nr == NR_lstat) {
        op = OP_STAT; path_ptr = ARG(f, 0); buf = ARG(f, 1); follow = nr == NR_stat;
    } else if (nr == NR_fstat) {
        op = OP_STAT; dirfd = (long)(int)ARG(f, 0); buf = ARG(f, 1); by_fd = 1;
    } else if (nr == NR_newfstatat) {
        op = OP_STAT; dirfd = (long)(int)ARG(f, 0); path_ptr = ARG(f, 1); buf = ARG(f, 2);
        const long flags = (long)(int)ARG(f, 3);
        if (flags & ~(AT_SYMLINK_NOFOLLOW_ | AT_NO_AUTOMOUNT_ | AT_EMPTY_PATH_)) return FALLBACK;
        follow = !(flags & AT_SYMLINK_NOFOLLOW_);
        by_fd = (flags & AT_EMPTY_PATH_) != 0;
    } else if (nr == NR_statx) {
        op = OP_STATX; dirfd = (long)(int)ARG(f, 0); path_ptr = ARG(f, 1); buf = ARG(f, 4);
        const long flags = (long)(int)ARG(f, 2);
        if (flags & ~(AT_SYMLINK_NOFOLLOW_ | AT_NO_AUTOMOUNT_ | AT_EMPTY_PATH_ | AT_STATX_SYNC_MASK_))
            return FALLBACK;
        follow = !(flags & AT_SYMLINK_NOFOLLOW_);
        by_fd = (flags & AT_EMPTY_PATH_) != 0;
    } else if (nr == NR_readlink) {
        op = OP_READLINK; path_ptr = ARG(f, 0); buf = ARG(f, 1); size = ARG(f, 2); follow = 0;
    } else if (nr == NR_readlinkat) {
        op = OP_READLINK; dirfd = (long)(int)ARG(f, 0); path_ptr = ARG(f, 1);
        buf = ARG(f, 2); size = ARG(f, 3); follow = 0;
    } else if (nr == NR_getxattr || nr == NR_lgetxattr) {
        op = OP_XATTR; path_ptr = ARG(f, 0); name = ARG(f, 1); buf = ARG(f, 2); size = ARG(f, 3);
        follow = nr == NR_getxattr;
    } else if (nr == NR_listxattr || nr == NR_llistxattr) {
        op = OP_XATTR; path_ptr = ARG(f, 0); buf = ARG(f, 1); size = ARG(f, 2);
        follow = nr == NR_listxattr;
    } else {
        return FALLBACK;
    }
    if (op == OP_READLINK && (long)size <= 0) return FALLBACK;

    const uint32_t seq = load_acq(&e->t->seq);
    if (seq & 1) return FALLBACK;

    /* the guest path, made absolute */
    char g[LX_FP_PATH_MAX];
    long n;
    int dir_check = 0;  /* g's parent must be fst's inode */
    struct kstat fst;   /* the fd's own stat, when there is an fd */
    if (path_ptr) {
        n = lx_fp_strcpy(g, (const char*)path_ptr, LX_FP_PATH_MAX - 1);
        if (n < 0 || n >= (long)LX_FP_PATH_MAX - 1) return FALLBACK;
        g[n] = 0;
    } else {
        n = 0;
        g[0] = 0;
    }
    if (n == 0) {
        /* only "the fd itself" makes an empty path legal */
        if (!by_fd || dirfd < 0) return FALLBACK;
        n = fd_path(e, dirfd, g, &fst, 0);
        if (n <= 0) return FALLBACK;
        by_fd = 2;   /* answer from fst, the fd's real inode */
    } else if (g[0] != '/' && dirfd >= 0) {
        /* relative to a directory fd, if its recorded path still names the
           directory it has open (a rename moves the dir away from the name) */
        char d[LX_FP_FD_PATH];
        const long dl = fd_path(e, dirfd, d, &fst, 1);
        if (dl <= 0) return FALLBACK;
        dir_check = 1;
        const uint32_t lead = dl == 1 ? 1 : (uint32_t)dl + 1;
        if (lead + (uint32_t)n >= LX_FP_PATH_MAX) return FALLBACK;
        for (long i = n; i >= 0; --i) g[i + lead] = g[i];
        move(g, d, (unsigned long)dl);
        g[lead - 1] = '/';
        n += lead;
    } else if (g[0] != '/') {
        if (dirfd != AT_FDCWD_) return FALLBACK;
        const long tg = lx_fp_gate(NR_getpid, 0, 0, 0, 0, e->key);
        if (tg <= 0) return FALLBACK;
        const struct lx_fp_cwd* cw = 0;
        const uint32_t start = (uint32_t)tg & (LX_FP_CWD_SLOTS - 1);
        for (uint32_t k = 0; k < LX_FP_CWD_SLOTS; ++k) {
            const struct lx_fp_cwd* c = &e->t->cwds[(start + k) & (LX_FP_CWD_SLOTS - 1)];
            const int32_t t = __atomic_load_n(&c->tgid, __ATOMIC_ACQUIRE);
            if (t == (int32_t)tg) { cw = c; break; }
            if (t == 0) break;
        }
        if (!cw) return FALLBACK;
        const uint32_t s1 = load_acq(&cw->seq);
        const uint32_t cl = cw->len;
        if ((s1 & 1) || cl == 0 || cl >= LX_FP_CWD_MAX || cl + 1 + (uint32_t)n >= LX_FP_PATH_MAX)
            return FALLBACK;
        const uint32_t lead = cl == 1 ? 1 : cl + 1;   /* cwd "/" needs no extra slash */
        for (long i = n; i >= 0; --i) g[i + lead] = g[i];
        move(g, cw->path, cl);
        g[lead - 1] = '/';
        n += lead;
        if (load_acq(&cw->seq) != s1 || __atomic_load_n(&cw->tgid, __ATOMIC_ACQUIRE) != (int32_t)tg)
            return FALLBACK;
    }
    const uint32_t gn = (uint32_t)n;
    if (!canonical(g, gn)) return FALLBACK;

    /* paths the supervisor answers differently: a removed path or one
       under it, a chmod/chown record, a socket placeholder */
    {
        uint64_t h = FNV_INIT;
        for (uint32_t i = 0; i < gn; ++i) {
            if (g[i] == '/' && i > 0 && exc_has(e, fnv_finish(h, i))) return FALLBACK;
            h = fnv_step(h, (unsigned char)g[i]);
        }
        const uint64_t full = fnv_finish(h, gn);
        if (exc_has(e, full) || exc_has(e, full ^ LX_FP_LEAF_SALT)) return FALLBACK;
    }

    const struct lx_fp_mount* m = deepest(e, g, gn);
    if (!m || m->kind == LX_FP_MNT_VIRTUAL) return FALLBACK;
    const uint32_t pl = m->prefix_len;
    const uint32_t skip = pl == 1 ? 0 : pl;
    const char* rel = g + skip;
    uint32_t rl = gn - skip;
    while (rl && rel[0] == '/') { ++rel; --rl; }

    /* every directory on the way must be one the supervisor walked and found
       free of symlinks (merged-/usr's /lib is a link it follows itself) */
    {
        uint32_t last = 0;
        for (uint32_t i = 0; i < gn; ++i) if (g[i] == '/') last = i;
        if (last > skip && !dir_clean(e, lx_fp_hash(g, last), last)) return FALLBACK;
    }

    char up[LX_FP_HOST_MAX], lo[LX_FP_HOST_MAX];
    int upn = -1;
    const int lon = join(lo, m->base, m->base_len, rel, rl);
    if (lon < 0) return FALLBACK;
    /* a host /proc or /dev path reads differently from here than from the
       supervisor (/proc/self); the dispatcher redirects those */
    if (host_special(lo, lon)) return FALLBACK;
    if (m->kind == LX_FP_MNT_OVERLAY) {
        upn = join(up, m->upper, m->upper_len, rel, rl);
        if (upn < 0 || host_special(up, upn)) return FALLBACK;
    }

    /* pick the layer with an lstat, as the supervisor's probe does; an fd
       stat is the fd's own inode, whichever layer it was opened in */
    struct kstat st;
    const char* hp = lo;
    int hn = lon;
    long r = -ENOENT_;
    if (dir_check) {
        /* the leaf's parent, in either layer, must be the dir the fd has
           open; otherwise the name now means another directory */
        int ok = 0;
        for (int layer = 0; layer < 2 && !ok; ++layer) {
            char* p = layer ? lo : up;
            const int pn = layer ? lon : upn;
            if (pn <= 0) continue;
            int cut = pn;
            while (cut > 0 && p[cut] != '/') --cut;
            if (cut <= 0) continue;
            p[cut] = 0;
            struct kstat ds;
            if (lx_fp_gate(NR_newfstatat, AT_FDCWD_, (long)p, (long)&ds, 0, e->key) == 0 &&
                ds.dev == fst.dev && ds.ino == fst.ino)
                ok = 1;
            p[cut] = '/';
        }
        if (!ok) return FALLBACK;
    }
    if (by_fd == 2) {
        if (op != OP_STAT && op != OP_STATX) return FALLBACK;
        st = fst;
        r = 0;
        if (upn >= 0 && exc_has(e, lx_fp_hash(up, (uint32_t)upn) ^ LX_FP_LEAF_SALT)) return FALLBACK;
    } else {
        if (upn >= 0) {
            r = lx_fp_gate(NR_newfstatat, AT_FDCWD_, (long)up, (long)&st, AT_SYMLINK_NOFOLLOW_, e->key);
            if (r == 0) { hp = up; hn = upn; }
            else if (r != -ENOENT_) return FALLBACK;
        }
        if (r != 0) {
            r = lx_fp_gate(NR_newfstatat, AT_FDCWD_, (long)lo, (long)&st, AT_SYMLINK_NOFOLLOW_, e->key);
            if (r != 0) return FALLBACK;   /* missing: let the supervisor say why */
        }
    }
    const int is_link = (st.mode & S_IFMT_) == S_IFLNK_;
    if (follow && is_link && by_fd != 2) return FALLBACK;
    /* an emulated hardlink's placeholder */
    if (exc_has(e, lx_fp_hash(hp, (uint32_t)hn) ^ LX_FP_LEAF_SALT)) return FALLBACK;

    if (op == OP_READLINK) {
        if (!is_link) r = -EINVAL_;
        else r = lx_fp_gate(NR_readlinkat, AT_FDCWD_, (long)hp, (long)buf, (long)size, e->key);
        if (r < 0 && r != -EINVAL_) return FALLBACK;
    } else if (op == OP_XATTR) {
        if (size > 65536) size = 65536;
        if (name) r = lx_fp_gate(nr, (long)hp, (long)name, (long)buf, (long)size, e->key);
        else      r = lx_fp_gate(nr, (long)hp, (long)buf, (long)size, 0, e->key);
        if (r < 0 && r != -ENODATA_ && r != -ERANGE_ && r != -ENOTSUP_) return FALLBACK;
    } else if (op == OP_STAT) {
        st.uid = 0;
        st.gid = 0;
        if (lx_fp_copy((void*)buf, &st, sizeof st) != 0) return FALLBACK;
        r = 0;
    } else {
        struct kstatx sx;
        zero(&sx, sizeof sx);
        sx.mask = 0x7ffu | 0x1000u | 0x4000u;   /* BASIC_STATS | MNT_ID | MNT_ID_UNIQUE */
        sx.blksize = (uint32_t)st.blksize;
        sx.nlink = (uint32_t)st.nlink;
        sx.mode = (uint16_t)st.mode;
        sx.ino = st.ino;
        sx.size = (uint64_t)st.size;
        sx.blocks = (uint64_t)st.blocks;
        sx.atime.sec = (int64_t)st.atime; sx.atime.nsec = (uint32_t)st.atime_ns;
        sx.mtime.sec = (int64_t)st.mtime; sx.mtime.nsec = (uint32_t)st.mtime_ns;
        sx.ctime.sec = (int64_t)st.ctime; sx.ctime.nsec = (uint32_t)st.ctime_ns;
        sx.btime = sx.ctime;
        sx.rdev_major = dev_major(st.rdev);
        sx.rdev_minor = dev_minor(st.rdev);
        sx.dev_major = dev_major(st.dev);
        sx.dev_minor = dev_minor(st.dev);
        sx.mnt_id = m->mnt_id;
        sx.attributes_mask = 0x2000;              /* MOUNT_ROOT */
        if (gn == pl) {   /* abs == prefix, as mount_of says */
            uint32_t k = 0;
            while (k < gn && g[k] == m->prefix[k]) ++k;
            if (k == gn) sx.attributes = 0x2000;
        }
        if (lx_fp_copy((void*)buf, &sx, sizeof sx) != 0) return FALLBACK;
        r = 0;
    }
    /* a change mid-call: the answer may be stale, ask the supervisor */
    if (load_acq(&e->t->seq) != seq) return FALLBACK;
    __atomic_fetch_add(&e->s->hits, 1, __ATOMIC_RELAXED);
    return r;
}

/* Runs on the guest's stack: block signals, take a private stack, work. */
long lx_fp_handle(uint64_t* frame, unsigned nr) {
    char* base = lx_fp_base();
    struct env e;
    e.t = (const struct lx_fp_table*)(base + LX_FP_TABLE_OFF);
    e.p = (struct lx_fp_proc*)(base + LX_FP_PROC_OFF);
    e.fds = (const struct lx_fp_fd*)(base + LX_FP_FDMAP_OFF);
    e.s = (struct lx_fp_stats*)(base + LX_FP_STATS_OFF);
    e.key = e.t->key;
    if (e.t->magic != LX_FP_MAGIC || !load_acq(&e.t->enabled) || e.p->disabled) return FALLBACK;

    /* every signal but the synchronous ones: a fault in a guarded copy has
       to reach the supervisor, and a blocked SIGSEGV would be forced */
    uint64_t block = ~0ULL, old = 0;
    block &= ~((1ULL << (9 - 1)) | (1ULL << (19 - 1)) |   /* KILL, STOP */
               (1ULL << (11 - 1)) | (1ULL << (7 - 1)) |   /* SEGV, BUS */
               (1ULL << (4 - 1)) | (1ULL << (8 - 1)) |    /* ILL, FPE */
               (1ULL << (5 - 1)));                        /* TRAP */
    if (lx_fp_gate(NR_rt_sigprocmask, 2 /*SETMASK*/, (long)&block, (long)&old, 8, e.key) != 0)
        return FALLBACK;

    long r = FALLBACK;
    for (uint32_t i = 0; i < LX_FP_STACKS; ++i) {
        const uint32_t bit = 1u << i;
        if (__atomic_fetch_or(&e.p->slots, bit, __ATOMIC_ACQUIRE) & bit) continue;
        struct ctx c = {&e, frame, (long)nr};
        char* top = base + LX_FP_STACKS_OFF + (uint64_t)(i + 1) * LX_FP_STACK_SIZE;
        r = lx_fp_on_stack(work, &c, top);
        __atomic_fetch_and(&e.p->slots, ~bit, __ATOMIC_RELEASE);
        break;
    }
    (void)lx_fp_gate(NR_rt_sigprocmask, 2, (long)&old, 0, 8, e.key);
    return r;
}
