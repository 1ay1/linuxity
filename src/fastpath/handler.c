/* In-guest fast path. Answers path queries (stat, statx, readlink, xattrs,
 * access) and does the plain fd operations (read-only open, close, dup,
 * getdents, lseek) inside the guest, the way the supervisor would, without
 * a ptrace stop. Freestanding: no libc, general registers only, no
 * writable data of its own.
 *
 * It is only a shortcut. Anything it can't prove it does exactly like the
 * supervisor (a symlink to follow, a chmod'd file, a virtual mount, a
 * directory whose listing is a merge of two layers, an unusual error)
 * returns LX_FP_FALLBACK and the stub runs the real syscall, which traps.
 *
 * fd changes are logged to a ring the supervisor drains before it handles
 * the process's next trapped call, so its fd table never runs behind what
 * the dispatcher looks at. Every use of an fd map entry is checked against
 * the real fd's inode first: a stale entry costs a fallback, never a wrong
 * answer or a wrong action.
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
#define EACCES_ 13
#define EINVAL_ 22
#define ERANGE_ 34
#define ENODATA_ 61
#define ENOTSUP_ 95

#define S_IFMT_ 0170000u
#define S_IFLNK_ 0120000u
#define S_IFDIR_ 0040000u
#define S_IFREG_ 0100000u

#define F_DUPFD_ 0
#define F_DUPFD_CLOEXEC_ 1030

#define O_ACCMODE_ 3
#define O_NOCTTY_ 0400
#define O_NONBLOCK_ 04000
#define O_CLOEXEC_ 02000000
#define O_PATH_ 010000000

#if defined(__x86_64__)
#define O_DIRECTORY_ 0200000
#define O_NOFOLLOW_ 0400000
#define O_LARGEFILE_ 0100000
enum {
    NR_stat = 4, NR_lstat = 6, NR_newfstatat = 262, NR_statx = 332, NR_fstat = 5,
    NR_readlink = 89, NR_readlinkat = 267,
    NR_getxattr = 191, NR_lgetxattr = 192, NR_listxattr = 194, NR_llistxattr = 195,
    NR_open = 2, NR_openat = 257, NR_close = 3,
    NR_dup = 32, NR_dup2 = 33, NR_dup3 = 292, NR_fcntl = 72,
    NR_getdents64 = 217, NR_lseek = 8,
    NR_access = 21, NR_faccessat = 269, NR_faccessat2 = 439,
    NR_rt_sigprocmask = 14, NR_getpid = 39,
};
struct kstat {
    uint64_t dev, ino, nlink;
    uint32_t mode, uid, gid, pad0;
    uint64_t rdev;
    int64_t size, blksize, blocks;
    uint64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
    int64_t reserved[3];
};
/* lx_fp_common's frame, from the pointer it passes: r9 r8 r10 rdx rsi rdi
   upwards, so arg i sits at index 5 - i. */
#define ARG(f, i) ((f)[5 - (i)])
#elif defined(__aarch64__)
#define O_DIRECTORY_ 040000
#define O_NOFOLLOW_ 0100000
#define O_LARGEFILE_ 0400000
enum {
    NR_stat = -1, NR_lstat = -2, NR_newfstatat = 79, NR_statx = 291, NR_fstat = 80,
    NR_readlink = -3, NR_readlinkat = 78,
    NR_getxattr = 8, NR_lgetxattr = 9, NR_listxattr = 11, NR_llistxattr = 12,
    NR_open = -4, NR_openat = 56, NR_close = 57,
    NR_dup = 23, NR_dup2 = -5, NR_dup3 = 24, NR_fcntl = 25,
    NR_getdents64 = 61, NR_lseek = 62,
    NR_access = -6, NR_faccessat = 48, NR_faccessat2 = 439,
    NR_rt_sigprocmask = 135, NR_getpid = 172,
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
/* The end of a seqlock read: the reads before it happened before this. */
static inline int seq_same(const uint32_t* p, uint32_t s1) {
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return __atomic_load_n(p, __ATOMIC_RELAXED) == s1;
}

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
    struct lx_fp_fd* fds;
    struct lx_fp_stats* s;
    const uint64_t* key;
    uint32_t seq;   /* table seq at the start of the call */
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

/* 0: not known clean; 1: clean; 2: clean and not in the upper layer */
static int dir_clean(const struct env* e, uint64_t h, uint32_t len) {
    const uint32_t gen = load_acq(&e->t->dir_gen);
    const uint32_t i = (uint32_t)h & (LX_FP_DIR_SLOTS - 1);
    for (uint32_t k = 0; k < LX_FP_PROBES; ++k) {
        const struct lx_fp_dir* d = &e->t->dirs[(i + k) & (LX_FP_DIR_SLOTS - 1)];
        const uint32_t g1 = load_acq(&d->gen);
        if (g1 == 0) return 0;
        const uint64_t dh = load_acq64(&d->hash);
        const uint32_t dl = d->len;
        const uint32_t nu = d->no_upper;
        if (!seq_same(&d->gen, g1)) return 0;
        if (g1 == gen && dh == h && dl == len) return nu ? 2 : 1;
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

static long sys(const struct env* e, long nr, long a0, long a1, long a2, long a3) {
    return lx_fp_gate(nr, a0, a1, a2, a3, e->key);
}

/* -- the fd map ---------------------------------------------------------- */

/* A consistent copy of fd's map entry, or -1. */
static int fd_read(const struct env* e, long fd, struct lx_fp_fd* out) {
    if (fd < 0 || fd >= (long)LX_FP_FDS) return -1;
    const struct lx_fp_fd* ent = &e->fds[fd];
    const uint32_t s1 = load_acq(&ent->seq);
    if (s1 & 1) return -1;
    out->kind = ent->kind;
    out->flags = ent->flags;
    out->len = ent->len;
    out->gen = ent->gen;
    out->dev = ent->dev;
    out->ino = ent->ino;
    const uint32_t len = out->len;
    if (len >= LX_FP_FD_PATH) return -1;
    move(out->path, ent->path, len);
    out->path[len] = 0;
    if (!seq_same(&ent->seq, s1)) return -1;
    return 0;
}

/* A host file or dir entry that still describes the real fd: `st` gets the
   fd's own stat. Also checks the path is current (no rename since). */
static int fd_host(const struct env* e, long fd, struct lx_fp_fd* ent, struct kstat* st) {
    if (fd_read(e, fd, ent) != 0 || ent->kind != LX_FP_FD_HOST) return -1;
    if (sys(e, NR_fstat, fd, (long)st, 0, 0) != 0) return -1;
    if (st->dev != ent->dev || st->ino != ent->ino) return -1;
    return 0;
}

static int fd_write(const struct env* e, long fd, const struct lx_fp_fd* src) {
    if (fd < 0 || fd >= (long)LX_FP_FDS) return -1;
    struct lx_fp_fd* ent = &e->fds[fd];
    uint32_t s = load_acq(&ent->seq);
    if (s & 1) return -1;
    if (!__atomic_compare_exchange_n(&ent->seq, &s, s + 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return -1;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    ent->kind = src->kind;
    ent->flags = src->flags;
    ent->len = src->len;
    ent->gen = src->gen;
    ent->pad = 0;
    ent->dev = src->dev;
    ent->ino = src->ino;
    if (src->len < LX_FP_FD_PATH) {
        move(ent->path, src->path, src->len);
        ent->path[src->len] = 0;
    }
    __atomic_store_n(&ent->seq, s + 2, __ATOMIC_RELEASE);
    return 0;
}

static void fd_clear(const struct env* e, long fd) {
    struct lx_fp_fd z;
    zero(&z, sizeof z);
    (void)fd_write(e, fd, &z);
}

/* -- the event ring --------------------------------------------------------
   Reserve before acting, so a full ring means "fall back" with nothing
   done; commit after (a NOOP when the action didn't happen). Signals are
   blocked in between, so a handler that never returns can't leave a slot
   unfinished and stall every later event. */
struct evh { long idx; uint64_t old; };
static int ev_reserve(const struct env* e, struct evh* h) {
    uint64_t block = ~0ULL;
    block &= ~((1ULL << (9 - 1)) | (1ULL << (19 - 1)) |   /* KILL, STOP */
               (1ULL << (11 - 1)) | (1ULL << (7 - 1)) |   /* SEGV, BUS */
               (1ULL << (4 - 1)) | (1ULL << (8 - 1)) |    /* ILL, FPE */
               (1ULL << (5 - 1)));                        /* TRAP */
    if (sys(e, NR_rt_sigprocmask, 2 /*SETMASK*/, (long)&block, (long)&h->old, 8) != 0) return -1;
    for (;;) {
        uint32_t w = load_acq(&e->p->ev_wr);
        const uint32_t r = load_acq(&e->p->ev_rd);
        if (w - r >= LX_FP_EVENTS) {
            (void)sys(e, NR_rt_sigprocmask, 2, (long)&h->old, 0, 8);
            return -1;
        }
        if (__atomic_compare_exchange_n(&e->p->ev_wr, &w, w + 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            h->idx = (long)w;
            return 0;
        }
    }
}
static void ev_commit(const struct env* e, const struct evh* h, long tg, uint8_t op, long fd,
                      const struct lx_fp_fd* now) {
    const long idx = h->idx;
    struct lx_fp_ev* ev = &e->p->ev[(uint32_t)idx & (LX_FP_EVENTS - 1)];
    ev->op = op;
    ev->fd = (int32_t)fd;
    ev->flags = now ? now->flags : 0;
    ev->len = now ? now->len : 0;
    if (now && now->len < LX_FP_FD_PATH) move(ev->path, now->path, now->len);
    __atomic_store_n(&ev->seq, (uint32_t)idx + 1, __ATOMIC_RELEASE);
    __atomic_fetch_add(&e->s->ev[(uint32_t)tg & (LX_FP_CWD_SLOTS - 1)], 1, __ATOMIC_RELEASE);
    __atomic_fetch_add(&e->s->evsum, 1, __ATOMIC_RELEASE);
    (void)sys(e, NR_rt_sigprocmask, 2, (long)&h->old, 0, 8);
}

/* The calling process, if it owns this region's fd map; else 0. */
static long owner(const struct env* e) {
    const long tg = sys(e, NR_getpid, 0, 0, 0, 0);
    if (tg <= 0 || tg != (long)__atomic_load_n(&e->p->owner, __ATOMIC_ACQUIRE)) return 0;
    return tg;
}

/* -- resolving a guest path -------------------------------------------------- */

struct res {
    uint32_t gn;
    int upn, lon, hn;
    int dir_check;      /* g's parent must be fst's inode */
    int no_upper;       /* the leaf's parent is not in the upper layer */
    const struct lx_fp_mount* m;
    const char* hp;     /* the layer that holds the leaf */
    struct kstat st;    /* its lstat */
    struct kstat fst;   /* the dirfd's own stat, or the fd's for AT_EMPTY_PATH */
    char g[LX_FP_PATH_MAX];
    char up[LX_FP_HOST_MAX], lo[LX_FP_HOST_MAX];
};

/* The guest path the call names, made absolute, in r->g. `by_fd` lets an
   empty path mean the fd itself (then r->fst is that fd's stat and the
   return is 2). 0 ok, -1 fall back. */
static int guest_path(const struct env* e, long dirfd, uint64_t path_ptr, int by_fd, struct res* r) {
    char* g = r->g;
    long n = 0;
    r->dir_check = 0;
    if (path_ptr) {
        n = lx_fp_strcpy(g, (const char*)path_ptr, LX_FP_PATH_MAX - 1);
        if (n < 0 || n >= (long)LX_FP_PATH_MAX - 1) return -1;
    }
    g[n] = 0;
    struct lx_fp_fd ent;
    if (n == 0) {
        /* only "the fd itself" makes an empty path legal */
        if (!by_fd || dirfd < 0) return -1;
        if (fd_host(e, dirfd, &ent, &r->fst) != 0) return -1;
        if (ent.gen != load_acq(&e->t->dir_gen)) return -1;
        move(g, ent.path, ent.len);
        g[ent.len] = 0;
        r->gn = ent.len;
        return 2;
    }
    if (g[0] != '/' && dirfd >= 0) {
        /* relative to a directory fd, if its recorded path still names the
           directory it has open (checked after the layers are known) */
        if (fd_host(e, dirfd, &ent, &r->fst) != 0 || !(ent.flags & LX_FP_FD_DIR)) return -1;
        if (ent.gen != load_acq(&e->t->dir_gen)) return -1;
        const uint32_t dl = ent.len;
        const uint32_t lead = dl == 1 ? 1 : dl + 1;
        if (lead + (uint32_t)n >= LX_FP_PATH_MAX) return -1;
        for (long i = n; i >= 0; --i) g[i + lead] = g[i];
        move(g, ent.path, dl);
        g[lead - 1] = '/';
        n += lead;
        r->dir_check = 1;
    } else if (g[0] != '/') {
        if (dirfd != AT_FDCWD_) return -1;
        const long tg = sys(e, NR_getpid, 0, 0, 0, 0);
        if (tg <= 0) return -1;
        const struct lx_fp_cwd* cw = 0;
        const uint32_t start = (uint32_t)tg & (LX_FP_CWD_SLOTS - 1);
        for (uint32_t k = 0; k < LX_FP_CWD_SLOTS; ++k) {
            const struct lx_fp_cwd* c = &e->t->cwds[(start + k) & (LX_FP_CWD_SLOTS - 1)];
            const int32_t t = __atomic_load_n(&c->tgid, __ATOMIC_ACQUIRE);
            if (t == (int32_t)tg) { cw = c; break; }
            if (t == 0) break;
        }
        if (!cw) return -1;
        const uint32_t s1 = load_acq(&cw->seq);
        const uint32_t cl = cw->len;
        if ((s1 & 1) || cl == 0 || cl >= LX_FP_CWD_MAX || cl + 1 + (uint32_t)n >= LX_FP_PATH_MAX)
            return -1;
        const uint32_t lead = cl == 1 ? 1 : cl + 1;   /* cwd "/" needs no extra slash */
        for (long i = n; i >= 0; --i) g[i + lead] = g[i];
        move(g, cw->path, cl);
        g[lead - 1] = '/';
        n += lead;
        if (!seq_same(&cw->seq, s1) || __atomic_load_n(&cw->tgid, __ATOMIC_ACQUIRE) != (int32_t)tg)
            return -1;
    }
    r->gn = (uint32_t)n;
    return 0;
}

/* Is guest dir g[0..dn) (in mount m, whose prefix is g[0..skip)) a real
   directory all the way down, as the supervisor's parent walk would find?
   Walks up to the nearest dir it has cached, then checks each step below
   it with an lstat: the upper copy if there is one (it wins), else the
   lower. -1: no (or can't tell); 0: yes; 1: yes, and not in the upper. */
static int dir_verify(const struct env* e, const struct lx_fp_mount* m, const char* g,
                      uint32_t dn, uint32_t skip) {
    uint32_t cuts[8];
    int n = 0;
    uint32_t at = dn;
    int up_absent = 0;   /* the cached ancestor isn't in upper */
    for (;;) {
        if (n == 8) return -1;
        cuts[n++] = at;
        uint32_t p = at;
        while (p > 0 && g[p - 1] != '/') --p;
        if (p == 0) return -1;
        const uint32_t parent = p - 1;   /* the slash before the last name */
        if (parent <= skip) break;       /* reached the mount's root */
        const int dc = dir_clean(e, lx_fp_hash(g, parent), parent);
        if (dc) { up_absent = dc == 2; break; }
        at = parent;
    }
    const uint32_t pl = m->prefix_len == 1 ? 0 : m->prefix_len;
    char hp[LX_FP_HOST_MAX];
    int no_up = up_absent || m->kind != LX_FP_MNT_OVERLAY;
    for (int i = n - 1; i >= 0; --i) {
        const uint32_t end = cuts[i];
        const char* rel = g + pl;
        uint32_t rl = end - pl;
        while (rl && rel[0] == '/') { ++rel; --rl; }
        struct kstat st;
        long rc = -ENOENT_;
        if (!no_up) {
            if (join(hp, m->upper, m->upper_len, rel, rl) < 0) return -1;
            rc = sys(e, NR_newfstatat, AT_FDCWD_, (long)hp, (long)&st, AT_SYMLINK_NOFOLLOW_);
            if (rc != 0 && rc != -ENOENT_) return -1;
            if (rc != 0) no_up = 1;   /* nothing below it is in upper either */
        }
        if (rc != 0) {
            if (join(hp, m->base, m->base_len, rel, rl) < 0) return -1;
            if (sys(e, NR_newfstatat, AT_FDCWD_, (long)hp, (long)&st, AT_SYMLINK_NOFOLLOW_) != 0) return -1;
        }
        if ((st.mode & S_IFMT_) != S_IFDIR_) return -1;
    }
    return no_up;
}

/* Which host paths r->g maps to (r->up for an overlay's upper, r->lo),
   after every check that the supervisor would answer it the plain way. */
static int layers(const struct env* e, struct res* r) {
    const char* g = r->g;
    const uint32_t gn = r->gn;
    if (!canonical(g, gn)) return -1;

    /* paths the supervisor answers differently: a removed path or one
       under it, a chmod/chown record, a socket placeholder */
    {
        uint64_t h = FNV_INIT;
        for (uint32_t i = 0; i < gn; ++i) {
            if (g[i] == '/' && i > 0 && exc_has(e, fnv_finish(h, i))) return -1;
            h = fnv_step(h, (unsigned char)g[i]);
        }
        const uint64_t full = fnv_finish(h, gn);
        if (exc_has(e, full) || exc_has(e, full ^ LX_FP_LEAF_SALT)) return -1;
    }

    const struct lx_fp_mount* m = deepest(e, g, gn);
    if (!m || m->kind == LX_FP_MNT_VIRTUAL) return -1;
    r->m = m;
    const uint32_t pl = m->prefix_len;
    const uint32_t skip = pl == 1 ? 0 : pl;
    const char* rel = g + skip;
    uint32_t rl = gn - skip;
    while (rl && rel[0] == '/') { ++rel; --rl; }

    /* every directory on the way must be a real directory, no symlink, as
       the supervisor's parent walk would find (merged-/usr's /lib is a link
       it follows itself). A dir it hasn't cached yet is checked here: up to
       the nearest cached ancestor, each step is a plain directory in the
       layer the supervisor's probe would pick (upper, else lower). */
    int no_upper = 0;
    {
        uint32_t last = 0;
        for (uint32_t i = 0; i < gn; ++i) if (g[i] == '/') last = i;
        if (last > skip) {
            const int dc = dir_clean(e, lx_fp_hash(g, last), last);
            if (dc) no_upper = dc == 2;
            else if ((no_upper = dir_verify(e, m, g, last, skip)) < 0) return -1;
        }
    }

    r->upn = -1;
    r->lon = join(r->lo, m->base, m->base_len, rel, rl);
    if (r->lon < 0) return -1;
    /* a host /proc or /dev path reads differently from here than from the
       supervisor (/proc/self); the dispatcher redirects those */
    if (host_special(r->lo, r->lon)) return -1;
    if (m->kind == LX_FP_MNT_OVERLAY) {
        r->upn = join(r->up, m->upper, m->upper_len, rel, rl);
        if (r->upn < 0 || host_special(r->up, r->upn)) return -1;
    }
    r->no_upper = no_upper;

    if (r->dir_check) {
        /* the leaf's parent, in either layer, must be the dir the fd has
           open; otherwise the name now means another directory */
        int ok = 0;
        for (int layer = 0; layer < 2 && !ok; ++layer) {
            char* p = layer ? r->lo : r->up;
            const int pn = layer ? r->lon : r->upn;
            if (pn <= 0) continue;
            int cut = pn;
            while (cut > 0 && p[cut] != '/') --cut;
            if (cut <= 0) continue;
            p[cut] = 0;
            struct kstat ds;
            if (sys(e, NR_newfstatat, AT_FDCWD_, (long)p, (long)&ds, 0) == 0 &&
                ds.dev == r->fst.dev && ds.ino == r->fst.ino)
                ok = 1;
            p[cut] = '/';
        }
        if (!ok) return -1;
    }
    return 0;
}

/* The layer that holds the leaf, as the supervisor's probe picks it (upper
   first), with its lstat. 1: the leaf is in neither layer (its parent is a
   verified real directory, so the supervisor says ENOENT too); 0: found;
   -1: fall back. */
static int pick(const struct env* e, struct res* r) {
    long rc = -ENOENT_;
    r->hp = r->lo;
    r->hn = r->lon;
    if (r->upn >= 0 && !r->no_upper) {
        rc = sys(e, NR_newfstatat, AT_FDCWD_, (long)r->up, (long)&r->st, AT_SYMLINK_NOFOLLOW_);
        if (rc == 0) { r->hp = r->up; r->hn = r->upn; }
        else if (rc != -ENOENT_) return -1;
    }
    if (rc != 0) {
        rc = sys(e, NR_newfstatat, AT_FDCWD_, (long)r->lo, (long)&r->st, AT_SYMLINK_NOFOLLOW_);
        if (rc == -ENOENT_) return 1;
        if (rc != 0) return -1;
    }
    /* an emulated hardlink's placeholder */
    if (exc_has(e, lx_fp_hash(r->hp, (uint32_t)r->hn) ^ LX_FP_LEAF_SALT)) return -1;
    return 0;
}

static int table_unchanged(const struct env* e) { return seq_same(&e->t->seq, e->seq); }

/* -- path queries ---------------------------------------------------------- */

static long do_stat(const struct env* e, uint64_t* f, long nr) {
    long dirfd = AT_FDCWD_;
    uint64_t path_ptr, buf;
    int follow = 1, by_fd = 0, is_statx = 0;
    if (nr == NR_stat || nr == NR_lstat) {
        path_ptr = ARG(f, 0); buf = ARG(f, 1); follow = nr == NR_stat;
    } else if (nr == NR_fstat) {
        dirfd = (long)(int)ARG(f, 0); path_ptr = 0; buf = ARG(f, 1); by_fd = 1;
    } else if (nr == NR_newfstatat) {
        dirfd = (long)(int)ARG(f, 0); path_ptr = ARG(f, 1); buf = ARG(f, 2);
        const long flags = (long)(int)ARG(f, 3);
        if (flags & ~(AT_SYMLINK_NOFOLLOW_ | AT_NO_AUTOMOUNT_ | AT_EMPTY_PATH_)) return FALLBACK;
        follow = !(flags & AT_SYMLINK_NOFOLLOW_);
        by_fd = (flags & AT_EMPTY_PATH_) != 0;
    } else {
        is_statx = 1;
        dirfd = (long)(int)ARG(f, 0); path_ptr = ARG(f, 1); buf = ARG(f, 4);
        const long flags = (long)(int)ARG(f, 2);
        if (flags & ~(AT_SYMLINK_NOFOLLOW_ | AT_NO_AUTOMOUNT_ | AT_EMPTY_PATH_ | AT_STATX_SYNC_MASK_))
            return FALLBACK;
        follow = !(flags & AT_SYMLINK_NOFOLLOW_);
        by_fd = (flags & AT_EMPTY_PATH_) != 0;
    }
    struct res r;
    const int gp = guest_path(e, dirfd, path_ptr, by_fd, &r);
    if (gp < 0 || layers(e, &r) != 0) return FALLBACK;
    if (gp == 2) {
        /* the fd's own inode, whichever layer it was opened in */
        r.st = r.fst;
        r.hp = r.lo; r.hn = r.lon;
        if (r.upn >= 0 && exc_has(e, lx_fp_hash(r.up, (uint32_t)r.upn) ^ LX_FP_LEAF_SALT)) return FALLBACK;
        if (exc_has(e, lx_fp_hash(r.lo, (uint32_t)r.lon) ^ LX_FP_LEAF_SALT)) return FALLBACK;
    } else {
        { const int pk = pick(e, &r); if (pk < 0) return FALLBACK; if (pk > 0) return table_unchanged(e) ? -ENOENT_ : FALLBACK; }
        if (follow && (r.st.mode & S_IFMT_) == S_IFLNK_) return FALLBACK;
    }
    struct kstat st = r.st;
    if (!is_statx) {
        st.uid = 0;
        st.gid = 0;
        if (!table_unchanged(e)) return FALLBACK;
        if (lx_fp_copy((void*)buf, &st, sizeof st) != 0) return FALLBACK;
        return 0;
    }
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
    sx.mnt_id = r.m->mnt_id;
    sx.attributes_mask = 0x2000;              /* MOUNT_ROOT */
    if (r.gn == r.m->prefix_len) {            /* abs == prefix, as mount_of says */
        uint32_t k = 0;
        while (k < r.gn && r.g[k] == r.m->prefix[k]) ++k;
        if (k == r.gn) sx.attributes = 0x2000;
    }
    if (!table_unchanged(e)) return FALLBACK;
    if (lx_fp_copy((void*)buf, &sx, sizeof sx) != 0) return FALLBACK;
    return 0;
}

static long do_readlink(const struct env* e, uint64_t* f, long nr) {
    long dirfd = AT_FDCWD_;
    uint64_t path_ptr, buf, size;
    if (nr == NR_readlink) {
        path_ptr = ARG(f, 0); buf = ARG(f, 1); size = ARG(f, 2);
    } else {
        dirfd = (long)(int)ARG(f, 0); path_ptr = ARG(f, 1); buf = ARG(f, 2); size = ARG(f, 3);
    }
    if ((long)size <= 0) return FALLBACK;
    struct res r;
    if (guest_path(e, dirfd, path_ptr, 0, &r) != 0 || layers(e, &r) != 0)
        return FALLBACK;
    { const int pk = pick(e, &r); if (pk < 0) return FALLBACK; if (pk > 0) return table_unchanged(e) ? -ENOENT_ : FALLBACK; }
    long rc = -EINVAL_;
    if ((r.st.mode & S_IFMT_) == S_IFLNK_)
        rc = sys(e, NR_readlinkat, AT_FDCWD_, (long)r.hp, (long)buf, (long)size);
    if (rc < 0 && rc != -EINVAL_) return FALLBACK;
    if (!table_unchanged(e)) return FALLBACK;
    return rc;
}

static long do_xattr(const struct env* e, uint64_t* f, long nr) {
    uint64_t name = 0, buf, size;
    const uint64_t path_ptr = ARG(f, 0);
    if (nr == NR_getxattr || nr == NR_lgetxattr) { name = ARG(f, 1); buf = ARG(f, 2); size = ARG(f, 3); }
    else { buf = ARG(f, 1); size = ARG(f, 2); }
    const int follow = nr == NR_getxattr || nr == NR_listxattr;
    struct res r;
    if (guest_path(e, AT_FDCWD_, path_ptr, 0, &r) != 0 || layers(e, &r) != 0)
        return FALLBACK;
    { const int pk = pick(e, &r); if (pk < 0) return FALLBACK; if (pk > 0) return table_unchanged(e) ? -ENOENT_ : FALLBACK; }
    if (follow && (r.st.mode & S_IFMT_) == S_IFLNK_) return FALLBACK;
    if (size > 65536) size = 65536;
    long rc;
    if (name) rc = sys(e, nr, (long)r.hp, (long)name, (long)buf, (long)size);
    else      rc = sys(e, nr, (long)r.hp, (long)buf, (long)size, 0);
    if (rc < 0 && rc != -ENODATA_ && rc != -ERANGE_ && rc != -ENOTSUP_) return FALLBACK;
    if (!table_unchanged(e)) return FALLBACK;
    return rc;
}

static long do_access(const struct env* e, uint64_t* f, long nr) {
    long dirfd = AT_FDCWD_;
    uint64_t path_ptr;
    long mode;
    if (nr == NR_access) {
        path_ptr = ARG(f, 0); mode = (long)(int)ARG(f, 1);
    } else {
        dirfd = (long)(int)ARG(f, 0); path_ptr = ARG(f, 1); mode = (long)(int)ARG(f, 2);
        if (nr == NR_faccessat2 && (int)ARG(f, 3) != 0) return FALLBACK;
    }
    if (mode & ~7L) return FALLBACK;
    if (mode && !__atomic_load_n(&e->p->privileged, __ATOMIC_ACQUIRE)) return FALLBACK;
    struct res r;
    if (guest_path(e, dirfd, path_ptr, 0, &r) != 0 || layers(e, &r) != 0)
        return FALLBACK;
    { const int pk = pick(e, &r); if (pk < 0) return FALLBACK; if (pk > 0) return table_unchanged(e) ? -ENOENT_ : FALLBACK; }
    if ((r.st.mode & S_IFMT_) == S_IFLNK_) return FALLBACK;
    long rc = 0;
    /* root reads and writes anything but needs an x bit to execute */
    if (mode & 1) {
        rc = sys(e, NR_faccessat, AT_FDCWD_, (long)r.hp, mode, 0);
        if (rc != 0 && rc != -EACCES_) return FALLBACK;
    }
    if (!table_unchanged(e)) return FALLBACK;
    return rc;
}

/* -- fd operations ------------------------------------------------------------ */

static long do_open(const struct env* e, uint64_t* f, long nr) {
    long dirfd = AT_FDCWD_;
    uint64_t path_ptr;
    long flags;
    if (nr == NR_open) { path_ptr = ARG(f, 0); flags = (long)(int)ARG(f, 1); }
    else { dirfd = (long)(int)ARG(f, 0); path_ptr = ARG(f, 1); flags = (long)(int)ARG(f, 2); }
    /* read-only opens that make nothing and touch no terminal */
    const long ok = O_NOCTTY_ | O_NONBLOCK_ | O_DIRECTORY_ | O_NOFOLLOW_ | O_LARGEFILE_ | O_CLOEXEC_ | O_PATH_;
    if ((flags & O_ACCMODE_) != 0 || (flags & ~ok)) return FALLBACK;
    if (!(flags & O_PATH_) && !__atomic_load_n(&e->p->privileged, __ATOMIC_ACQUIRE)) return FALLBACK;
    const long tg = owner(e);
    if (!tg) return FALLBACK;
    struct res r;
    if (guest_path(e, dirfd, path_ptr, 0, &r) != 0 || layers(e, &r) != 0)
        return FALLBACK;
    { const int pk = pick(e, &r); if (pk < 0) return FALLBACK; if (pk > 0) return table_unchanged(e) ? -ENOENT_ : FALLBACK; }
    const uint32_t type = r.st.mode & S_IFMT_;
    if (type != S_IFREG_ && type != S_IFDIR_) return FALLBACK;   /* links, fifos, devices */
    if ((flags & O_DIRECTORY_) && type != S_IFDIR_) return FALLBACK;
    /* the supervisor would first give itself rwx on such a dir */
    if (type == S_IFDIR_ && (r.st.mode & 0700u) != 0700u && !(flags & O_PATH_)) return FALLBACK;
    if (r.gn >= LX_FP_FD_PATH) return FALLBACK;
    struct evh ev;
    if (ev_reserve(e, &ev) != 0) return FALLBACK;
    /* O_NOFOLLOW: the leaf was not a link; if it became one, don't follow */
    const long fd = sys(e, NR_openat, AT_FDCWD_, (long)r.hp, flags | O_NOFOLLOW_, 0);
    if (fd < 0) { ev_commit(e, &ev, tg, LX_FP_EV_NOOP, -1, 0); return FALLBACK; }
    struct kstat fs;
    if (fd >= (long)LX_FP_FDS || sys(e, NR_fstat, fd, (long)&fs, 0, 0) != 0 ||
        fs.dev != r.st.dev || fs.ino != r.st.ino || !table_unchanged(e)) {
        sys(e, NR_close, fd, 0, 0, 0);
        ev_commit(e, &ev, tg, LX_FP_EV_NOOP, -1, 0);
        return FALLBACK;
    }
    struct lx_fp_fd ent;
    ent.kind = LX_FP_FD_HOST;
    ent.flags = type == S_IFDIR_ ? LX_FP_FD_DIR : 0;
    /* a directory on a plain bind mount lists natively from the start */
    if (type == S_IFDIR_ && r.m->kind == LX_FP_MNT_BIND) ent.flags |= LX_FP_FD_NATIVE;
    ent.len = (uint16_t)r.gn;
    ent.gen = load_acq(&e->t->dir_gen);
    ent.dev = fs.dev;
    ent.ino = fs.ino;
    move(ent.path, r.g, r.gn);
    (void)fd_write(e, fd, &ent);
    ev_commit(e, &ev, tg, LX_FP_EV_OPEN, fd, &ent);
    return fd;
}

static long do_close(const struct env* e, uint64_t* f) {
    const long fd = (long)(int)ARG(f, 0);
    struct lx_fp_fd ent;
    struct kstat st;
    if (fd_read(e, fd, &ent) != 0 || ent.kind != LX_FP_FD_HOST) return FALLBACK;
    const long tg = owner(e);
    if (!tg) return FALLBACK;
    if (fd_host(e, fd, &ent, &st) != 0) return FALLBACK;
    struct evh ev;
    if (ev_reserve(e, &ev) != 0) return FALLBACK;
    /* clear first: once the kernel frees the number, another thread's open
       may get it and its entry must not be wiped by ours */
    fd_clear(e, fd);
    const long rc = sys(e, NR_close, fd, 0, 0, 0);
    ev_commit(e, &ev, tg, LX_FP_EV_CLOSE, fd, 0);
    return rc;
}

static long do_dup(const struct env* e, uint64_t* f, long nr) {
    const long src = (long)(int)ARG(f, 0);
    long target = -1;
    if (nr == NR_fcntl) {
        const long cmd = (long)(int)ARG(f, 1);
        if (cmd != F_DUPFD_ && cmd != F_DUPFD_CLOEXEC_) return FALLBACK;
        if ((long)(int)ARG(f, 2) < 0 || (long)(int)ARG(f, 2) >= (long)LX_FP_FDS) return FALLBACK;
    } else if (nr == NR_dup2 || nr == NR_dup3) {
        target = (long)(int)ARG(f, 1);
        if (target < 0 || target >= (long)LX_FP_FDS) return FALLBACK;
    }
    struct lx_fp_fd ent;
    if (fd_read(e, src, &ent) != 0 || ent.kind != LX_FP_FD_HOST) return FALLBACK;
    /* the supervisor's merged listing restarts on a dup; leave it the call */
    if (ent.flags & LX_FP_FD_STREAM) return FALLBACK;
    const long tg = owner(e);
    if (!tg) return FALLBACK;
    struct kstat st;
    if (fd_host(e, src, &ent, &st) != 0) return FALLBACK;
    if (target == src && nr == NR_dup2) return src;   /* no change */
    struct evh ev;
    if (ev_reserve(e, &ev) != 0) return FALLBACK;
    const long fd = nr == NR_fcntl ? sys(e, nr, src, (long)ARG(f, 1), (long)ARG(f, 2), 0)
                                   : sys(e, nr, src, (long)ARG(f, 1), (long)ARG(f, 2), 0);
    if (fd < 0) { ev_commit(e, &ev, tg, LX_FP_EV_NOOP, -1, 0); return fd; }
    if (fd >= (long)LX_FP_FDS) {
        /* can't record it: undo, and let the supervisor do it */
        sys(e, NR_close, fd, 0, 0, 0);
        ev_commit(e, &ev, tg, LX_FP_EV_NOOP, -1, 0);
        return FALLBACK;
    }
    ent.flags &= (uint8_t)~LX_FP_FD_BYSUP;
    (void)fd_write(e, fd, &ent);
    ev_commit(e, &ev, tg, LX_FP_EV_OPEN, fd, &ent);
    return fd;
}

/* Decide how a host directory fd is listed: natively when the guest dir is
   exactly one host dir (one layer, nothing removed in it), else by the
   supervisor's merged listing. 1 native, 0 merged, -1 can't tell. */
static int list_natively(const struct env* e, const struct lx_fp_fd* ent, const struct kstat* fst) {
    struct res r;
    if (ent->gen != load_acq(&e->t->dir_gen)) return -1;
    move(r.g, ent->path, ent->len);
    r.g[ent->len] = 0;
    r.gn = ent->len;
    r.dir_check = 0;
    if (layers(e, &r) != 0) return -1;
    if (r.m->kind == LX_FP_MNT_BIND) return 1;
    /* the mount's root holds our journals in its upper; a dir with a
       removed name in it needs the names filtered */
    if (r.gn == r.m->prefix_len) return 0;
    if (exc_has(e, lx_fp_hash(r.g, r.gn) ^ LX_FP_WO_DIR_SALT)) return 0;
    struct kstat us, ls;
    const long ru = sys(e, NR_newfstatat, AT_FDCWD_, (long)r.up, (long)&us, AT_SYMLINK_NOFOLLOW_);
    const long rl = sys(e, NR_newfstatat, AT_FDCWD_, (long)r.lo, (long)&ls, AT_SYMLINK_NOFOLLOW_);
    if ((ru != 0 && ru != -ENOENT_) || (rl != 0 && rl != -ENOENT_)) return -1;
    const int up_dir = ru == 0 && (us.mode & S_IFMT_) == S_IFDIR_;
    const int lo_dir = rl == 0 && (ls.mode & S_IFMT_) == S_IFDIR_;
    if (up_dir && lo_dir) return 0;
    const struct kstat* one = up_dir ? &us : lo_dir ? &ls : 0;
    if (!one || one->dev != fst->dev || one->ino != fst->ino) return -1;
    if (!table_unchanged(e)) return -1;
    return 1;
}

static long do_getdents(const struct env* e, uint64_t* f) {
    const long fd = (long)(int)ARG(f, 0);
    struct lx_fp_fd ent;
    struct kstat st;
    if (fd_host(e, fd, &ent, &st) != 0) return FALLBACK;
    if (ent.flags & LX_FP_FD_STREAM) return FALLBACK;
    if (!(ent.flags & LX_FP_FD_DIR) || (ent.flags & LX_FP_FD_NATIVE))
        return sys(e, NR_getdents64, fd, (long)ARG(f, 1), (long)ARG(f, 2), 0);
    /* first read: decide, and tell the supervisor if it is native */
    const long tg = owner(e);
    if (!tg) return FALLBACK;
    const int native = list_natively(e, &ent, &st);
    if (native < 0) return FALLBACK;
    if (!native) {
        ent.flags |= LX_FP_FD_STREAM;
        (void)fd_write(e, fd, &ent);
        return FALLBACK;
    }
    struct evh ev;
    if (ev_reserve(e, &ev) != 0) return FALLBACK;
    ent.flags = (uint8_t)((ent.flags | LX_FP_FD_NATIVE) & ~LX_FP_FD_BYSUP);
    (void)fd_write(e, fd, &ent);
    ev_commit(e, &ev, tg, LX_FP_EV_OPEN, fd, &ent);
    return sys(e, NR_getdents64, fd, (long)ARG(f, 1), (long)ARG(f, 2), 0);
}

static long do_lseek(const struct env* e, uint64_t* f) {
    const long fd = (long)(int)ARG(f, 0);
    struct lx_fp_fd ent;
    struct kstat st;
    if (fd_host(e, fd, &ent, &st) != 0) return FALLBACK;
    /* a directory's cursor is the supervisor's unless it lists natively */
    if ((ent.flags & LX_FP_FD_DIR) && !(ent.flags & LX_FP_FD_NATIVE)) return FALLBACK;
    return sys(e, NR_lseek, fd, (long)ARG(f, 1), (long)ARG(f, 2), 0);
}

struct ctx { const struct env* e; uint64_t* frame; long nr; };

static long work(void* arg) {
    const struct ctx* c = (const struct ctx*)arg;
    const struct env* e = c->e;
    const long nr = c->nr;
    const uint32_t off = e->t->off_ops;
    long r;
    if (nr == NR_stat || nr == NR_lstat || nr == NR_fstat || nr == NR_newfstatat || nr == NR_statx)
        r = off & 1 ? FALLBACK : do_stat(e, c->frame, nr);
    else if (nr == NR_readlink || nr == NR_readlinkat)
        r = off & 2 ? FALLBACK : do_readlink(e, c->frame, nr);
    else if (nr == NR_getxattr || nr == NR_lgetxattr || nr == NR_listxattr || nr == NR_llistxattr)
        r = off & 4 ? FALLBACK : do_xattr(e, c->frame, nr);
    else if (nr == NR_access || nr == NR_faccessat || nr == NR_faccessat2)
        r = off & 8 ? FALLBACK : do_access(e, c->frame, nr);
    else if (nr == NR_open || nr == NR_openat)
        r = off & 16 ? FALLBACK : do_open(e, c->frame, nr);
    else if (nr == NR_close)
        r = off & 32 ? FALLBACK : do_close(e, c->frame);
    else if (nr == NR_dup || nr == NR_dup2 || nr == NR_dup3 || nr == NR_fcntl)
        r = off & 64 ? FALLBACK : do_dup(e, c->frame, nr);
    else if (nr == NR_getdents64)
        r = off & 128 ? FALLBACK : do_getdents(e, c->frame);
    else if (nr == NR_lseek)
        r = off & 256 ? FALLBACK : do_lseek(e, c->frame);
    else
        r = FALLBACK;
    if (r != FALLBACK) __atomic_fetch_add(&e->s->hits, 1, __ATOMIC_RELAXED);
    return r;
}

/* Calls this blob has anything to say about. A patched site can be shared
   by many syscalls (glibc's cancellable wrapper serves read and write too),
   so the rest leave before any work. */
static int wanted(long nr, const uint64_t* f) {
    if (nr == NR_fcntl) {
        const long cmd = (long)(int)ARG(f, 1);
        return cmd == F_DUPFD_ || cmd == F_DUPFD_CLOEXEC_;
    }
    return nr == NR_stat || nr == NR_lstat || nr == NR_fstat || nr == NR_newfstatat ||
           nr == NR_statx || nr == NR_readlink || nr == NR_readlinkat ||
           nr == NR_getxattr || nr == NR_lgetxattr || nr == NR_listxattr || nr == NR_llistxattr ||
           nr == NR_access || nr == NR_faccessat || nr == NR_faccessat2 ||
           nr == NR_open || nr == NR_openat || nr == NR_close ||
           nr == NR_dup || nr == NR_dup2 || nr == NR_dup3 ||
           nr == NR_getdents64 || nr == NR_lseek;
}

/* Runs on the guest's stack: block signals, take a private stack, work. */
long lx_fp_handle(uint64_t* frame, unsigned nr) {
    if (!wanted((long)(int)nr, frame)) return FALLBACK;
    char* base = lx_fp_base();
    struct env e;
    e.t = (const struct lx_fp_table*)(base + LX_FP_TABLE_OFF);
    e.p = (struct lx_fp_proc*)(base + LX_FP_PROC_OFF);
    e.fds = (struct lx_fp_fd*)(base + LX_FP_FDMAP_OFF);
    e.s = (struct lx_fp_stats*)(base + LX_FP_STATS_OFF);
    e.key = e.t->key;
    if (e.t->magic != LX_FP_MAGIC || !load_acq(&e.t->enabled) || e.p->disabled) return FALLBACK;
    e.seq = load_acq(&e.t->seq);
    if (e.seq & 1) return FALLBACK;

    /* No signal masking: a handler that interrupts this and makes a patched
       call takes another stack slot (or falls back when none is free), and
       every shared write here is a CAS or a reserved slot, so nesting is
       safe. A fault in a guarded copy reaches the supervisor either way. */
    long r = FALLBACK;
    for (uint32_t i = 0; i < LX_FP_STACKS; ++i) {
        const uint32_t bit = 1u << i;
        if (__atomic_fetch_or(&e.p->slots, bit, __ATOMIC_ACQUIRE) & bit) continue;
        struct ctx c = {&e, frame, (long)(int)nr};
        char* top = base + LX_FP_STACKS_OFF + (uint64_t)(i + 1) * LX_FP_STACK_SIZE;
        r = lx_fp_on_stack(work, &c, top);
        __atomic_fetch_and(&e.p->slots, ~bit, __ATOMIC_RELEASE);
        break;
    }
    return r;
}
