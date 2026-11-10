/* linuxity/runtime/linux/fastpath_abi.h
 *
 * The contract between the supervisor and the in-guest fast path. Plain C so
 * the freestanding guest blob (src/fastpath) and the C++ supervisor share one
 * layout.
 *
 * A guest process that makes enough path queries gets one private region
 * (wherever its mmap puts it): the blob's code, a per-process page, a few
 * small stacks, then the shared table (a file the supervisor keeps
 * writing). Hot libc syscall sites are patched to jump to a stub near them,
 * which calls the blob. The blob answers read-only path queries the way the
 * supervisor would, and makes the stub run the original syscall (so it traps
 * as before) whenever it can't be sure.
 *
 * The blob's own syscalls carry a 128-bit key in the 5th and 6th argument
 * (unused by every call it makes), which the seccomp filter lets through.
 * linuxity is not a sandbox; the key keeps ordinary code from ever matching.
 */
#ifndef LINUXITY_FASTPATH_ABI_H
#define LINUXITY_FASTPATH_ABI_H

#include <stdint.h>

#define LX_FP_MAGIC   0x4c5846505441424cULL /* "LXFPTABL" */
#define LX_FP_VERSION 1u

/* Offsets from the region base (= the blob's first byte). */
#define LX_FP_CODE_MAX    0x8000ULL    /* r-x */
#define LX_FP_PROC_OFF    0x8000ULL    /* rw, 0x5000 (the event ring); then a guard */
#define LX_FP_PROC_SIZE   0x5000ULL
#define LX_FP_FDMAP_OFF   0x10000ULL   /* rw: fd -> what it is, by fd number */
#define LX_FP_FDS         1024u
#define LX_FP_FD_PATH     224u
#define LX_FP_STACKS_OFF  0x51000ULL   /* rw; the page before it is a guard */
#define LX_FP_STACKS      4u
#define LX_FP_STACK_SIZE  0x8000ULL
#define LX_FP_TABLE_OFF   0x71000ULL   /* r--, MAP_SHARED */
#define LX_FP_TABLE_SIZE  0x120000ULL
#define LX_FP_STATS_OFF   (LX_FP_TABLE_OFF + LX_FP_TABLE_SIZE)   /* rw-, MAP_SHARED, one page */
#define LX_FP_REGION_SIZE (LX_FP_STATS_OFF + 0x1000ULL)

/* Stubs live in a region near the patched library (branch range). */
#define LX_FP_NEAR_SIZE  0x10000ULL
#define LX_FP_SLOT_SIZE  256u
#define LX_FP_SLOTS      (LX_FP_NEAR_SIZE / LX_FP_SLOT_SIZE)

#define LX_FP_PATH_MAX   1024u   /* longest guest path answered */
#define LX_FP_HOST_MAX   1536u   /* longest host path built */
#define LX_FP_MAX_MOUNTS 32u
#define LX_FP_DIR_SLOTS  32768u
#define LX_FP_EXC_SLOTS  65536u
#define LX_FP_PROBES     32u
#define LX_FP_CWD_SLOTS  256u    /* processes whose cwd the blob knows */
#define LX_FP_CWD_MAX    256u    /* longer cwds: relative paths fall back */
#define LX_FP_EVENTS     64u     /* fd events a process can hold unapplied */

/* The handler's "run the real syscall" answer. */
#define LX_FP_FALLBACK   (-0x7fffffffffffffffLL - 1)

/* exc entries: a removed path blocks itself and everything under it (plain
   hash); the rest only the exact path (hash xor this). A directory holding
   a removed name is listed by the supervisor (hash xor WO_DIR). */
#define LX_FP_LEAF_SALT  0x9e3779b97f4a7c15ULL
#define LX_FP_WO_DIR_SALT 0xc2b2ae3d27d4eb4fULL

enum { LX_FP_MNT_VIRTUAL = 0, LX_FP_MNT_OVERLAY = 1, LX_FP_MNT_BIND = 2 };

struct lx_fp_mount {
    uint16_t prefix_len, base_len, upper_len;
    uint8_t  kind, pad0;
    uint32_t mnt_id;   /* statx stx_mnt_id the supervisor reports */
    char prefix[256];
    char base[512];
    char upper[512];
};

/* A guest directory whose path the supervisor walked and found free of
   symlinks. Valid while gen == table.dir_gen. */
struct lx_fp_dir {
    uint64_t hash;
    uint32_t gen;
    uint16_t len;
    uint16_t no_upper;  /* the dir isn't in the upper layer: neither is anything in it */
};

/* A process's cwd, by host tgid (the blob asks getpid with its key). The
   supervisor writes it at every trap that may change it. */
struct lx_fp_cwd {
    uint32_t seq;    /* seqlock */
    int32_t  tgid;   /* 0: free */
    uint32_t len;
    uint32_t pad;
    char path[LX_FP_CWD_MAX];
};

struct lx_fp_table {
    uint64_t magic;
    uint32_t version;
    uint32_t seq;      /* seqlock: odd while the supervisor changes things */
    uint32_t enabled;  /* 0: every call falls back */
    uint32_t dir_gen;
    uint32_t n_mounts;
    uint32_t off_ops;  /* debug: ops the blob must leave to the trap (bit per op) */
    uint64_t key[2];   /* goes in the blob's syscalls' args 4 and 5 */
    struct lx_fp_mount mounts[LX_FP_MAX_MOUNTS];
    struct lx_fp_cwd cwds[LX_FP_CWD_SLOTS];
    struct lx_fp_dir dirs[LX_FP_DIR_SLOTS];
    uint64_t exc[LX_FP_EXC_SLOTS];
};

/* An fd the blob changed, for the supervisor to replay into its table in
   reservation order. Carries what the fd became, so a later reuse of the
   number by another thread can't be mistaken for it. */
struct lx_fp_ev {
    uint32_t seq;   /* = index + 1 once the entry is complete */
    uint8_t  op;    /* OPEN: fd is now path; CLOSE: fd is gone */
    uint8_t  flags; /* the fd map flags it got */
    uint16_t len;
    int32_t  fd;
    uint32_t pad;
    char path[LX_FP_FD_PATH];
};
enum { LX_FP_EV_NOOP = 0, LX_FP_EV_OPEN = 1, LX_FP_EV_CLOSE = 2, LX_FP_EV_DUP = 3 };

/* Per process, at base + LX_FP_PROC_OFF. */
struct lx_fp_proc {
    uint32_t disabled;
    uint32_t slots;     /* stacks in use, one bit each */
    int32_t  owner;     /* host tgid whose fd table the fd map describes; a
                           vfork child shares this memory but not the fds,
                           so only the owner may change fds in the guest */
    uint32_t slot;      /* the owner's index into stats.ev; >= CWD_SLOTS: none */
    uint32_t privileged;/* the owner may open anything it can read (root) */
    uint32_t ev_rd;     /* events the supervisor has applied */
    uint32_t ev_wr;     /* events reserved (blob) */
    uint32_t pad;
    uint64_t probe;     /* the supervisor writes here to tell a shared mm */
    struct lx_fp_ev ev[LX_FP_EVENTS];
};

/* What an fd is, by fd number. The blob and the supervisor keep it exact
   for the fds they open, dup and close; a reader of a path still checks
   dev/ino against the real fd, so an fd changed behind both (an fd received
   over a socket) never reads as the wrong file.
   Private memory: fork copies it with the fd table, exec drops both. */
enum { LX_FP_FD_NONE = 0, LX_FP_FD_HOST = 1 };
/* flags */
#define LX_FP_FD_DIR     1u   /* a directory */
#define LX_FP_FD_NATIVE  2u   /* its listing is the host fd's own */
#define LX_FP_FD_STREAM  4u   /* the supervisor serves its listing and seeks */
#define LX_FP_FD_BYSUP   8u   /* written by the supervisor: its table agrees */
#define LX_FP_FD_CLOSED 16u   /* closed in the guest: drop it from the table */
struct lx_fp_fd {
    uint32_t seq;       /* seqlock */
    uint8_t  kind;      /* HOST: a host file or dir at path. NONE: something
                           only the supervisor (or nobody) knows */
    uint8_t  flags;
    uint16_t len;
    uint32_t gen;       /* table.dir_gen when the path was last known right */
    uint32_t pad;
    uint64_t dev, ino;
    char path[LX_FP_FD_PATH];
};

/* Shared by every process, at base + LX_FP_STATS_OFF (the page after the
   table in the same file, mapped writable). */
struct lx_fp_stats {
    uint64_t hits;      /* calls answered in the guest */
    uint32_t evsum;     /* bumped with any ev[] */
    uint32_t pad;
    uint32_t ev[LX_FP_CWD_SLOTS];   /* bumped when a process (by tgid) logs an fd event */
};

/* At offset 0 of the blob; offsets are from the blob start. */
struct lx_fp_header {
    uint64_t magic;
    uint32_t version;
    uint32_t common;       /* stub entry */
    uint32_t guard_start;  /* [guard_start, guard_end): faults resume at fault_ret */
    uint32_t guard_end;
    uint32_t fault_ret;
    uint32_t pad;
};

/* FNV-1a, never 0 (0 marks an empty slot). */
static inline uint64_t lx_fp_hash(const char* s, uint32_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (uint32_t i = 0; i < n; ++i) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    h ^= (uint64_t)n << 56;
    return h ? h : 1;
}

#endif
