// linuxity-bridge: the guest side of the host bridge.
//
// One static binary, several names (busybox style):
//
//   xdg-open URL|FILE      open on the host (the phone, or the desktop)
//   wl-copy / xclip -i     copy stdin (or the arguments) to the host clipboard
//   wl-paste / xclip -o    print the host clipboard
//   notify-send TITLE [BODY]
//   linuxity-bridge open|copy|paste|notify ...
//
// It talks to the instance through $LINUXITY_BRIDGE, an abstract unix
// socket ("@name"), one JSON line each way. Static and libc-only so it runs
// in any distro the guest has.
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void put_json_string(char** out, size_t* len, size_t* cap, const char* s) {
    for (const char* p = "\""; *p; ++p) {
        if (*len + 8 >= *cap) { *cap *= 2; *out = realloc(*out, *cap); }
        (*out)[(*len)++] = *p;
    }
    for (; *s; ++s) {
        if (*len + 8 >= *cap) { *cap *= 2; *out = realloc(*out, *cap); }
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { (*out)[(*len)++] = '\\'; (*out)[(*len)++] = (char)c; }
        else if (c == '\n') { (*out)[(*len)++] = '\\'; (*out)[(*len)++] = 'n'; }
        else if (c == '\t') { (*out)[(*len)++] = '\\'; (*out)[(*len)++] = 't'; }
        else if (c < 0x20) *len += (size_t)snprintf(*out + *len, 8, "\\u%04x", c);
        else (*out)[(*len)++] = (char)c;
    }
    if (*len + 2 >= *cap) { *cap *= 2; *out = realloc(*out, *cap); }
    (*out)[(*len)++] = '"';
}

static void put_raw(char** out, size_t* len, size_t* cap, const char* s) {
    size_t n = strlen(s);
    while (*len + n + 1 >= *cap) { *cap *= 2; *out = realloc(*out, *cap); }
    memcpy(*out + *len, s, n);
    *len += n;
}

// Find "key":"value" in a flat JSON reply and unescape the value.
static char* json_get(const char* j, const char* key) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":", key);
    const char* p = strstr(j, pat);
    if (!p) return NULL;
    p += strlen(pat);
    if (*p != '"') {
        size_t n = strcspn(p, ",}");
        char* v = malloc(n + 1);
        memcpy(v, p, n);
        v[n] = 0;
        return v;
    }
    ++p;
    char* v = malloc(strlen(p) + 1);
    size_t k = 0;
    for (; *p && *p != '"'; ++p) {
        if (*p == '\\' && p[1]) {
            ++p;
            switch (*p) {
                case 'n': v[k++] = '\n'; break;
                case 't': v[k++] = '\t'; break;
                case 'r': v[k++] = '\r'; break;
                case 'u': {
                    unsigned cp = 0;
                    for (int i = 1; i <= 4 && p[i]; ++i) {
                        char c = p[i];
                        cp = cp * 16 + (unsigned)(c <= '9' ? c - '0' : (c | 32) - 'a' + 10);
                    }
                    p += 4;
                    if (cp < 0x80) v[k++] = (char)cp;
                    else if (cp < 0x800) { v[k++] = (char)(0xC0 | (cp >> 6)); v[k++] = (char)(0x80 | (cp & 63)); }
                    else { v[k++] = (char)(0xE0 | (cp >> 12)); v[k++] = (char)(0x80 | ((cp >> 6) & 63)); v[k++] = (char)(0x80 | (cp & 63)); }
                    break;
                }
                default: v[k++] = *p;
            }
        } else {
            v[k++] = *p;
        }
    }
    v[k] = 0;
    return v;
}

static char* read_all(FILE* f) {
    size_t cap = 4096, len = 0;
    char* b = malloc(cap);
    size_t n;
    while ((n = fread(b + len, 1, cap - len - 1, f)) > 0) {
        len += n;
        if (len + 1 >= cap) { cap *= 2; b = realloc(b, cap); }
    }
    b[len] = 0;
    return b;
}

static int usage(void) {
    fputs("usage: linuxity-bridge open URL|FILE | copy [TEXT] | paste | notify TITLE [BODY]\n", stderr);
    return 2;
}

int main(int argc, char** argv) {
    const char* self = strrchr(argv[0], '/');
    self = self ? self + 1 : argv[0];

    const char* op = NULL;
    int first = 1;
    if (!strcmp(self, "xdg-open") || !strcmp(self, "open") || !strcmp(self, "linuxity-open")) op = "open";
    else if (!strcmp(self, "wl-copy") || !strcmp(self, "linuxity-copy") || !strcmp(self, "pbcopy")) op = "copy";
    else if (!strcmp(self, "wl-paste") || !strcmp(self, "linuxity-paste") || !strcmp(self, "pbpaste")) op = "paste";
    else if (!strcmp(self, "notify-send") || !strcmp(self, "linuxity-notify")) op = "notify";
    else if (!strcmp(self, "xclip") || !strcmp(self, "xsel")) {
        op = "copy";
        for (int i = 1; i < argc; ++i)
            if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) op = "paste";
        first = argc;   // xclip's own flags aren't text
    } else {
        if (argc < 2) return usage();
        op = argv[1];
        first = 2;
    }
    // skip options of the tools we stand in for (wl-paste -n, notify-send -u ...)
    while (first < argc && argv[first][0] == '-' && argv[first][1]) {
        if (!strcmp(op, "notify") && (!strcmp(argv[first], "-u") || !strcmp(argv[first], "-t") ||
                                      !strcmp(argv[first], "-i") || !strcmp(argv[first], "-a")))
            ++first;
        ++first;
    }

    const char* bridge = getenv("LINUXITY_BRIDGE");
    if (!bridge || !*bridge) {
        fprintf(stderr, "%s: not running under a linuxity instance (no $LINUXITY_BRIDGE)\n", self);
        return 1;
    }

    size_t cap = 256, len = 0;
    char* req = malloc(cap);
    put_raw(&req, &len, &cap, "{\"op\":");
    put_json_string(&req, &len, &cap, op);

    if (!strcmp(op, "open")) {
        if (first >= argc) return usage();
        const char* t = argv[first];
        if (strstr(t, "://") || !strncmp(t, "mailto:", 7) || !strncmp(t, "tel:", 4)) {
            put_raw(&req, &len, &cap, ",\"url\":");
            put_json_string(&req, &len, &cap, t);
        } else {
            char abs[4096];
            if (t[0] == '/') snprintf(abs, sizeof abs, "%s", t);
            else {
                char cwd[2048];
                if (!getcwd(cwd, sizeof cwd)) cwd[0] = 0;
                snprintf(abs, sizeof abs, "%s/%s", cwd, t);
            }
            if (access(abs, F_OK) != 0) { fprintf(stderr, "%s: %s: %s\n", self, t, strerror(errno)); return 1; }
            put_raw(&req, &len, &cap, ",\"path\":");
            put_json_string(&req, &len, &cap, abs);
        }
    } else if (!strcmp(op, "copy")) {
        char* text;
        if (first < argc) {
            size_t n = 0;
            for (int i = first; i < argc; ++i) n += strlen(argv[i]) + 1;
            text = malloc(n + 1);
            text[0] = 0;
            for (int i = first; i < argc; ++i) { if (i > first) strcat(text, " "); strcat(text, argv[i]); }
        } else {
            text = read_all(stdin);
        }
        put_raw(&req, &len, &cap, ",\"text\":");
        put_json_string(&req, &len, &cap, text);
    } else if (!strcmp(op, "notify")) {
        put_raw(&req, &len, &cap, ",\"title\":");
        put_json_string(&req, &len, &cap, first < argc ? argv[first] : "linuxity");
        put_raw(&req, &len, &cap, ",\"body\":");
        put_json_string(&req, &len, &cap, first + 1 < argc ? argv[first + 1] : "");
    } else if (strcmp(op, "paste") != 0) {
        return usage();
    }
    put_raw(&req, &len, &cap, "}\n");

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    const char* name = bridge[0] == '@' ? bridge + 1 : bridge;
    size_t n = strlen(name);
    if (n > sizeof sa.sun_path - 2) n = sizeof sa.sun_path - 2;
    socklen_t alen;
    if (bridge[0] == '@') {
        memcpy(sa.sun_path + 1, name, n);
        alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
    } else {
        memcpy(sa.sun_path, name, n);
        alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + 1);
    }
    if (fd < 0 || connect(fd, (struct sockaddr*)&sa, alen) != 0) {
        fprintf(stderr, "%s: cannot reach the linuxity bridge: %s\n", self, strerror(errno));
        return 1;
    }
    for (size_t off = 0; off < len;) {
        ssize_t w = write(fd, req + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; perror(self); return 1; }
        off += (size_t)w;
    }
    // one reply line
    size_t rcap = 4096, rlen = 0;
    char* rep = malloc(rcap);
    for (;;) {
        if (rlen + 1 >= rcap) { rcap *= 2; rep = realloc(rep, rcap); }
        ssize_t r = read(fd, rep + rlen, rcap - rlen - 1);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) break;
        rlen += (size_t)r;
        rep[rlen] = 0;
        if (memchr(rep, '\n', rlen)) break;
    }
    rep[rlen] = 0;
    close(fd);
    if (!strstr(rep, "\"ok\":true")) {
        char* e = json_get(rep, "error");
        fprintf(stderr, "%s: %s\n", self, e ? e : "the host refused");
        return 1;
    }
    if (!strcmp(op, "paste")) {
        char* t = json_get(rep, "text");
        if (t) fputs(t, stdout);
    }
    return 0;
}
