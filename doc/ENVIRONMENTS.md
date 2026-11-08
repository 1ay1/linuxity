# Environments

An environment is a rootfs plus everything you'd want to tune about the
Linux system on top of it: hostname, user, shell, DNS, limits, mounts,
services. It's described by one file, `env.vibe`, written in
[VIBE](https://github.com/1ay1/vibe). Frontends (the Android app, a settings
UI) edit the same file through `linuxity env set` or the JSON schema.

```sh
linuxity env create arch ~/arch/root.x86_64
linuxity env adduser arch ayush --sudo
linuxity env set arch login.user ayush
linuxity env set arch system.hostname pixel
linuxity shell arch            # starts it if needed, opens a login shell
```

## Layout

Everything lives under `$LINUXITY_HOME` (default
`~/.local/share/linuxity`; the Android app points it at its files dir):

```
envs/<name>/
  env.vibe         the config
  upper/           every write the guest made (the rootfs itself is never touched)
  snapshots/<s>/   saved copies of upper/, plus the env.vibe of the time
  logs/            linuxity.log for a running instance, <service>.log per service
  run/             control socket, pid, lock (only while running)
```

Because the rootfs is read-only and all writes land in `upper/`, these are
cheap and safe:

```sh
linuxity env snapshot arch before-upgrade
linuxity env restore arch before-upgrade
linuxity env reset arch          # back to the clean image
```

## env.vibe

A new env starts from a commented template. A fuller example:

```vibe
name arch
rootfs /home/ayush/arch/root.x86_64

system {
  hostname pixel
  timezone Europe/Berlin
}

login {
  user ayush
  shell /usr/bin/zsh
  umask 022
}

network {
  dns [ 1.1.1.1 9.9.9.9 ]
}

limits {
  cpus 2
  memory 2G
  pids 4096
}

env {
  EDITOR nvim
}

mount {
  phone { host /sdcard at /mnt/phone }
}

service {
  sshd { command [ /usr/bin/sshd -D -p 8022 ] restart on-failure }
}
```

`linuxity env check <name>` validates it. Unknown keys are warnings with a
"did you mean" hint; a wrong type is an error, and an env with errors won't
start. `linuxity env set` edits the file in place and keeps your comments.

## Keys

`linuxity env schema` prints all of this as JSON (type, default, doc,
choices, and whether it applies live). That output is what a settings
screen should be built from.

| key | type | default | |
|---|---|---|---|
| `name` | string | - | Display name of the environment. |
| `rootfs` | string | - | Host directory holding the distro tree. Never written to. |
| `upper` | string | - | Host directory that receives every write (default: `<env>/upper`). |
| `system.hostname` | string | `linuxity` | Hostname the guest sees (`uname -n`, `/etc/hostname`). Applies live. |
| `system.kernel-release` | string | `6.6.0-linuxity` | Kernel release the guest sees (`uname -r`). |
| `system.host-hardware` | boolean | `true` | Show the real CPU, memory, thermal and battery data instead of a synthetic machine. |
| `system.host-pids` | boolean | `false` | Share the host's pid space, like `docker --pid=host`. |
| `system.timezone` | string | - | Timezone name, e.g. `Europe/Berlin` (sets `TZ`). |
| `system.locale` | string | - | Locale, e.g. `en_US.UTF-8`. Empty: the best one the image can load. |
| `network.dns` | strings | - | Nameservers. Empty: the image's own, else the host's, else public ones. Applies live. |
| `network.manage-dns` | boolean | `true` | Serve a `resolv.conf` when the image has none. |
| `login.user` | string | `root` | User sessions run as. Must exist in the guest's `/etc/passwd`. |
| `login.shell` | string | - | Login shell. Empty: the user's shell from `/etc/passwd`. |
| `login.cwd` | string | - | Starting directory. Empty: the user's home. |
| `login.command` | strings | - | What a new session runs. Empty: the login shell with `-l`. |
| `login.umask` | string | `022` | File creation mask, octal. |
| `login.clean-env` | boolean | `true` | Start from an empty environment instead of the host's. |
| `login.pass-env` | strings | `TERM COLORTERM DISPLAY WAYLAND_DISPLAY` | Host variables kept when clean-env is on. |
| `limits.cpus` | number | - | CPU ceiling in cores, e.g. `1.5`. |
| `limits.memory` | size | - | Memory ceiling, e.g. `2G`. |
| `limits.memory-swap` | size | - | Memory plus swap ceiling. |
| `limits.pids` | integer | - | Most tasks the guest may run at once. |
| `limits.cpuset` | string | - | CPUs to pin to, e.g. `0-3`. |
| `storage.persist` | boolean | `true` | Keep writes across runs. Off: every run starts clean. |
| `storage.private-tmp` | boolean | `true` | Give the guest its own `/tmp`. |
| `compat.seccomp` | boolean | `true` | The seccomp fast path. Off is slower; for debugging. |
| `compat.fifos` | `auto`/`emulate` | `auto` | Named FIFOs: real where the host allows them, or always emulated. |
| `compat.sysv-ipc` | `auto`/`emulate` | `auto` | SysV IPC: the host's, or always emulated. |
| `compat.nl80211` | `auto`/`emulate` | `auto` | Wifi netlink: the host's, or always emulated. |
| `compat.hardlinks` | `auto`/`emulate` | `auto` | Hard links: real where allowed, or always emulated. |
| `compat.pacman-overwrite` | boolean | `true` | Pass `--overwrite "*"` to pacman so bootstrap images can install packages. |
| `bridge.enabled` | boolean | `true` | Let the guest open links, use the clipboard and post notifications on the host. |
| `bridge.host-fallback` | boolean | `true` | With no app attached, use host tools (`xdg-open`, `wl-copy`, `notify-send`). |
| `debug.trace` | string | - | Log every syscall decision: a file path, or stderr. |
| `debug.log` | string | - | Where a running instance logs (default: `<env>/logs/linuxity.log`). |

Named tables:

| key | |
|---|---|
| `env.<NAME>` | A variable for every session and service. |
| `mount.<name>.host`, `.at` | Expose a host directory at a guest path. Writes land on the real files. |
| `service.<name>.command` | Program and arguments (required). |
| `service.<name>.user`, `.cwd` | Defaults: `login.user`, the user's home. |
| `service.<name>.autostart` | Start with the instance (default `true`). |
| `service.<name>.restart` | `no`, `on-failure` (default) or `always`. |
| `service.<name>.env.<NAME>` | A variable for this service only. |

Every key also has a flag for one-off runs: `--hostname`, `--user`,
`--cwd`, `--umask`, `--dns`, `-e K=V`, `--clean-env`, `--timezone`,
`--locale`, plus the existing `--root`, `--persist`, `--bind`, `--cpus`,
`--memory`, `--pids`. Flags after `--env <name>` override that env.

## Running

There are two ways to run an environment.

`linuxity run <env> [-- cmd ...]` runs one program as pid 1 in the
foreground, the same way plain `linuxity --root ...` always has.

`linuxity up <env>` starts an **instance**: one linuxity kernel that keeps
running in the background. It has its own pid 1, and every session and
service shares one process table, one set of SysV IPC, one hostname. So two
terminal tabs see each other's processes, and a server started in one keeps
running when the tab closes.

```sh
linuxity up arch
linuxity shell arch                 # a login shell on a fresh pty
linuxity exec arch -- make -j8      # a command, output on your terminal
linuxity ps arch
linuxity kill arch 42 TERM
linuxity svc arch restart sshd
linuxity logs arch sshd -f
linuxity status arch
linuxity down arch
```

`shell` and `exec` start the instance if it isn't running. Exit codes come
back from the session. `-t`/`-T` force a pty on or off.

### Reload

After an edit (`env set` does this for you), `linuxity reload <env>`
applies what it can to the running instance: the hostname, DNS, and
services (new ones start, removed ones stop). Anything else is reported as
needing a restart.

### Services

Each `service` runs as a session of its own, logs to
`logs/<name>.log`, and restarts as `restart` says, with backoff starting
at 100ms. Five exits within two seconds of starting each mark it
`failed` instead of looping forever.

## The bridge

Inside an instance, guest programs can reach the host. `xdg-open`,
`wl-copy`, `wl-paste` and `notify-send` are on every session's `PATH` (from
`/run/linuxity/bin`, a small static helper), so ordinary tools just work:

```sh
xdg-open https://example.com       # opens in the phone's browser
xdg-open report.pdf                # the host gets the real file path
echo hi | wl-copy; wl-paste        # the host clipboard
notify-send "build done" "all green"
```

A frontend that subscribed with `"bridge": true` handles these. With none
attached, the instance uses the host's own tools, unless
`bridge.host-fallback` is off. On a desktop that's `xdg-open`, `wl-copy`,
`wl-paste` and `notify-send`. On Android it's `am start` for URLs and
`cmd notification post`; files and the clipboard need the app. A missing
tool comes back to the guest as an error with a nonzero exit.

## The control protocol

Frontends talk to an instance over `run/control.sock`: newline-delimited
JSON on a unix stream socket. Where the host forbids a filesystem socket
(some Android SELinux policies), the instance binds the abstract name
`linuxity-ctl/<hash of the path>` instead, and clients try both. Only the
same uid may connect.

Each request gets one reply line, `{"ok":true,...}` or
`{"ok":false,"error":"..."}`.

| op | fields | reply |
|---|---|---|
| `hello` | | `env`, `pid`, `protocol` (1), `sessions` |
| `spawn` | `argv`, `user`, `cwd`, `env` {}, `fds` (0, 1 or 3), `wait` | `pid` |
| `ps` | | `procs`: `pid ppid uid user comm cmdline state rss_kb session [service]` |
| `kill` | `pid`, `signal`, `session` (whole session) | |
| `status` | | uptime, hostname, limits, `sessions`, `services`, `notes` (startup events) |
| `svc` | `action` (`list`/`start`/`stop`/`restart`), `name` | `services` for list |
| `reload` | | `applied` [], `restart_needed` |
| `subscribe` | `events`, `bridge` | then event lines (below) |
| `bridge-reply` | `id`, `ok`, `text`, `error` | none |
| `down` | | then the socket closes once everything has exited |

`spawn` takes its fds as `SCM_RIGHTS` on the same message: one fd is a
terminal (stdin, stdout and stderr, and it becomes the controlling tty),
three are stdin, stdout and stderr. This is how the app hands over its pty.
With `wait`, the reply is followed by `{"event":"exit","pid":N,"code":C}`
when the session ends.

Event lines, after `subscribe`:

```json
{"event":"exit","pid":7,"code":0}
{"event":"service","name":"sshd","state":"restarting","code":1}
{"event":"bridge","id":3,"op":"open","url":"https://example.com"}
{"event":"bridge","id":4,"op":"open","path":"/home/ayush/a.pdf","host_path":"/data/.../upper/home/ayush/a.pdf"}
{"event":"bridge","id":5,"op":"copy","text":"..."}
{"event":"bridge","id":6,"op":"paste"}
{"event":"bridge","id":7,"op":"notify","title":"...","body":"..."}
```

Answer every bridge event with `bridge-reply` (for `paste`, put the text in
`text`).

## Status events

`--status-fd N` (on any run, `up` or `run`) writes what the runtime
decided as JSON lines to fd N, so a frontend doesn't have to scrape
stderr. Each has `event` and a human `text`:

```json
{"event":"limits","text":"bounded via setrlimit (coarse): mem=1.0G","cgroup":false}
{"event":"storage","text":"persistent overlay upper at ...","upper":"...","persist":true}
{"event":"dns","text":"dns from host /etc/resolv.conf (192.168.0.1)","origin":"host /etc/resolv.conf","servers":["192.168.0.1"]}
{"event":"compat","text":"host forbids mkfifo; emulating FIFOs","feature":"fifos","mode":"emulated"}
{"event":"bind","text":"bind /mnt/phone -> /sdcard","at":"/mnt/phone","host":"/sdcard"}
{"event":"ready","text":"instance arch is up (pid 1234)","env":"arch","pid":1234,"socket":"...","abstract":false}
{"event":"service","text":"service sshd started (pid 3)","name":"sshd","state":"running","pid":3}
{"event":"stopping"} {"event":"down"}
```

`--quiet` drops the stderr copies. A running instance also replays them in
`status` under `notes`.

## Users

`login.user` must exist in the guest. `linuxity env adduser <env> <user>
[--sudo]` runs the image's own `useradd` (or busybox `adduser`) as root, and
with `--sudo` adds the user to `wheel` and allows that group in
`/etc/sudoers.d`. A non-root session gets that user's uid, gid, groups and
home, and no capabilities, and file permissions are checked against it
like a real kernel would.
