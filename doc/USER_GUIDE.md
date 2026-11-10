# linuxity user guide

linuxity runs a real Linux distro (Ubuntu, Alpine, Arch, or any rootfs you
have) without a VM, without root, and without changing your system. Programs
run at full native speed on your CPU; linuxity sits between them and the
kernel, so they see their own `/`, their own users, their own hostname and
their own process list.

It's one binary, `linuxity`. It's the command you type and also the thing
that keeps an environment running in the background.

---

## Contents

1. [Quick start](#1-quick-start)
2. [Ideas](#2-ideas)
3. [Making environments](#3-making-environments)
4. [Using an environment](#4-using-an-environment)
5. [Users and sudo](#5-users-and-sudo)
6. [Settings](#6-settings)
7. [Every setting](#7-every-setting)
8. [Services](#8-services)
9. [Snapshots, reset, export](#9-snapshots-reset-export)
10. [Sharing files with the host](#10-sharing-files-with-the-host)
11. [The host bridge](#11-the-host-bridge)
12. [Resource limits](#12-resource-limits)
13. [One-off runs without an environment](#13-one-off-runs-without-an-environment)
14. [Android](#14-android)
15. [Where things live](#15-where-things-live)
16. [Scripting and JSON](#16-scripting-and-json)
17. [Troubleshooting](#17-troubleshooting)
18. [Command reference](#18-command-reference)

---

## 1. Quick start

```sh
linuxity new ubuntu          # download, verify, unpack; asks for your user name
linuxity                     # a shell in it
```

That's it. Inside you're a normal user with `sudo`, `apt` works, and the
hostname is `ubuntu`. Leave with `exit`; the environment keeps running in the
background so a second terminal joins the same system:

```sh
linuxity exec -- htop        # in another terminal: same processes, same files
linuxity stop                # when you're done
```

---

## 2. Ideas

**Environment.** A distro plus its settings. It has a name (`ubuntu`, `dev`,
`arch`), a root filesystem, and a config file `env.vibe`. You can have as
many as you like. One of them is the **default**: plain `linuxity` opens it,
and any command that takes an environment name uses it when you leave the
name out.

**Image and changes.** The distro's files (the image) are never modified.
Everything you change, install or delete is recorded in a separate layer next
to it. That's why reset and snapshots are instant and safe.

**Instance.** When you open a shell, linuxity starts the environment once in
the background. Every shell, command and service after that joins the same
running system: they share one process list, one hostname, one set of IPC.
`linuxity stop` ends it. `linuxity run` is the exception: it runs one program
on its own, in the foreground, and ends with it.

**Root without root.** Inside, you can be root, install packages, `chown`
files and run `sudo`, but none of it needs or gets real root on your machine.
Owners and permissions are tracked by linuxity and shown to programs as
they'd expect.

---

## 3. Making environments

### From the catalog

```sh
linuxity images              # what's available for this CPU
linuxity new alpine          # named "alpine"
linuxity new ubuntu dev      # named "dev"
```

| distro | | download | notes |
|---|---|---|---|
| `alpine` | Alpine Linux 3.24 | ~4 MB | tiny, musl, `apk` |
| `ubuntu` | Ubuntu 24.04 LTS | ~30 MB | glibc, `apt` |
| `arch` | Arch Linux / Arch Linux ARM | 150 / 830 MB | `pacman`; x86-64 needs `zstd` installed |

`new` downloads the image (with `curl` or `wget`), checks it against the
checksum its publisher lists, unpacks it, runs the distro's first-time setup
(Arch: mirror and keyring), and asks for your user name. Downloads are kept,
so a second `new` of the same distro is instant.

Options:

| | |
|---|---|
| `--user NAME` | create this user without asking |
| `--root` | don't create a user; stay root |
| `--password` | give the user a password (asked twice); otherwise sudo needs none |
| `--file PATH` | use an image you already downloaded |
| `--checksum sha256:HEX` | check `--file` against this |
| `--no-verify` | skip the checksum (not recommended) |

The first environment you make becomes the default.

### Your own rootfs

```sh
linuxity import mydistro rootfs.tar.gz      # .tar, .tar.gz, .tar.xz, .tar.zst
linuxity import work ~/some/extracted/root  # a directory is used in place, never written to
```

`import` accepts a tarball that wraps everything in one top directory, and
takes `--user NAME` or `--root` like `new`. The CPU has to match: an aarch64
rootfs won't run on an x86-64 machine (linuxity runs code natively and has no
emulator).

### Managing them

```sh
linuxity list                # all of them, running or stopped
linuxity default dev         # what plain `linuxity` opens
linuxity rename dev work
linuxity rm work             # asks first; --yes to skip
```

`rm` deletes the environment and everything in it. If it was imported from a
directory, that directory itself is kept. `rm`, `reset`, `restore` and
`rename` always need the name typed out; they never fall back to the default.

---

## 4. Using an environment

```sh
linuxity                          # login shell in the default env
linuxity shell dev                # in a specific one
linuxity exec -- make -j8         # run a command, output in your terminal
linuxity exec dev -- python3 app.py
```

`exec` options:

| | |
|---|---|
| `-u USER` | run as this user (default: the env's login user) |
| `-C DIR` | start in this directory |
| `-e KEY=VALUE` | set a variable (repeatable) |
| `-t` / `-T` | force a terminal on / off (default: a terminal if you're in one) |

A bare command name (`htop`) is looked up on the guest's `PATH`. The exit
code is the program's, so `linuxity exec -- false` exits 1.

### Background and status

```sh
linuxity start               # start without opening a shell (services come up)
linuxity status              # what's running, how limits are held, DNS, notes
linuxity ps                  # processes inside
linuxity kill 1234           # signal one (TERM by default)
linuxity kill 1234 KILL
linuxity stop                # stop everything in it
```

`shell` and `exec` start the environment if it isn't running.

### One program on its own

```sh
linuxity run -- uname -a          # pid 1, foreground, ends with the program
linuxity run --fresh -- sh        # throwaway: changes are discarded at exit
linuxity run -v ~/proj:/work -- make
```

`run` is like `docker run`: it doesn't use or need the background instance.
`--fresh` starts from the clean image (users you added later aren't in it,
so it runs as root then).

---

## 5. Users and sudo

```sh
linuxity adduser ayush               # sudo, no password; new shells log in as ayush
linuxity adduser ayush --password    # sudo asks for the password you set
linuxity users                       # who can log in, who has sudo, the default
```

`adduser` does the whole job inside the environment:

- creates the user with a home directory and their own group, using the
  distro's own tools;
- installs `sudo` if the image doesn't have it (apt, apk, pacman, dnf,
  zypper);
- grants sudo with a checked rule in `/etc/sudoers.d/90-linuxity-USER`;
- tests `sudo -n true` as the user before saying it worked;
- makes them the login user, so new shells use them right away.

Options: `--no-sudo`, `--no-default` (don't make them the login user),
`--shell /usr/bin/zsh`, `--password-stdin` (read the password from a pipe).
Running it again for an existing user updates that user.

Switch who new shells log in as:

```sh
linuxity set user=root
linuxity exec -u root -- id          # just once
```

Inside, a normal user is held to normal permissions: `touch /etc/x` fails,
`sudo touch /etc/x` works.

---

## 6. Settings

Each environment's settings live in `env.vibe`. You rarely need to open it.

```sh
linuxity get                         # every setting and its value
linuxity get hostname
linuxity set hostname=devbox
linuxity set memory=2G cpus=2 timezone=Europe/Berlin
linuxity set dns 1.1.1.1 9.9.9.9     # a list
linuxity set env.EDITOR=nvim         # an environment variable
linuxity set timezone=               # empty = back to the default
linuxity edit                        # open env.vibe in $EDITOR
```

Short names work when they're unique (`hostname` = `system.hostname`,
`memory` = `limits.memory`, `user` = `login.user`). Values are checked: a
typo gets "did you mean", a wrong type is refused. `set` edits the file in
place and keeps your comments.

**Live or restart.** Changes to hostname, DNS, the login user/shell/dir/
command and services apply to the running environment immediately. Anything
else says "restart it for this to take effect": `linuxity stop` then use it
again.

`env.vibe` looks like this:

```vibe
name dev
rootfs rootfs

system {
  hostname devbox
  timezone Europe/Berlin
}

login {
  user ayush
  shell /usr/bin/zsh
}

network {
  dns [ 1.1.1.1 9.9.9.9 ]
}

limits {
  memory 2G
  pids 4096
}

env {
  EDITOR nvim
}

mount {
  code { host /home/ayush/code at /code }
}

service {
  web { command [ python3 -m http.server 8000 ] restart on-failure }
}
```

`linuxity check` validates it; an environment with errors won't start.

---

## 7. Every setting

`live` = applies to a running environment without a restart.

| setting | default | |
|---|---|---|
| `system.hostname` | env name | hostname (`uname -n`, `/etc/hostname`, `/etc/hosts`). live |
| `system.kernel-release` | `6.6.0-linuxity` | what `uname -r` says |
| `system.timezone` | image's | e.g. `Europe/Berlin` |
| `system.locale` | best available | e.g. `en_US.UTF-8` |
| `system.host-hardware` | `true` | show the real CPU, memory, sensors, battery |
| `system.host-pids` | `false` | see all host processes, like `docker --pid=host` |
| `network.dns` | image's, else host's, else public | nameservers. live |
| `network.manage-dns` | `true` | serve `resolv.conf` when the image has none |
| `network.manage-hosts` | `true` | add the hostname to `/etc/hosts` |
| `login.user` | `root` | who shells and commands run as. live |
| `login.shell` | user's | login shell. live |
| `login.cwd` | user's home | starting directory. live |
| `login.command` | the login shell | what a new shell session runs. live |
| `login.umask` | `022` | file creation mask |
| `login.clean-env` | `true` | don't inherit the host's environment variables |
| `login.pass-env` | `TERM COLORTERM DISPLAY WAYLAND_DISPLAY` | the ones that do pass |
| `limits.cpus` | none | CPU ceiling in cores, e.g. `1.5` |
| `limits.memory` | none | memory ceiling, e.g. `2G` |
| `limits.memory-swap` | none | memory plus swap |
| `limits.pids` | none | most processes and threads at once |
| `limits.cpuset` | all | CPUs to use, e.g. `0-3` |
| `storage.persist` | `true` | keep changes; off = every start is clean |
| `storage.private-tmp` | `true` | its own `/tmp` |
| `bridge.enabled` | `true` | `xdg-open`, clipboard, notifications reach the host |
| `bridge.host-fallback` | `true` | use host tools when no app is attached |
| `compat.fifos`, `compat.sysv-ipc`, `compat.nl80211`, `compat.hardlinks` | `auto` | `emulate` forces linuxity's own version |
| `compat.pacman-overwrite` | `true` | lets bootstrap Arch images install packages |
| `debug.trace` | off | log every syscall decision to a file |
| `debug.log` | `logs/linuxity.log` | where a running environment logs |

Named entries:

| | |
|---|---|
| `env.NAME` | a variable for every session and service |
| `mount.NAME.host` / `.at` | a host folder and where it appears inside |
| `service.NAME.command` | a background program (see below) |
| `service.NAME.user`, `.cwd`, `.autostart`, `.restart`, `.env.NAME` | its options |

`linuxity schema` prints all of this as JSON.

---

## 8. Services

A service is a program that runs in the background while the environment is
up: a web server, `sshd`, a database.

```sh
linuxity set service.web.command="python3 -m http.server 8000"
linuxity set service.web.restart=always
linuxity svc                    # list with state, pid, restarts
linuxity svc restart web
linuxity svc stop web
linuxity logs web -f            # follow its output
linuxity logs                   # linuxity's own log
```

`restart` is `no`, `on-failure` (default) or `always`. Restarts back off from
100 ms up to 30 s; a service that dies within two seconds five times in a
row is marked `failed` instead of looping. `autostart false` keeps it from
starting with the environment. Adding or removing a service applies live.

---

## 9. Snapshots, reset, export

```sh
linuxity snapshot before-upgrade     # save the current state
linuxity snapshots                   # list them
linuxity restore dev before-upgrade  # go back (stop the env first)
linuxity drop-snapshot dev before-upgrade
linuxity reset dev                   # back to the freshly made state
```

A snapshot saves your changes and settings, not the image, so it's small.
`reset` throws away every change; users you added go with it.

Move an environment somewhere else, or make a template:

```sh
linuxity export dev dev.tar.gz       # everything as it looks inside
linuxity import dev2 dev.tar.gz      # anywhere with the same CPU
```

---

## 10. Sharing files with the host

```sh
linuxity set mount.code.host=/home/ayush/code mount.code.at=/code
linuxity exec -- ls /code
```

A mount shows a host folder inside the environment. Writes go straight to
the real files. For one run, `linuxity run -v ~/proj:/work -- make`.

Everything else inside is kept apart from your system: a program writing to
`/etc` or `/usr` changes the environment's copy only.

---

## 11. The host bridge

Inside a running environment these commands reach the host:

```sh
xdg-open https://example.com     # opens in your browser
xdg-open report.pdf              # opens with the host's app
echo hi | wl-copy                # host clipboard
wl-paste
notify-send "build done" "all green"
```

On a desktop they use the host's `xdg-open`, `wl-copy`, `wl-paste` and
`notify-send`. In the Android app they open the phone's chooser, use its
clipboard and post real notifications. Turn it off with
`linuxity set bridge.enabled=false`.

---

## 12. Resource limits

```sh
linuxity set memory=2G cpus=1.5 pids=512 cpuset=0-3
```

Programs inside are told the same numbers (`nproc`, `free`, `/proc/meminfo`),
so they size themselves to the limit.

How each limit is held depends on the host. `linuxity status` says which:

| limit | with cgroups (most Linux desktops) | without (Android, some containers) |
|---|---|---|
| `memory` | exact | per-process address-space cap |
| `cpus` | exact | not enforced, only reported |
| `memory-swap` | exact | not enforced |
| `pids` | exact | enforced by linuxity |
| `cpuset` | exact | enforced (CPU affinity) |

`linuxity run` gets exact cgroup limits through `systemd-run` where
available. A background environment started with `start`/`shell` uses them
only if your own session already delegates the controllers.

---

## 13. One-off runs without an environment

linuxity also works on any extracted rootfs directly, no environment needed:

```sh
linuxity --root ~/arch/root.x86_64 /usr/bin/bash
linuxity --root ./rootfs --persist ./changes --memory 1G /bin/sh -c 'apk add curl'
linuxity --env dev --memory 512M /usr/bin/python3     # an env's settings, overridden
```

Every setting has a flag; `linuxity help --all` lists them (`--hostname`,
`--user`, `--cwd`, `--dns`, `-e K=V`, `--bind`, `--cpus`, `--memory`,
`--pids`, `--cpuset`, `--host-pids`, `--clean-env`, `--status-fd`, `--quiet`,
...). Without `--persist`, changes vanish when the program exits.

---

## 14. Android

The linuxity app is a terminal with the runtime inside.

- **First launch** shows a welcome screen: pick Alpine, Ubuntu or Arch, give
  it a name and your user name, tap create. The app downloads, verifies and
  sets it up.
- **The top bar** shows the environment name. Tap it to switch, add or
  remove environments. `≡` opens the environment's settings (users,
  hostname, DNS, limits, snapshots, reset); `⚙` is the terminal's look and
  feel; `⌕` searches the scrollback.
- **Keeps running** in the background with a notification; "Stop" in the
  notification ends it.
- **Keyboard**: the extra key row has Esc, Tab, Ctrl, Alt, arrows and paste.
  Long-press text to select and copy.

Things that are different on a phone:

- The app is a sideload build (it targets an older Android API so it may
  run the distro's programs); it can't be published on Google Play.
- `wl-paste` only works while the app is on screen; Android only lets the
  front app read the clipboard.
- CPU and swap limits aren't enforced (see section 12).
- From `adb shell` the same CLI works with the app's binary; set
  `LINUXITY_HOME` to the app's `files/linuxity` dir.

### macOS (Apple Silicon)

The same binary and the same commands. Programs run as aarch64 Linux code
on the M-series CPU inside a kernel-less Hypervisor.framework VM; linuxity
answers their syscalls (no Linux kernel, no Docker). Pick the aarch64
images: `linuxity new alpine` does.

    linuxity new alpine
    linuxity                   # a shell
    linuxity uname -a          # any command: runs in your default environment

Things that are different on a Mac:

- An environment runs while a `shell`, `exec` or `run` is open; there's no
  background instance, so `start`, `ps`, `svc` and `logs` don't apply and
  `list` shows it as `ready`. Files and settings persist exactly the same.
- Users, `su` and `sudo` work as on Linux: `--user`, `login.user` and
  `linuxity adduser` give a real unprivileged user, and a setuid `sudo`
  raises it to root.
- The binary must carry the `com.apple.security.hypervisor` entitlement
  (the build signs it ad hoc); without it linuxity says how to sign it.

---

## 15. Where things live

```
~/.local/share/linuxity/            ($LINUXITY_HOME)
  default                           the default environment's name
  cache/                            downloaded images
  envs/NAME/
    env.vibe                        settings
    rootfs/                         the image (from new/import)
    upper/                          your changes
    image.meta                      the image's owners and modes
    snapshots/NAME/                 saved states
    logs/linuxity.log, SERVICE.log
    run/                            control socket, pid (while running)
```

`linuxity path dev` prints an environment's directory, `linuxity info dev`
shows its size, snapshots and state. Scratch files go in `/tmp`, or in
`$LINUXITY_TMPDIR` if set.

---

## 16. Scripting and JSON

Most read commands take `--json`: `list`, `status`, `ps`, `users`, `info`,
`check`, `images`, `snapshots`. `linuxity schema` describes every setting.

```sh
linuxity status --json | jq .services
linuxity exec -T -- sh -c 'cat /etc/os-release' > os.txt
printf 'secret\n' | linuxity adduser bob --password-stdin
```

`--status-fd N` on `run`/`start` writes what the runtime decided (DNS
source, how limits are held, compat fallbacks, ready, service state changes)
as JSON lines to file descriptor N.

Frontends drive a running environment over its control socket
(`envs/NAME/run/control.sock`, newline-delimited JSON). The protocol is in
`doc/ENVIRONMENTS.md`.

---

## 17. Troubleshooting

| you see | do |
|---|---|
| `No Linux environments yet` | `linuxity new ubuntu` |
| `which environment?` | name it, or `linuxity default NAME` |
| `restart it for this to take effect` | `linuxity stop`, then use it again |
| `no user 'X' in the guest's /etc/passwd` | `linuxity adduser X`, or `linuxity set user=root` |
| `foreign-architecture binary` | the rootfs is for another CPU; use one built for this machine |
| `this system has no curl or wget` | install one, or download the image yourself and pass `--file` |
| `...is zstd-compressed and this system has no zstd` | install `zstd` |
| `doesn't match its checksum` | the download was damaged; run `new` again |
| `sudo: unable to resolve host` | `linuxity set network.manage-hosts=true` |
| a command hangs or misbehaves | `linuxity logs`, then `linuxity set debug.trace=/tmp/trace.txt`, restart, reproduce |
| something's broken beyond repair | `linuxity reset NAME` (or `restore` a snapshot) |

`linuxity status` shows notes about what the runtime had to work around on
this host (no FIFOs, abstract sockets, refused syscalls), which usually
explains odd behaviour.

---

## 18. Command reference

`[ENV]` can be left out to use the default environment.

| command | |
|---|---|
| `linuxity` | shell in the default environment |
| `new DISTRO[:VERSION] [NAME]` | download and set up (`--user`, `--root`, `--password`, `--file`, `--checksum`, `--no-verify`) |
| `import NAME FILE\|DIR` | from your own rootfs (`--user`, `--root`) |
| `export [ENV] FILE` | write it out as a tarball (`.gz` compresses) |
| `images` | the catalog |
| `list` | environments |
| `default [ENV]` | show or set the default |
| `rename OLD NEW` | |
| `rm ENV` | delete (`--yes`) |
| `shell [ENV]` | login shell (`-u USER`) |
| `exec [ENV] [-u U] [-C DIR] [-e K=V] [-t\|-T] -- CMD` | run a command |
| `run [ENV] [--fresh] [-v H:G] [-e K=V] [-- CMD]` | one program, foreground |
| `start [ENV]` / `stop [ENV]` | background on / off |
| `status [ENV]` / `ps [ENV]` / `kill [ENV] PID [SIG]` | |
| `get [ENV] [KEY]` / `set [ENV] K=V ...` / `unset [ENV] KEY` | settings |
| `edit [ENV]` / `check [ENV]` / `info [ENV]` / `path [ENV]` | |
| `reload [ENV]` | apply `env.vibe` edits made by hand |
| `adduser [ENV] USER` | user with sudo (`--password`, `--password-stdin`, `--no-sudo`, `--no-default`, `--shell`) |
| `users [ENV]` | login users |
| `svc [ENV] [list\|start\|stop\|restart NAME]` | services |
| `logs [ENV] [SERVICE] [-f]` | |
| `snapshot [ENV] NAME` / `snapshots [ENV]` | |
| `restore ENV NAME` / `drop-snapshot ENV NAME` / `reset ENV` | |
| `schema` | every setting, as JSON |
| `help` / `help --all` / `version` | |
| `linuxity [FLAGS] PROGRAM [ARGS]` | one-off run (section 13) |
