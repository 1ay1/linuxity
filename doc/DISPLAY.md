# linuxity-display — guest GUI apps as native host windows

A Linux GUI program in a linuxity guest opens a window, and a real window
appears on the host: a Mac window on macOS, with a native title bar, Retina
pixels, Mission Control, Cmd-Tab, and the system clipboard. No VM, no
XQuartz, no VNC. This page explains how, and how it extends to Android and
Windows.

```
  guest (Linux)                                     host
  ─────────────                                     ────
  GTK / Qt / SDL / foot …                ┌────────────────────────────────┐
        │  libwayland-client             │        linuxity-display        │
        │                                │                                │
  $XDG_RUNTIME_DIR/wayland-0 ──AF_UNIX──▶│  wire/   bytes + fds ⇄ messages│
  (/run/user/UID, via the file           │  core/   the compositor        │
   namespace: a real host socket)        │            surfaces, xdg-shell,│
                                         │            seat, clipboard     │
        memfd pixels ──SCM_RIGHTS──────▶ │  ─── Host interface ─────────  │
        (MAP_SHARED, same pages)         │  hosts/cocoa    NSWindow+CALayer│
                                         │  hosts/headless PPM dumps, CI  │
                                         └────────────────────────────────┘
```

## Why a compositor, and why Wayland

The guest's apps need *a display server*. Rather than translate one (X11 to
Quartz, say), linuxity-display **is** one: a Wayland compositor that runs
natively on the host and whose "screen" is the host's window system. Each
toplevel becomes a host window; each popup a child window; each surface a
GPU layer. The compositor makes every decision a desktop compositor makes —
roles, configure sequences, popup placement, focus, input routing — and the
host just shows windows and reports input.

Wayland is the right protocol for this:

- it is per-window by design (no root window to fake), so "one app window
  = one host window" is the natural mapping;
- clients draw their own pixels into shared memory and pass the fd; the
  compositor never renders widgets;
- it is what GTK 3/4, Qt 5/6, SDL2/3, Electron, Firefox and every modern
  terminal speak natively. X11 apps run through Xwayland (a Wayland client
  like any other) — see *X11* below.

## What makes it work on linuxity

Two properties of linuxity's runtime carry the whole design:

1. **Guest AF_UNIX sockets are host sockets.** A guest `connect()` to
   `/run/user/1000/wayland-0` resolves through the file namespace to a host
   path. A native host process listening there is reachable by guest
   clients exactly as a Linux compositor is.
2. **Guest memory sharing is real.** A guest `memfd_create` is a host file;
   `MAP_SHARED` maps the same pages into the guest (macOS: the VM's IPA
   range is backed by the file); `SCM_RIGHTS` carries the fd to the host
   peer. So `wl_shm` works with no copies on the way in.

Both were checked end to end before any compositor code was written
(a guest wrote a memfd, passed it over a socket to a host process, and
each saw the other's writes).

## Source layout

| Path | What |
|------|------|
| `src/display/wire/` | the wire format: header, args, strings, arrays, fds (`wire.hpp`); a byte+fd transport (`channel.hpp`) |
| `src/display/protocol/` | **generated** tables for every interface (`tools/wayland-tables.py` from `third_party/wayland-protocols/*.xml`) |
| `src/display/core/server.*` | objects, clients, dispatch, `wl_display`, `wl_registry`, globals |
| `src/display/core/surface.cpp` | `wl_compositor`, `wl_surface`, `wl_region`, `wl_subsurface`, `wl_shm` |
| `src/display/core/shell.cpp` | `xdg_wm_base`, toplevels, popups, positioners, `xdg-decoration` |
| `src/display/core/seat.cpp` | pointer, keyboard, `wl_data_device` (clipboard) |
| `src/display/core/compositor.*` | globals, `wl_output`, frame pacing, host events |
| `src/display/core/host.hpp` | **the platform seam** |
| `src/display/hosts/cocoa/` | macOS |
| `src/display/hosts/headless.cpp` | no screen; software-composites into PPM files |
| `src/display_attach.hpp` | linuxity's side: find or start a compositor, give the guest a socket |
| `tests/display/` | a scripted Wayland client against the headless host |

## The Host seam

`core/host.hpp` is the only thing a new platform implements:

```cpp
class Host {
    EventLoop& loop();                                  // the platform's run loop
    std::vector<OutputInfo> outputs();                  // screens, scale, refresh
    KeyboardInfo keyboard();                            // XKB layout + repeat
    std::unique_ptr<HostWindow> create_window(const WindowSpec&, WindowSink&);
    void set_cursor(const CursorImage&); void reset_cursor();
    HostClipboard* clipboard();
};
class HostWindow {
    void present(const Scene&);                         // layers of pixels
    void set_title(...); set_decorations(...); set_maximized(...); ...
    void begin_move(); void begin_resize(edges);        // client-side frames
    Rect work_area() const;                             // for popup placement
};
```

Data flows one way each:

- **out**: a `Scene` per window — the view rectangle, the window geometry,
  and back-to-front `Layer`s (`Pixels` + logical rect + buffer scale). Pixels
  are immutable and shared: a host may wrap them without copying (Cocoa
  hands them to a `CGImage` that keeps them alive).
- **in**: `WindowSink` (configure, close, focus, pointer, scroll, output)
  per window and `HostSink` (keys as Linux evdev codes, modifiers, outputs
  and keyboard changed, app activation) for the whole host.

The core never sees an `NSWindow`, an `HWND`, or a `Surface` from
`android.view`; the hosts never see a Wayland object.

### macOS (hosts/cocoa)

- One `NSWindow` per toplevel. Popups (menus, tooltips, combo lists) are
  borderless child windows at popup level, so they track their parent.
- Every surface of a window's tree is a `CALayer`; Core Animation
  composites on the GPU. Unchanged surfaces keep their layer contents.
- Server-side decorations are the native title bar; GTK's headerbar
  (client-side) gets a borderless resizable window, and the app's
  `xdg_toplevel.move/resize` drive a native drag / an event-driven resize.
- Keys are sent as evdev codes from the hardware keycode, so the guest's XKB
  layout interprets them exactly as on Linux; the keymap's layout is chosen
  from the Mac's input source. **Command acts as Control** by default
  (Cmd-C copies in Linux apps); `--command-is-super` keeps it as Super.
- Scrolling: trackpads send `finger` axis events with stop, mice send
  `value120` detents.
- The pasteboard is two-way: a Linux app's copy lands on the Mac clipboard,
  a Mac copy is offered to the focused Linux app.
- The server is an accessory app (no Dock icon) until it has a window.

### Android (planned)

An Android host is the same core with `hosts/android/`: an `Activity` per
toplevel (or a freeform-window `SurfaceView`), `ANativeWindow_lock` or a
`SurfaceControl` per layer, input from `MotionEvent`/`KeyEvent` (Android
key codes map to evdev the way Cocoa's do), `ClipboardManager`, the
`Choreographer` for frame pacing as the `EventLoop` timer. Android sockets
are a host capability (`kernel/socket_ns.hpp`): where filesystem binds are
refused, the compositor listens on the abstract name the guest's path maps
to, and nothing else changes.

### Windows (planned)

`hosts/win32/`: an `HWND` per toplevel, a DirectComposition visual (or a
layered window) per layer, `WM_INPUT`/scancodes to evdev, the Win32
clipboard, a message loop as the `EventLoop`. On Windows guest sockets and
memfds are linuxity's own objects, so `wire::Channel` (the only code that
touches `sendmsg`) is replaced by an in-process channel that passes those
objects as handles; the rest of the compositor is unchanged.

## How linuxity attaches a guest (display_attach.hpp)

On every run (`lx`, `linuxity run`, `__run`, instances):

1. `display.wayland = off`, or the user set `WAYLAND_DISPLAY` → nothing.
2. The host has a compositor (a Linux desktop) → use it.
3. Otherwise start `linuxity-display` once per user (detached, its own
   session), at `$TMPDIR/linuxity-display-UID/wayland/wayland-0`, and reuse
   it for every environment.

The guest gets the standard layout: `XDG_RUNTIME_DIR=/run/user/UID`, private
per environment and guest user and writable (dconf, dbus, pipewire put
sockets there), containing `wayland-0` (a hard link to the compositor's
socket). Toolkit hints are set only if absent: `GDK_BACKEND=wayland,x11`,
`QT_QPA_PLATFORM=wayland;xcb`, `SDL_VIDEODRIVER=wayland,x11`,
`MOZ_ENABLE_WAYLAND=1`, `ELECTRON_OZONE_PLATFORM_HINT=auto`. With
linuxity-display, `LIBGL_ALWAYS_SOFTWARE=1` as well: there is no GPU to
share, so GL apps render with Mesa's llvmpipe (JIT, multithreaded) into
`wl_shm` buffers.

All of it lives under one 0700 directory of the host user's: no other
account on the machine can reach the compositor, the windows, or the
clipboard.

## Protocol coverage

| Interface | Version | Notes |
|-----------|---------|-------|
| wl_compositor, wl_surface | 6 | buffer scale, offset, frame callbacks, input regions, enter/leave, preferred_buffer_scale |
| wl_subcompositor, wl_subsurface | 1 | sync/desync, restacking |
| wl_shm | 1 | ARGB/XRGB/ABGR/XBGR 8888; pixels copied at commit, buffer released at once; SIGBUS-safe |
| xdg_wm_base, xdg_surface, xdg_toplevel, xdg_popup, xdg_positioner | 6 | full configure/ack protocol, wm_capabilities, configure_bounds, popup grabs, reposition, flip/slide/resize constraints |
| zxdg_decoration_manager_v1 | 1 | native title bars unless the client draws its own |
| wl_seat, wl_pointer, wl_keyboard | 8 | XKB keymap by RMLVO, repeat info, axis_value120, axis_stop |
| wl_data_device_manager | 3 | clipboard both ways with the host; drag and drop not yet |
| wl_output | 4 | one per screen, scale, refresh, name/description |

Next protocols, in order of what apps notice: `wp_viewporter`,
`wp_fractional_scale_v1` (sharp text at non-integer scale), `xdg_output`,
`zwp_primary_selection`, `zwp_text_input_v3` (IME), `wp_cursor_shape`,
`xdg_activation`, drag and drop, `linux-dmabuf` (once a GPU path exists).

## X11

X11 apps run under **Xwayland** in the guest, which is a Wayland client of
linuxity-display. The plan: linuxity starts `Xwayland -rootless` on demand,
and a small built-in X window manager (as in wlroots/KWin) maps X toplevels
to xdg-like windows via `xwayland_shell_v1` — the protocol table is already
generated. Nothing in the host backends changes.

## Running and debugging

```sh
lx @ubuntu gtk4-demo               # starts linuxity-display if needed
linuxity config ubuntu display.wayland off      # opt out per environment

linuxity-display --verbose --socket /tmp/w.sock       # by hand, logging
linuxity-display --dump /tmp/frames --socket /tmp/w.sock   # headless, PPM per present
lx @ubuntu -e WAYLAND_DISPLAY=/tmp/w.sock -v /tmp:/tmp foot
```

The server logs to `$TMPDIR/linuxity-display-UID.log`. `WAYLAND_DEBUG=1`
in the guest shows the client's side of the conversation.
