// src/display/core/server.cpp -- clients, dispatch, wl_display, wl_registry.
#include "server.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <sys/file.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#if defined(__APPLE__)
#include <sys/ucred.h>
#endif

namespace lx::display {

namespace {

using proto::WlDisplay;
using proto::WlRegistry;

constexpr std::size_t kMaxQueuedOutput = 8u << 20;   // a client that stopped reading

class Registry final : public Object<WlRegistry> {
public:
    using Object::Object;
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != WlRegistry::Req::bind) return;
        const std::uint32_t name = a.u(0), version = a.u(2);
        const std::string_view iface = a.str(1);
        const ObjectId id = a.new_id(3);
        for (const auto& g : client().server().globals_for_bind()) {
            if (g.name != name) continue;
            if (g.iface->name != iface || version == 0 || version > g.version) {
                post_error(WlDisplay::Error::invalid_object,
                           "bind: " + std::string{iface} + " v" + std::to_string(version) +
                           " does not match global " + std::to_string(name));
                return;
            }
            g.bind(client(), version, id);
            return;
        }
        post_error(WlDisplay::Error::invalid_object, "bind: no global " + std::to_string(name));
    }
};

class Display final : public Object<WlDisplay> {
public:
    using Object::Object;
    void request(std::uint16_t op, wire::Args& a) override {
        if (op == WlDisplay::Req::sync) {
            if (auto cb = client().create<Callback>(a.new_id(0), 1)) cb->fire(client().server().next_serial());
        } else if (op == WlDisplay::Req::get_registry) {
            if (auto r = client().create<Registry>(a.new_id(0), 1)) client().server().announce(r);
        }
    }
};

}  // namespace

// -- Resource -----------------------------------------------------------------

void Resource::post_error(std::uint32_t code, std::string message) {
    client_->fatal(id_, code, std::string{iface_->name} + "@" + std::to_string(id_) + ": " + message);
}

void Resource::destroy() {
    if (!alive_) return;
    alive_ = false;
    on_destroy();
    client_->remove(*this);
}

// -- Client -------------------------------------------------------------------

Client::Client(Server& s, wire::Fd sock, std::uint64_t serial)
    : server_(&s), serial_no_(serial), chan_(std::move(sock)) {
#if defined(__APPLE__)
    pid_t pid = -1;
    socklen_t len = sizeof pid;
    if (::getsockopt(chan_.fd(), SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0) pid_ = pid;
#elif defined(SO_PEERCRED)
    struct ::ucred cr{};
    socklen_t len = sizeof cr;
    if (::getsockopt(chan_.fd(), SOL_SOCKET, SO_PEERCRED, &cr, &len) == 0) pid_ = cr.pid;
#endif
    objects_[1] = std::make_shared<Display>(*this, 1, 1);
    read_src_ = s.loop().on_readable(chan_.fd(), [this] { readable(); });
}

Client::~Client() {
    read_src_.reset();
    write_src_.reset();
    for (int fd : out_fds_) ::close(fd);
}

bool Client::id_ok(ObjectId id) {
    if (id == 0 || id >= wire::kFirstServerId || objects_.contains(id)) {
        fatal(1, static_cast<std::uint32_t>(WlDisplay::Error::invalid_object),
              "invalid new id " + std::to_string(id));
        return false;
    }
    zombies_.erase(id);
    return true;
}

void Client::queue_event(ObjectId id, const wire::Interface& iface, std::uint16_t op,
                         const std::function<void(wire::Encoder&)>& fill) {
    if (dead_) return;
    wire::Encoder e{out_, out_fds_, id, op};
    fill(e);
    e.finish();
    (void)iface;
    if (out_.size() > kMaxQueuedOutput) {
        std::fprintf(stderr, "linuxity-display: client %llu stopped reading; dropping it\n",
                     static_cast<unsigned long long>(serial_no_));
        disconnect("not reading its events");
        return;
    }
    server_->schedule_flush(*this);
}

void Client::fatal(ObjectId id, std::uint32_t code, const std::string& message) {
    if (dead_ || closing_) return;
    std::fprintf(stderr, "linuxity-display: protocol error (client %llu): %s\n",
                 static_cast<unsigned long long>(serial_no_), message.c_str());
    if (auto d = objects_.find(1); d != objects_.end())
        d->second->send(WlDisplay::Ev::error, wire::Object{id}, code, message);
    closing_ = true;
    read_src_.reset();
    server_->schedule_flush(*this);
}

void Client::disconnect(const char* why) {
    if (dead_) return;
    dead_ = true;
    if (server_->verbose)
        std::fprintf(stderr, "linuxity-display: client %llu (pid %d) gone: %s\n",
                     static_cast<unsigned long long>(serial_no_), static_cast<int>(pid_), why);
    read_src_.reset();
    write_src_.reset();
    // Highest id first: children (created later) before what they hang off.
    while (!objects_.empty()) {
        auto it = std::prev(objects_.end());
        auto obj = it->second;
        if (obj->alive_) {
            obj->alive_ = false;
            obj->on_destroy();
        }
        objects_.erase(obj->id());
    }
    server_->reap(this);
}

void Client::remove(Resource& r) {
    const ObjectId id = r.id();
    const wire::Interface* iface = &r.iface();
    const bool by_request = in_request_ == id;
    objects_.erase(id);   // may free r: nothing of it below this line
    if (dead_) return;
    if (id < wire::kFirstServerId) {
        if (!by_request) zombies_[id] = iface;
        if (auto d = objects_.find(1); d != objects_.end()) d->second->send(WlDisplay::Ev::delete_id, id);
    }
}

void Client::readable() {
    if (dead_ || closing_) return;
    errno = 0;
    const auto io = chan_.read_some(in_);
    if (io == wire::Channel::Io::closed) { disconnect(errno ? std::strerror(errno) : "peer closed"); return; }
    dispatch_buffered();
}

bool Client::has_buffered_message() const noexcept {
    if (in_.size() - in_pos_ < 8) return false;
    std::uint32_t w = 0;
    std::memcpy(&w, in_.data() + in_pos_ + 4, 4);
    return in_.size() - in_pos_ >= std::max<std::size_t>(8, w >> 16);
}

void Client::dispatch_buffered() {
    // Reentrancy: a request handler can pump this client again -- a window
    // being mapped makes AppKit resize it synchronously, and a live resize
    // waits for the client to redraw (ShellSurface::host_configure_and_wait
    // -> pump_until -> readable). The nested call appends to in_ (which may
    // move it) and dispatches the NEXT requests. So the read position is the
    // member in_pos_, shared by every level and advanced BEFORE a dispatch;
    // a body is copied out of in_ before its handler runs; and only the
    // outermost call compacts the buffer. (A local cursor over in_, erased
    // at the end of each level, corrupted the heap -- the compositor died
    // with "memory corruption of free block" -- and dispatched requests
    // twice: "invalid new id".)
    ++depth_;
    while (!dead_ && !closing_ && in_.size() - in_pos_ >= 8) {
        std::uint32_t id = 0, w = 0;
        std::memcpy(&id, in_.data() + in_pos_, 4);
        std::memcpy(&w, in_.data() + in_pos_ + 4, 4);
        const std::size_t size = w >> 16;
        const auto op = static_cast<std::uint16_t>(w & 0xffff);
        if (size < 8 || size % 4 || size > wire::kMaxMessage) {
            fatal(1, static_cast<std::uint32_t>(WlDisplay::Error::invalid_method), "bad message size");
            break;
        }
        if (in_.size() - in_pos_ < size) break;
        std::array<std::byte, wire::kMaxMessage> body;
        std::memcpy(body.data(), in_.data() + in_pos_ + 8, size - 8);
        in_pos_ += size;
        dispatch_one(id, op, {body.data(), size - 8});
    }
    if (--depth_ == 0 && !dead_) {
        in_.erase(in_.begin(), in_.begin() + static_cast<std::ptrdiff_t>(in_pos_));
        in_pos_ = 0;
    }
}

void Client::dispatch_one(ObjectId id, std::uint16_t op, std::span<const std::byte> body) {
    auto obj = any(id);
    const wire::Interface* iface = obj ? &obj->iface() : nullptr;
    if (!obj) {
        // A request to an object we destroyed before the client heard: decode
        // it only to consume its fds, then drop it.
        const auto z = zombies_.find(id);
        if (z == zombies_.end()) {
            fatal(1, static_cast<std::uint32_t>(WlDisplay::Error::invalid_object),
                  "invalid object " + std::to_string(id));
            return;
        }
        if (op < z->second->requests.size()) {
            wire::Args a;
            (void)wire::decode(z->second->requests[op].signature, body, chan_, a);
        }
        return;
    }
    if (op >= iface->requests.size()) {
        fatal(id, static_cast<std::uint32_t>(WlDisplay::Error::invalid_method),
              std::string{iface->name} + ": invalid opcode " + std::to_string(op));
        return;
    }
    const wire::Message& m = iface->requests[op];
    if (m.since > obj->version()) {
        fatal(id, static_cast<std::uint32_t>(WlDisplay::Error::invalid_method),
              std::string{iface->name} + "." + std::string{m.name} + " needs a newer version");
        return;
    }
    wire::Args args;
    if (!wire::decode(m.signature, body, chan_, args)) {
        fatal(id, static_cast<std::uint32_t>(WlDisplay::Error::invalid_method),
              std::string{iface->name} + "." + std::string{m.name} + ": malformed arguments");
        return;
    }
    in_request_ = id;
    obj->request(op, args);
    // A destructor request the handler didn't act on still ends the object.
    if (m.destructor && obj->alive()) obj->destroy();
    in_request_ = 0;
}

void Client::flush() {
    if (dead_) return;
    const auto io = chan_.write_some(out_, out_fds_);
    if (io == wire::Channel::Io::closed) { disconnect(std::strerror(errno)); return; }
    if (io == wire::Channel::Io::again) {
        if (!write_src_)
            write_src_ = server_->loop().on_writable(chan_.fd(), [this] {
                write_src_.reset();
                flush();
            });
        return;
    }
    if (closing_) disconnect("protocol error");
}

bool Client::pump_until(const std::function<bool()>& done, std::chrono::milliseconds budget) {
    const auto until = std::chrono::steady_clock::now() + budget;
    flush();
    while (!dead_ && !closing_ && !done()) {
        // requests already read (by an outer readable() that is waiting on
        // us) come first: they may be exactly what `done` waits for
        if (has_buffered_message()) { dispatch_buffered(); flush(); continue; }
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(until - std::chrono::steady_clock::now());
        if (left.count() <= 0) break;
        ::pollfd p{chan_.fd(), POLLIN, 0};
        if (::poll(&p, 1, static_cast<int>(left.count())) <= 0) continue;
        readable();
        flush();
    }
    return !dead_ && done();
}

// -- Server -------------------------------------------------------------------

Server::Server(EventLoop& loop) : loop_(&loop) {}

Server::~Server() {
    listen_src_.reset();
    disconnect_all();
    if (!path_.empty()) ::unlink(path_.c_str());
}

void Server::disconnect_all() {
    shutting_down_ = true;
    auto cs = std::move(clients_);
    clients_.clear();
    for (auto& c : cs) c->disconnect("server shutting down");
    dirty_.clear();
    shutting_down_ = false;
}

bool Server::listen(const std::string& path, std::string& why) {
    ::sockaddr_un sa{};
    if (path.size() >= sizeof sa.sun_path) { why = "socket path too long: " + path; return false; }
    // One server per socket: hold a lock beside it for our whole life.
    lock_path_ = path + ".lock";
    lock_fd_ = wire::Fd{::open(lock_path_.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600)};
    if (!lock_fd_ || ::flock(lock_fd_.get(), LOCK_EX | LOCK_NB) != 0) {
        why = "another display server owns " + path;
        return false;
    }
    ::unlink(path.c_str());
    listen_fd_ = wire::Fd{::socket(AF_UNIX, SOCK_STREAM, 0)};
    if (!listen_fd_) { why = std::strerror(errno); return false; }
    (void)::fcntl(listen_fd_.get(), F_SETFD, FD_CLOEXEC);
    (void)::fcntl(listen_fd_.get(), F_SETFL, O_NONBLOCK);
    sa.sun_family = AF_UNIX;
    std::memcpy(sa.sun_path, path.c_str(), path.size() + 1);
    if (::bind(listen_fd_.get(), reinterpret_cast<::sockaddr*>(&sa), sizeof sa) != 0 ||
        ::listen(listen_fd_.get(), 64) != 0) {
        why = path + ": " + std::strerror(errno);
        return false;
    }
    path_ = path;
    // Guest users are not the host user; who may reach the socket is
    // decided by the directory it lives in (display_attach keeps that
    // private to the host user), so the node itself is open.
    (void)::chmod(path.c_str(), 0777);
    listen_src_ = loop_->on_readable(listen_fd_.get(), [this] { accept_clients(); });
    return true;
}

Client* Server::adopt(wire::Fd sock) {
    clients_.push_back(std::make_unique<Client>(*this, std::move(sock), next_client_++));
    if (verbose)
        std::fprintf(stderr, "linuxity-display: client %llu connected (pid %d)\n",
                     static_cast<unsigned long long>(clients_.back()->serial_no()), static_cast<int>(clients_.back()->pid()));
    if (on_idle_change) on_idle_change();
    return clients_.back().get();
}

void Server::accept_clients() {
    for (;;) {
        const int fd = ::accept(listen_fd_.get(), nullptr, nullptr);
        if (fd < 0) return;
        (void)adopt(wire::Fd{fd});
    }
}

void Server::reap(Client* c) {
    std::erase(dirty_, c);
    if (on_client_gone) on_client_gone(*c);
    if (shutting_down_) return;   // disconnect_all owns and frees them
    // Not now: we may be inside this client's own callback.
    loop_->defer([this, c] {
        std::erase_if(clients_, [c](const auto& p) { return p.get() == c; });
        if (on_idle_change) on_idle_change();
    });
}

void Server::schedule_flush(Client& c) {
    if (std::find(dirty_.begin(), dirty_.end(), &c) == dirty_.end()) dirty_.push_back(&c);
    if (flush_scheduled_) return;
    flush_scheduled_ = true;
    loop_->defer([this] { flush_all(); });
}

void Server::flush_all() {
    flush_scheduled_ = false;
    auto d = std::move(dirty_);
    dirty_.clear();
    for (Client* c : d) c->flush();
}

std::uint32_t Server::add_global(const wire::Interface& iface, std::uint32_t version,
                                 std::function<void(Client&, std::uint32_t, ObjectId)> bind) {
    // LINUXITY_DISPLAY_HIDE=a,b: don't advertise these interfaces. When an
    // app misbehaves, hiding protocols one by one finds the one it trips on.
    static const std::string hide = [] {
        const char* h = std::getenv("LINUXITY_DISPLAY_HIDE");
        return h ? "," + std::string{h} + "," : std::string{};
    }();
    if (!hide.empty() && hide.find("," + std::string{iface.name} + ",") != std::string::npos) return 0;
    const std::uint32_t name = next_global_++;
    globals_.push_back({name, &iface, version, std::move(bind)});
    for (auto& w : registries_)
        if (auto r = w.lock(); r && r->alive())
            r->send(WlRegistry::Ev::global, name, iface.name, version);
    return name;
}

void Server::remove_global(std::uint32_t name) {
    std::erase_if(globals_, [name](const Global& g) { return g.name == name; });
    for (auto& w : registries_)
        if (auto r = w.lock(); r && r->alive()) r->send(WlRegistry::Ev::global_remove, name);
}

void Server::announce(const std::shared_ptr<Resource>& registry) {
    std::erase_if(registries_, [](const auto& w) { return w.expired(); });
    registries_.push_back(registry);
    for (const auto& g : globals_) registry->send(WlRegistry::Ev::global, g.name, g.iface->name, g.version);
}

std::uint32_t Server::now_ms() const noexcept {
    ::timespec ts{};
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint32_t>(static_cast<std::uint64_t>(ts.tv_sec) * 1000u +
                                      static_cast<std::uint64_t>(ts.tv_nsec) / 1000000u);
}

}  // namespace lx::display
