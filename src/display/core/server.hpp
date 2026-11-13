// src/display/core/server.hpp -- Wayland objects, clients and globals.
//
// A Resource is one protocol object a client holds (its id, interface and
// bound version); concrete objects derive from it and handle their
// requests. The Client owns its resources and its Channel; the Server owns
// the listening socket, the clients and the global list. Lifetimes follow
// the protocol: a destructor request (or the client going away) destroys the
// object, other objects refer to it through weak_ptr and see it vanish.
#pragma once

#include "../protocol/protocol.hpp"
#include "../wire/channel.hpp"
#include "loop.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace lx::display {

class Client;
class Server;
using wire::ObjectId;

class Resource : public std::enable_shared_from_this<Resource> {
public:
    Resource(Client& c, const wire::Interface& iface, std::uint32_t version, ObjectId id)
        : client_(&c), iface_(&iface), version_(version), id_(id) {}
    virtual ~Resource() = default;
    Resource(const Resource&) = delete;
    Resource& operator=(const Resource&) = delete;

    [[nodiscard]] Client& client() const noexcept { return *client_; }
    [[nodiscard]] const wire::Interface& iface() const noexcept { return *iface_; }
    [[nodiscard]] std::uint32_t version() const noexcept { return version_; }
    [[nodiscard]] ObjectId id() const noexcept { return id_; }
    [[nodiscard]] bool alive() const noexcept { return alive_; }

    // Send an event; silently dropped if the client bound a version that
    // predates it, or if this object is already gone.
    template <class... A>
    void send(std::uint16_t opcode, A&&... args);

    // A protocol error on this object: the client is told, then dropped.
    void post_error(std::uint32_t code, std::string message);
    template <class E>
    void post_error(E code, std::string message) { post_error(static_cast<std::uint32_t>(code), std::move(message)); }

    // Remove this object from its client (the destructor request, or the
    // server ending a one-shot object like wl_callback).
    void destroy();

protected:
    friend class Client;
    virtual void request(std::uint16_t opcode, wire::Args& args) = 0;
    // Called once when the object leaves its client, for whatever reason.
    virtual void on_destroy() {}

private:
    Client* client_;
    const wire::Interface* iface_;
    std::uint32_t version_;
    ObjectId id_;
    bool alive_{true};
};

// A Resource bound to its generated protocol struct (proto::WlSurface ...).
template <class Proto>
class Object : public Resource {
public:
    using Protocol = Proto;
    Object(Client& c, std::uint32_t version, ObjectId id) : Resource(c, Proto::iface, version, id) {}
};

// wl_callback: one `done`, then the server destroys it.
class Callback final : public Object<proto::WlCallback> {
public:
    using Object::Object;
    void fire(std::uint32_t data) {
        send(proto::WlCallback::Ev::done, data);
        destroy();
    }
protected:
    void request(std::uint16_t, wire::Args&) override {}
};

class Client {
public:
    Client(Server& s, wire::Fd sock, std::uint64_t serial);
    ~Client();
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    [[nodiscard]] Server& server() const noexcept { return *server_; }
    [[nodiscard]] std::uint64_t serial_no() const noexcept { return serial_no_; }
    [[nodiscard]] pid_t pid() const noexcept { return pid_; }

    // The live object `id` if it implements T, else null.
    template <class T>
    [[nodiscard]] std::shared_ptr<T> get(ObjectId id) const {
        const auto it = objects_.find(id);
        if (it == objects_.end() || &it->second->iface() != &T::Protocol::iface) return nullptr;
        return std::static_pointer_cast<T>(it->second);
    }
    [[nodiscard]] std::shared_ptr<Resource> any(ObjectId id) const {
        const auto it = objects_.find(id);
        return it == objects_.end() ? nullptr : it->second;
    }

    // Create the object a request's new_id names. On a bad id the client is
    // already being dropped and this returns null.
    template <class T, class... A>
    std::shared_ptr<T> create(ObjectId id, std::uint32_t version, A&&... args) {
        if (!id_ok(id)) return nullptr;
        auto obj = std::make_shared<T>(*this, version, id, std::forward<A>(args)...);
        objects_[id] = obj;
        return obj;
    }
    // A server-created object (wl_data_offer and friends).
    template <class T, class... A>
    std::shared_ptr<T> create_server_side(std::uint32_t version, A&&... args) {
        const ObjectId id = next_server_id_++;
        auto obj = std::make_shared<T>(*this, version, id, std::forward<A>(args)...);
        objects_[id] = obj;
        return obj;
    }

    void queue_event(ObjectId id, const wire::Interface& iface, std::uint16_t op,
                     const std::function<void(wire::Encoder&)>& fill);
    void fatal(ObjectId id, std::uint32_t code, const std::string& message);
    void disconnect(const char* why = "closed");   // drop the client now
    [[nodiscard]] bool dead() const noexcept { return dead_; }
    // Flush our events, then read and dispatch this client's requests
    // right here (not via the loop) until `done()` or `budget` runs out.
    // For the few places a platform callback must see the client's answer
    // before it returns (interactive resize). Returns done().
    bool pump_until(const std::function<bool()>& done, std::chrono::milliseconds budget);

private:
    friend class Resource;
    friend class Server;
    [[nodiscard]] bool id_ok(ObjectId id);
    void readable();
    void dispatch_buffered();
    [[nodiscard]] bool has_buffered_message() const noexcept;
    void dispatch_one(ObjectId id, std::uint16_t op, std::span<const std::byte> body);
    void flush();
    void remove(Resource& r);

    Server* server_;
    std::uint64_t serial_no_;
    pid_t pid_{-1};
    wire::Channel chan_;
    std::vector<std::byte> in_, out_;
    std::size_t in_pos_{0};     // next unread byte of in_ (shared by nested readable())
    int depth_{0};              // readable() nesting
    std::vector<int> out_fds_;
    std::map<ObjectId, std::shared_ptr<Resource>> objects_;
    std::map<ObjectId, const wire::Interface*> zombies_;   // server-destroyed, client may not know yet
    ObjectId in_request_{0};
    ObjectId next_server_id_{wire::kFirstServerId};
    std::unique_ptr<EventLoop::Source> read_src_, write_src_;
    bool dead_{false};
    bool closing_{false};       // fatal error sent: flush, then drop
};

// A global: something clients find in the registry and bind.
struct Global {
    std::uint32_t name;
    const wire::Interface* iface;
    std::uint32_t version;
    std::function<void(Client&, std::uint32_t version, ObjectId id)> bind;
};

class Server {
public:
    explicit Server(EventLoop& loop);
    ~Server();

    // Listen on a filesystem AF_UNIX path (replacing a stale socket).
    [[nodiscard]] bool listen(const std::string& path, std::string& why);
    // Adopt an already-connected socket as a client (socketpair launches).
    Client* adopt(wire::Fd sock);

    [[nodiscard]] EventLoop& loop() const noexcept { return *loop_; }

    std::uint32_t add_global(const wire::Interface& iface, std::uint32_t version,
                             std::function<void(Client&, std::uint32_t, ObjectId)> bind);
    void remove_global(std::uint32_t name);
    template <class Proto, class T>
    std::uint32_t add_global(std::uint32_t version, T&& bind) {
        return add_global(Proto::iface, version, std::forward<T>(bind));
    }

    [[nodiscard]] std::uint32_t next_serial() noexcept { return ++serial_; }
    [[nodiscard]] std::uint32_t now_ms() const noexcept;

    [[nodiscard]] std::size_t client_count() const noexcept { return clients_.size(); }
    // Called when a client goes away (the compositor tears down its windows).
    std::function<void(Client&)> on_client_gone;
    std::function<void()> on_idle_change;   // client count changed
    bool verbose{false};                    // log client connects/disconnects

    void schedule_flush(Client& c);
    // Drop every client now (their objects' teardown still runs). Whoever
    // their objects point into -- the compositor -- calls this before it goes.
    void disconnect_all();
    [[nodiscard]] const std::vector<Global>& globals_for_bind() const noexcept { return globals_; }
    void announce(const std::shared_ptr<Resource>& registry);

private:
    friend class Client;
    void accept_clients();
    void reap(Client* c);
    void flush_all();

    EventLoop* loop_;
    wire::Fd listen_fd_;
    std::string path_, lock_path_;
    wire::Fd lock_fd_;
    std::unique_ptr<EventLoop::Source> listen_src_;
    std::vector<std::unique_ptr<Client>> clients_;
    std::vector<Global> globals_;
    std::vector<std::weak_ptr<Resource>> registries_;
    std::vector<Client*> dirty_;
    bool flush_scheduled_{false};
    bool shutting_down_{false};
    std::uint32_t next_global_{1};
    std::uint32_t serial_{0};
    std::uint64_t next_client_{1};
    std::chrono::steady_clock::time_point epoch_{std::chrono::steady_clock::now()};
};

template <class... A>
void Resource::send(std::uint16_t opcode, A&&... args) {
    if (!alive_ || opcode >= iface_->events.size()) return;
    if (iface_->events[opcode].since > version_) return;
    client_->queue_event(id_, *iface_, opcode, [&](wire::Encoder& e) {
        (e.put(wire::wire_value(std::forward<A>(args))), ...);
    });
}

}  // namespace lx::display
