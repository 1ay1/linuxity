// Compile-time proof that abi::Outcome makes bad states unrepresentable.
// Every assertion here is a `static_assert` or a negative compile check: this
// file testing clean IS the result.
#include "linuxity/abi/outcome.hpp"

#include <cstdio>
#include <string_view>
#include <type_traits>

using namespace lx;
using namespace lx::abi;

// -- 1. The fate is a SUM, not a product of flags -------------------------
// Eight fates, exactly one inhabited at a time. The old struct had 2^7 = 128
// flag combinations of which ~8 were legal; a variant has exactly 8 states.
static_assert(std::variant_size_v<Fate> == 8);

// -- 2. Mandatory payload is a constructor parameter ----------------------
// You cannot name a fate without giving it the data that fate requires.
static_assert(!std::is_default_constructible_v<Raise>,
              "a signal fate without pid+signum must not be constructible");
static_assert(!std::is_default_constructible_v<Redirect>,
              "a redirect without a translated host path must not exist");
static_assert(!std::is_default_constructible_v<Inject>,
              "an inject without content must not exist");
static_assert(!std::is_default_constructible_v<Exited>,
              "an exit without a status must not exist");
static_assert(!std::is_default_constructible_v<ExecInterp>,
              "an exec-interp without interpreter+program must not exist");
static_assert(!std::is_default_constructible_v<SockRewrite>,
              "a sockaddr rewrite without a path must not exist");
static_assert(!std::is_default_constructible_v<Scrub>,
              "a scrub without a buffer must not exist");
static_assert(!std::is_default_constructible_v<PathArg>,
              "a path rewrite without (arg, host_path) must not exist");

// Forward is the one fate with no mandatory data, so it IS default-ok.
static_assert(std::is_default_constructible_v<Forward>);

// -- 3. Modifiers are scoped to the fate they qualify ---------------------
// `scrub` exists only on Redirect, `mirror` only on Forward. There is no
// syntax for a scrubbed Inject or a parent-making Raise.
//
// The negative checks go through named concepts: `requires` on a member of a
// concrete type is a hard error, not a substitution failure, so the probe has
// to take the type as a template parameter to be detectable at all.
template <class T> concept HasScrub       = requires(T t) { t.scrub; };
template <class T> concept HasMakeParents = requires(T t) { t.make_parents; };
template <class T> concept HasMirror      = requires(T t) { t.mirror; };

static_assert(HasScrub<Redirect>);
static_assert(HasMakeParents<Redirect>);
static_assert(HasMirror<Forward>);

static_assert(!HasScrub<Inject>,
              "scrub must be unrepresentable outside a redirect");
static_assert(!HasMakeParents<Raise>,
              "make_parents must be unrepresentable outside a redirect");
static_assert(!HasMirror<Virtualize>,
              "a dup mirror must be unrepresentable outside a forward");

// -- 4. The -errno convention is applied in exactly one place -------------
static_assert(Virtualize::fail(Errno::enoent).ret == -2);
static_assert(Virtualize{7}.ret == 7);
static_assert(Virtualize::fail(Errno::eacces).ret == -13);

// -- 5. match() is total --------------------------------------------------
// This compiles only because all eight alternatives are handled. Drop one arm
// and the build fails naming the unhandled fate.
[[nodiscard]] constexpr const char* name_of(const Outcome& o) {
    return o.match(
        [](const Virtualize&)  { return "virtualize"; },
        [](const Forward&)     { return "forward"; },
        [](const Redirect&)    { return "redirect"; },
        [](const Inject&)      { return "inject"; },
        [](const Raise&)       { return "raise"; },
        [](const ExecInterp&)  { return "exec_interp"; },
        [](const SockRewrite&) { return "sock_rewrite"; },
        [](const Exited&)      { return "exited"; });
}

int main() {
    int failures = 0;
    auto check = [&](bool cond, const char* what) {
        if (!cond) { std::fprintf(stderr, "FAIL: %s\n", what); ++failures; }
    };

    // The named constructors land on the fate they say they do.
    check(std::string_view{name_of(Outcome::value(0))} == "virtualize",
          "value -> virtualize");
    check(std::string_view{name_of(Outcome::forward())} == "forward",
          "forward -> forward");
    check(std::string_view{name_of(Outcome::exited(3))} == "exited",
          "exited -> exited");
    check(std::string_view{name_of(Outcome::raise_at(1, 9))} == "raise",
          "raise_at -> raise");

    // errno is negated once, by the type.
    check(Outcome::error(Errno::enoent).get_if<Virtualize>()->ret == -2,
          "error(enoent) == -2");
    check(Outcome::value(42).get_if<Virtualize>()->ret == 42, "value(42) == 42");

    // A fate carries only its own payload, and get_if on the wrong fate is
    // null rather than garbage -- the old struct would hand you a default.
    Outcome fwd = Outcome::forward();
    check(fwd.get_if<Redirect>() == nullptr, "a forward is not a redirect");
    check(fwd.get_if<Forward>() != nullptr, "a forward is a forward");
    check(!fwd.get_if<Forward>()->mirror.has_value(), "plain forward has no mirror");

    // Redirect builds up through named modifiers; each is optional and scoped.
    Redirect r = Redirect{PathArg{0, "/host/etc/passwd"}}
                     .with(Scrub{Scrub::Layout::stat, uaddr(0x1000), "/etc/passwd"})
                     .parents();
    check(r.first.arg == 0, "redirect path arg");
    check(r.first.host_path == "/host/etc/passwd", "redirect host path");
    check(r.scrub.has_value(), "redirect carries its scrub");
    check(r.scrub->layout == Scrub::Layout::stat, "scrub layout");
    check(r.scrub->guest_path == "/etc/passwd", "scrub lookup key");
    check(r.make_parents, "redirect make_parents");
    check(!r.second.has_value(), "single-path redirect has no second operand");

    // symlink: the link TEXT is guest data, only the target translates. The
    // old encoding spelled this as the sentinel path_arg = -1.
    Redirect s = Redirect::target_only(PathArg{1, "/host/upper/link"});
    check(s.second.has_value(), "target_only sets the second operand");
    check(s.second->arg == 1, "target_only arg");
    check(s.first.arg == -1, "target_only leaves no first path");

    // A forward that must mirror fd bindings says so in its own payload.
    Outcome dup = Forward{DupMirror{5, 7}};
    const Forward* f = dup.get_if<Forward>();
    check(f && f->mirror && f->mirror->from == 5, "dup mirror source");
    check(f && f->mirror->close_first == 7, "dup mirror close target");

    // Raise keeps pid and signum together; neither can go missing.
    Outcome k = Outcome::raise_at(1234, 15);
    check(k.get_if<Raise>()->guest_pid == 1234, "raise pid");
    check(k.get_if<Raise>()->signum == 15, "raise signum");

    // ExecInterp requires interpreter + program up front; argv extras are opt.
    ExecInterp ei{0, "/host/lib/ld.so", "/bin/sh"};
    ei.prefix.push_back("-e");
    check(ei.interp_host == "/host/lib/ld.so", "interp host path");
    check(ei.prog_guest == "/bin/sh", "program guest path");
    check(ei.prefix.size() == 1, "interp prefix");
    check(ei.extra_args.empty(), "no appended args by default");

    // SockRewrite carries address, path and the socklen fixup together.
    SockRewrite sr{uaddr(0x2000), "/host/run/S.gpg-agent", 2, 26};
    check(value(sr.path_addr) == 0x2000, "sockaddr path addr");
    check(sr.new_len == 26, "sockaddr new socklen");

    // match() dispatches on the inhabited fate, with no precedence to recall.
    check(std::string_view{name_of(Outcome{std::move(r)})} == "redirect",
          "match picks redirect");
    check(std::string_view{name_of(Outcome{Inject{1, {}, true}})} == "inject",
          "match picks inject");

    // Inject names the register its temp path is spliced into, alongside the
    // bytes; a virtual dir carries no content but still needs the arg.
    Inject file{1, std::vector<std::byte>{std::byte{'h'}, std::byte{'i'}}};
    check(file.path_arg == 1, "inject path arg");
    check(file.content.size() == 2, "inject content");
    check(!file.is_dir, "inject defaults to a file");
    Inject dir{0, {}, true};
    check(dir.is_dir && dir.content.empty(), "inject dir carries no bytes");

    if (failures == 0) std::puts("outcome: all checks passed");
    return failures == 0 ? 0 : 1;
}
