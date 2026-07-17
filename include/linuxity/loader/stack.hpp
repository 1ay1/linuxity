// linuxity/loader/stack.hpp
//
// Initial process stack setup — the System V AMD64 ABI process-init contract.
//
// When the kernel transfers control to a fresh process's entry point, the
// stack is not empty: it holds, from the top of the stack downward, exactly
// the structure libc's _start and the dynamic linker expect. Getting a single
// field wrong here means glibc segfaults before main() — so this mirrors the
// kernel's fs/binfmt_elf.c layout precisely.
//
//   [ argc                    ]  <- initial %rsp points here
//   [ argv[0] ]..[ argv[n-1] ]
//   [ NULL                    ]
//   [ envp[0] ]..[ envp[m-1] ]
//   [ NULL                    ]
//   [ auxv: (type,val) pairs  ]
//   [ AT_NULL pair            ]
//   [ ...string data (argv/envp/AT_RANDOM bytes)... ]
//
// %rsp must be 16-byte aligned at the entry point per the AMD64 ABI.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/loader/elf.hpp"
#include "linuxity/loader/loader.hpp"
#include "linuxity/mm/address_space.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace lx::loader {

struct StackParams {
    UAddr top{};                 // highest guest address of the stack region
    std::size_t size{};          // stack region size
    std::vector<std::string> argv;
    std::vector<std::string> envp;
    Loaded image;                // for AT_PHDR/AT_ENTRY/etc.
};

// Builds the initial stack image and returns the guest %rsp to start at.
template <host::Host H>
class StackBuilder {
public:
    explicit StackBuilder(mm::AddressSpace<H>& as) : as_{as} {}

    [[nodiscard]] Result<UAddr> build(const StackParams& p) {
        const std::uint64_t top = value(p.top);
        std::uint64_t sp = top;

        // -- 1. Push string data (argv, envp) high, record their addrs. ---
        std::vector<std::uint64_t> argp, envpp;
        for (const auto& s : p.envp) envpp.push_back(sp = push_cstr(sp, s));
        for (const auto& s : p.argv) argp.push_back(sp = push_cstr(sp, s));

        // 16 random bytes for AT_RANDOM (glibc stack-canary/PRNG seed).
        std::uint64_t random_at = sp = push_bytes(sp, kRandom, sizeof kRandom);

        // -- 2. Compute the aligned base of the pointer arrays. -----------
        // Total words below sp: argc + argv[]+NULL + envp[]+NULL + auxv.
        const std::size_t aux_pairs = 6;                 // see below (+AT_NULL)
        std::size_t words = 1                            // argc
                          + p.argv.size() + 1            // argv + NULL
                          + p.envp.size() + 1            // envp + NULL
                          + (aux_pairs + 1) * 2;         // auxv incl AT_NULL
        // Align so that final %rsp is 16-byte aligned.
        std::uint64_t arr = sp - words * 8;
        arr &= ~std::uint64_t{15};
        std::uint64_t w = arr;

        // -- 3. Write argc, argv[], NULL, envp[], NULL. -------------------
        LX_TRY(put_u64(w, p.argv.size())); w += 8;
        for (auto a : argp)  { LX_TRY(put_u64(w, a)); w += 8; }
        LX_TRY(put_u64(w, 0)); w += 8;
        for (auto e : envpp) { LX_TRY(put_u64(w, e)); w += 8; }
        LX_TRY(put_u64(w, 0)); w += 8;

        // -- 4. Write the auxiliary vector. -------------------------------
        auto aux = [&](AuxType t, std::uint64_t v) -> Status {
            LX_TRY(put_u64(w, static_cast<std::uint64_t>(t))); w += 8;
            LX_TRY(put_u64(w, v)); w += 8;
            return ok();
        };
        LX_TRY(aux(AuxType::phdr,   value(p.image.phdr)));
        LX_TRY(aux(AuxType::phent,  p.image.phent));
        LX_TRY(aux(AuxType::phnum,  p.image.phnum));
        LX_TRY(aux(AuxType::pagesz, kPageSize));
        LX_TRY(aux(AuxType::entry,  value(p.image.entry)));
        LX_TRY(aux(AuxType::random, random_at));
        LX_TRY(aux(AuxType::null,   0));                 // AT_NULL terminator

        return ok(uaddr(arr)); // initial %rsp
    }

private:
    static constexpr std::uint8_t kRandom[16] = {
        0x9e,0x37,0x79,0xb9,0x7f,0x4a,0x7c,0x15,
        0xf3,0x9c,0xc0,0x60,0x5c,0xed,0xc8,0x34,
    };

    // Push a NUL-terminated C string; returns the guest addr of its start.
    std::uint64_t push_cstr(std::uint64_t sp, const std::string& s) {
        return push_bytes(sp, s.data(), s.size() + 1 /*NUL*/);
    }
    std::uint64_t push_bytes(std::uint64_t sp, const void* data, std::size_t n) {
        sp -= n;
        (void)as_.write(uaddr(sp),
                        {static_cast<const std::byte*>(data), n});
        return sp;
    }
    [[nodiscard]] Status put_u64(std::uint64_t at, std::uint64_t v) {
        return as_.write(uaddr(at),
                         {reinterpret_cast<const std::byte*>(&v), sizeof v});
    }

    mm::AddressSpace<H>& as_;
};

} // namespace lx::loader
