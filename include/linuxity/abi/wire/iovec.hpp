// linuxity/abi/wire/iovec.hpp
//
// The guest's `struct iovec`, defined once.
#pragma once

#include <cstdint>

namespace lx::abi::wire {

// struct iovec, as the guest lays it out: a {pointer, length} pair for the
// scatter/gather calls (readv/writev/preadv/pwritev/process_vm_readv).
//
// Both targeted ABIs are LP64, so this is 16 bytes with no padding on either.
// It was declared identically in darwin/mem.hpp and windows/mem.hpp; the
// shape is ABI, so it belongs here and the per-backend copies alias it.
//
// NOTE `base` is a guest address, deliberately a raw u64 rather than UAddr:
// these bytes are read straight out of guest memory, so the struct has to be
// trivially copyable with the exact ABI layout.
struct Iovec {
    std::uint64_t base{};
    std::uint64_t len{};
};

static_assert(sizeof(Iovec) == 16, "struct iovec is 16 bytes on LP64");
static_assert(alignof(Iovec) == 8);

// The kernel's cap on how many segments one call may carry. A guest passing
// more gets EINVAL -- and a backend that loops without this bound will walk
// off the end of whatever the guest claimed.
inline constexpr std::uint64_t kIovMax = 1024;

} // namespace lx::abi::wire
