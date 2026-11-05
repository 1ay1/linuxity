// linuxity/conform/sysno_names.hpp
//
// Sysno -> name, for divergence reports. The table is generated from the enum
// (tools/gen_sysno_names.py) so it cannot drift: a new Sysno member without a
// regenerated .inc fails the static_assert below.
#pragma once

#include <array>
#include <string_view>

#include "linuxity/abi/sysno.hpp"

namespace lx::conform {

namespace detail {

// The generated list, materialised once as a constexpr array indexed by the
// enum's own value. Using the enumerator in both the index and the string
// keeps them welded together -- you cannot add one without the other.
inline constexpr auto sysno_name_table = [] {
#define LX_SYSNO_NAME(n) +1
    constexpr std::size_t count = 0
#include "linuxity/conform/sysno_names.inc"
        ;
#undef LX_SYSNO_NAME

    std::array<std::string_view, count> t{};
#define LX_SYSNO_NAME(n) t[static_cast<std::size_t>(abi::Sysno::n)] = #n;
#include "linuxity/conform/sysno_names.inc"
#undef LX_SYSNO_NAME
    return t;
}();

} // namespace detail

// Total number of Sysno members the name table knows about.
inline constexpr std::size_t sysno_count = detail::sysno_name_table.size();

[[nodiscard]] constexpr std::string_view name_of(abi::Sysno s) noexcept {
    const auto i = static_cast<std::size_t>(s);
    return i < detail::sysno_name_table.size() ? detail::sysno_name_table[i]
                                               : std::string_view{"<out-of-range>"};
}

// Every slot must be filled. A hole means the enum has a member the generated
// table lacks (regenerate), or an explicit `= N` created a gap.
static_assert([] {
    for (const auto n : detail::sysno_name_table)
        if (n.empty()) return false;
    return true;
}(), "conform: sysno name table has a hole -- rerun tools/gen_sysno_names.py");

} // namespace lx::conform
