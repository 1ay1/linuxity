# The host backends are header-only (so the runtime can bind statically),
# but we compile a translation unit per host to prove the static_asserts.
add_library(linuxity_host STATIC posix_host.cpp)
target_link_libraries(linuxity_host PUBLIC linuxity_core)
