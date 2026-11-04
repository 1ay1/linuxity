cmake_minimum_required(VERSION 3.28)
project(linuxity
    VERSION 0.1.0
    DESCRIPTION "A portable, type-theoretic implementation of the Linux userspace ABI"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wshadow -Wconversion -Wsign-conversion
    -Wnon-virtual-dtor -Wold-style-cast -Woverloaded-virtual
    -fno-rtti)

# ---- The runtime core: host-agnostic Linux ABI ---------------------------
add_library(linuxity_core INTERFACE)
target_include_directories(linuxity_core INTERFACE ${CMAKE_SOURCE_DIR}/include)
target_compile_features(linuxity_core INTERFACE cxx_std_23)

# ---- Host backends -------------------------------------------------------
# The core above is header-only and host-agnostic. The executable needs a
# trap backend; today that is ptrace (Linux). macOS (Hypervisor.framework)
# and Windows (WHP) backends are on the roadmap.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(src/host)
    add_executable(linuxity src/main.cpp)
    target_link_libraries(linuxity PRIVATE linuxity_core linuxity_host)
elseif(APPLE AND CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    # macOS: the Hypervisor.framework backend. hv_vm_create is entitlement-
    # gated, so sign ad-hoc with com.apple.security.hypervisor after linking.
    add_executable(linuxity src/main_macos.cpp)
    target_link_libraries(linuxity PRIVATE linuxity_core "-framework Hypervisor")
    add_custom_command(TARGET linuxity POST_BUILD
        COMMAND codesign -s - --entitlements
                ${CMAKE_SOURCE_DIR}/tests/hypervisor.entitlements
                -f $<TARGET_FILE:linuxity>
        COMMENT "Signing linuxity with the hypervisor entitlement"
        VERBATIM)
else()
    message(STATUS "linuxity: no trap backend for ${CMAKE_SYSTEM_NAME} yet; "
                   "building the portable core + tests only")
endif()

# ---- Tests ---------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
