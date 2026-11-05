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

if(MSVC)
    # The GCC/Clang warning set below has no MSVC spelling; /W4 is the
    # nearest equivalent, and /Zc:preprocessor is needed for a conforming
    # preprocessor (the WHP headers rely on it).
    add_compile_options(/W4 /permissive- /Zc:preprocessor /EHsc)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wshadow -Wconversion -Wsign-conversion
        -Wnon-virtual-dtor -Wold-style-cast -Woverloaded-virtual
        -fno-rtti)
endif()

# ---- The runtime core: host-agnostic Linux ABI ---------------------------
add_library(linuxity_core INTERFACE)
target_include_directories(linuxity_core INTERFACE ${CMAKE_SOURCE_DIR}/include)
target_compile_features(linuxity_core INTERFACE cxx_std_23)

# ---- Host backends -------------------------------------------------------
# The core above is header-only and host-agnostic. The executable needs a
# trap backend; today those are ptrace (Linux), Hypervisor.framework
# (macOS/arm64) and WHP (Windows/x86-64).
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
elseif(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    # Windows: the WHP backend. Guest syscalls are intercepted by clearing
    # IA32_EFER.SCE (so `syscall` raises #UD) and routing vector 6 to the host
    # through the partition's ExceptionExitBitmap -- no guest kernel needed.
    #
    # WinHvPlatform.dll is resolved at RUNTIME (see runtime/whp_api.hpp), NOT
    # linked, so the binary still starts on a machine where the "Windows
    # Hypervisor Platform" feature is off and can print a real diagnostic
    # instead of dying in the loader with 0xC0000135.
    add_executable(linuxity src/main_windows.cpp)
    target_link_libraries(linuxity PRIVATE linuxity_core)
    message(STATUS "linuxity: WHP backend (Windows x86-64); "
                   "WinHvPlatform.dll is loaded on demand at runtime")
else()
    message(STATUS "linuxity: no trap backend for ${CMAKE_SYSTEM_NAME} yet; "
                   "building the portable core + tests only")
endif()

# ---- Tests ---------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
