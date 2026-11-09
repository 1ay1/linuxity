cmake_minimum_required(VERSION 3.28)
project(linuxity
    VERSION 0.1.0
    DESCRIPTION "A portable, type-theoretic implementation of the Linux userspace ABI"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to an OPTIMIZED build. linuxity is a runtime: every guest syscall
# runs through this code, so a Debug default made everything ~35% slower
# per syscall and doubled process startup (measured: getpid 1.47 -> 1.02 us,
# screenfetch 1.45 -> 0.78 s). RelWithDebInfo keeps symbols for sample(1)
# and crash reports. Pass -DCMAKE_BUILD_TYPE=Debug to develop.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG" CACHE STRING "" FORCE)

if(MSVC)
    # The GCC/Clang warning set below has no MSVC spelling; /W4 is the
    # nearest equivalent, and /Zc:preprocessor is needed for a conforming
    # preprocessor (the WHP headers rely on it).
    add_compile_options(/W4 /permissive- /Zc:preprocessor /EHsc)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wshadow -Wconversion -Wsign-conversion
        $<$<COMPILE_LANGUAGE:CXX>:-Wnon-virtual-dtor>
        $<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>
        $<$<COMPILE_LANGUAGE:CXX>:-Woverloaded-virtual>
        $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>)
endif()

# ---- Sanitizers (opt-in: -DLX_SANITIZE=address,undefined) ----------------
#
# Off by default because the live guest tests drive ptrace and read another
# process's memory, which ASan's bookkeeping slows down -- but this codebase
# is exactly the kind that hides UB. It pokes guest memory through
# PTRACE_PEEKDATA, writes raw ABI structs into another address space, and
# hand-manages an fd table and an interval map. A warning flag cannot see any
# of that; a sanitizer can.
#
# `undefined` matters as much as `address` here: abi/wire does a lot of
# shifting and masking on guest values, and a signed shift or a misaligned
# load is precisely the fault that works on x86-64 and breaks on aarch64.
set(LX_SANITIZE "" CACHE STRING
    "Comma-separated -fsanitize list, e.g. address,undefined")
if(LX_SANITIZE AND NOT MSVC)
    message(STATUS "linuxity: sanitizers enabled (${LX_SANITIZE})")
    add_compile_options(-fsanitize=${LX_SANITIZE} -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=${LX_SANITIZE})
endif()

# ---- The runtime core: host-agnostic Linux ABI ---------------------------
add_library(linuxity_core INTERFACE)
target_include_directories(linuxity_core INTERFACE ${CMAKE_SOURCE_DIR}/include)
target_compile_features(linuxity_core INTERFACE cxx_std_23)

# ---- libvibe: the parser for env.vibe (vendored single header, MIT) -------
enable_language(C)
add_library(linuxity_vibe STATIC third_party/vibe/vibe_impl.c)
target_include_directories(linuxity_vibe PUBLIC ${CMAKE_SOURCE_DIR}/third_party/vibe)
set_target_properties(linuxity_vibe PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
# third-party code: our C++ warning set doesn't apply to it
target_compile_options(linuxity_vibe PRIVATE -w)
target_link_libraries(linuxity_core INTERFACE linuxity_vibe)

# ---- Host backends -------------------------------------------------------
# The core above is header-only and host-agnostic. The executable needs a
# trap backend; today those are ptrace (Linux), Hypervisor.framework
# (macOS/arm64) and WHP (Windows/x86-64).
#
# ANDROID IS A PTRACE HOST. The NDK sets CMAKE_SYSTEM_NAME to "Android", not
# "Linux", so matching only "Linux" silently defined no `linuxity` target at
# all -- the build succeeded and produced nothing, which is a worse failure
# than an error. Android has the same kernel, the same ptrace ABI and the same
# seccomp; what differs (bionic vs glibc, no /etc/resolv.conf, SELinux policy)
# is handled behind the seams in runtime/ and kernel/, not here.
#
# One list, so a new Linux-ABI platform is one entry rather than a condition
# repeated per target.
set(LX_PTRACE_HOSTS Linux Android)
if(CMAKE_SYSTEM_NAME IN_LIST LX_PTRACE_HOSTS)
    add_subdirectory(src/host)
    # The guest side of the host bridge: static, so it runs in any distro.
    # It's embedded in linuxity (one file to ship); an instance writes it out
    # and puts it on the guest's PATH as xdg-open, wl-copy, notify-send.
    add_executable(linuxity-bridge src/guest/linuxity-bridge.c)
    target_link_options(linuxity-bridge PRIVATE -static)
    target_compile_options(linuxity-bridge PRIVATE -O2 -w)
    set_target_properties(linuxity-bridge PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    enable_language(ASM)
    set(LX_BRIDGE_BIN ${CMAKE_BINARY_DIR}/linuxity-bridge)
    file(WRITE ${CMAKE_BINARY_DIR}/bridge_blob.S
        ".section .rodata\n.balign 16\n.global lx_bridge_blob\nlx_bridge_blob:\n"
        ".incbin \"${LX_BRIDGE_BIN}\"\n.global lx_bridge_blob_end\nlx_bridge_blob_end:\n"
        ".section .note.GNU-stack,\"\",%progbits\n")
    set_source_files_properties(${CMAKE_BINARY_DIR}/bridge_blob.S PROPERTIES OBJECT_DEPENDS ${LX_BRIDGE_BIN})

    add_executable(linuxity src/main.cpp src/cli.cpp ${CMAKE_BINARY_DIR}/bridge_blob.S)
    target_link_libraries(linuxity PRIVATE linuxity_core linuxity_host z)
    add_dependencies(linuxity linuxity-bridge)
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
    # WinHvPlatform.dll is resolved at RUNTIME (see runtime/windows/api.hpp), NOT
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
