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
add_subdirectory(src/host)

# ---- The executable that wires a host to the core ------------------------
add_executable(linuxity src/main.cpp)
target_link_libraries(linuxity PRIVATE linuxity_core linuxity_host)

# ---- Tests ---------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
