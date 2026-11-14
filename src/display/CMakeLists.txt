# linuxity-display: the native Wayland compositor guests' GUI apps talk to.
#
# A separate executable on purpose: on macOS every guest process is a
# linuxity process, and none of them should pay for loading AppKit. The
# core (protocol, surfaces, shell, seat) is portable C++; a host backend
# under hosts/ supplies windows, input and the event loop.
add_library(linuxity_display_core STATIC
    protocol/protocol.cpp
    core/server.cpp
    core/surface.cpp
    core/shell.cpp
    core/seat.cpp
    core/scale.cpp
    core/extras.cpp
    core/compositor.cpp
    core/poll_loop.cpp
    core/soft_compose.cpp)
target_include_directories(linuxity_display_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# generated tables and the wire templates: keep the strict set, minus the
# conversions the 24.8/byte-twiddling code does on purpose
target_compile_options(linuxity_display_core PRIVATE -Wno-sign-conversion)

# -- Host backends -------------------------------------------------------------
# lx_display_host(<name> SOURCES <files...> [LIBRARIES <libs...>]
#                 [OPTIONS <compile options...>] [CONDITION <bool>])
#
# One call per backend in hosts/<name>/. The backend's sources must define
#     const lx::display::HostBackend& lx_display_host_<name>();
# Each enabled backend becomes its own static library (so a host's
# platform frameworks link only where it does) and a line of the generated
# host_list.inc, which host_registry.cpp turns into the backend list. No
# other file names a platform.
set(LX_DISPLAY_HOSTS "" CACHE INTERNAL "")
function(lx_display_host name)
    cmake_parse_arguments(H "" "CONDITION" "SOURCES;LIBRARIES;OPTIONS" ${ARGN})
    if(DEFINED H_CONDITION AND NOT H_CONDITION)
        return()
    endif()
    set(lib linuxity_display_host_${name})
    add_library(${lib} STATIC ${H_SOURCES})
    target_link_libraries(${lib} PUBLIC linuxity_display_core ${H_LIBRARIES})
    if(H_OPTIONS)
        target_compile_options(${lib} PRIVATE ${H_OPTIONS})
    endif()
    set(LX_DISPLAY_HOSTS ${LX_DISPLAY_HOSTS} ${name} CACHE INTERNAL "")
endfunction()

lx_display_host(headless SOURCES hosts/headless/headless.cpp)

if(APPLE)
    enable_language(OBJCXX)
    set(LX_COCOA_FRAMEWORKS "-framework AppKit" "-framework QuartzCore" "-framework Carbon"
                            "-framework CoreVideo" "-framework IOSurface")
    set(LX_OBJC_OPTIONS -fobjc-arc -Wno-old-style-cast -Wno-sign-conversion -Wno-shorten-64-to-32
                        -Wno-gnu-conditional-omitted-operand)
    lx_display_host(cocoa
        SOURCES hosts/cocoa/cocoa_host.mm
        LIBRARIES ${LX_COCOA_FRAMEWORKS}
        OPTIONS ${LX_OBJC_OPTIONS})
endif()

# the registry: one LX_DISPLAY_HOST(name) line per enabled backend
set(LX_HOST_LIST "")
foreach(h IN LISTS LX_DISPLAY_HOSTS)
    string(APPEND LX_HOST_LIST "LX_DISPLAY_HOST(${h})\n")
endforeach()
file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/host_list.inc CONTENT "${LX_HOST_LIST}")

add_executable(linuxity-display main.cpp host_registry.cpp)
target_include_directories(linuxity-display PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
foreach(h IN LISTS LX_DISPLAY_HOSTS)
    target_link_libraries(linuxity-display PRIVATE linuxity_display_host_${h})
endforeach()
set_target_properties(linuxity-display PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
install(TARGETS linuxity-display RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# -- Tests -----------------------------------------------------------------------
# The compositor core against a scripted client, on the headless host.
add_executable(test_display ${CMAKE_SOURCE_DIR}/tests/display/test_display.cpp)
target_link_libraries(test_display PRIVATE linuxity_display_host_headless)
target_compile_options(test_display PRIVATE -UNDEBUG -Wno-sign-conversion)
add_test(NAME display COMMAND test_display)

# Every backend in this build against the same contract (what any Host
# must do), where it can run here; plus the registry itself.
add_executable(test_display_hosts ${CMAKE_SOURCE_DIR}/tests/display/test_hosts.cpp host_registry.cpp)
target_include_directories(test_display_hosts PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
foreach(h IN LISTS LX_DISPLAY_HOSTS)
    target_link_libraries(test_display_hosts PRIVATE linuxity_display_host_${h})
endforeach()
target_compile_options(test_display_hosts PRIVATE -UNDEBUG)
add_test(NAME display_hosts COMMAND test_display_hosts)

if(APPLE)
    # The macOS host against real AppKit windows (needs a GUI session).
    add_executable(test_cocoa ${CMAKE_SOURCE_DIR}/tests/display/test_cocoa.mm)
    set_source_files_properties(${CMAKE_SOURCE_DIR}/tests/display/test_cocoa.mm PROPERTIES
        COMPILE_OPTIONS "-fobjc-arc;-Wno-old-style-cast;-Wno-sign-conversion;-Wno-shorten-64-to-32;-UNDEBUG")
    target_link_libraries(test_cocoa PRIVATE linuxity_display_host_cocoa)
    add_test(NAME display_cocoa COMMAND test_cocoa)
endif()
