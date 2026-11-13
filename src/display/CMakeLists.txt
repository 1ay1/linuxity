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
    core/compositor.cpp
    core/poll_loop.cpp
    hosts/headless.cpp)
target_include_directories(linuxity_display_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# generated tables and the wire templates: keep the strict set, minus the
# conversions the 24.8/byte-twiddling code does on purpose
target_compile_options(linuxity_display_core PRIVATE -Wno-sign-conversion)

add_executable(linuxity-display main.cpp)
target_link_libraries(linuxity-display PRIVATE linuxity_display_core)
set_target_properties(linuxity-display PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

if(APPLE)
    enable_language(OBJCXX)
    target_sources(linuxity-display PRIVATE hosts/cocoa/cocoa_host.mm)
    set_source_files_properties(hosts/cocoa/cocoa_host.mm PROPERTIES
        COMPILE_OPTIONS "-fobjc-arc;-Wno-old-style-cast;-Wno-sign-conversion;-Wno-shorten-64-to-32")
    target_compile_definitions(linuxity-display PRIVATE LX_DISPLAY_COCOA=1)
    target_link_libraries(linuxity-display PRIVATE
        "-framework AppKit" "-framework QuartzCore" "-framework Carbon" "-framework CoreVideo")
endif()

install(TARGETS linuxity-display RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# The compositor core against a scripted client, on the headless host.
add_executable(test_display ${CMAKE_SOURCE_DIR}/tests/display/test_display.cpp)
target_link_libraries(test_display PRIVATE linuxity_display_core)
target_compile_options(test_display PRIVATE -UNDEBUG -Wno-sign-conversion)
add_test(NAME display COMMAND test_display)
