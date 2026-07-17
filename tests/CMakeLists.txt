add_executable(test_core test_core.cpp)
target_link_libraries(test_core PRIVATE linuxity_core)
add_test(NAME core COMMAND test_core)

add_executable(test_authority test_authority.cpp)
target_link_libraries(test_authority PRIVATE linuxity_core)
add_test(NAME authority COMMAND test_authority)

add_executable(test_vfs test_vfs.cpp)
target_link_libraries(test_vfs PRIVATE linuxity_core)
add_test(NAME vfs COMMAND test_vfs)
