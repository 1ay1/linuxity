add_executable(test_core test_core.cpp)
target_link_libraries(test_core PRIVATE linuxity_core)
add_test(NAME core COMMAND test_core)

add_executable(test_authority test_authority.cpp)
target_link_libraries(test_authority PRIVATE linuxity_core)
add_test(NAME authority COMMAND test_authority)

add_executable(test_vfs test_vfs.cpp)
target_link_libraries(test_vfs PRIVATE linuxity_core)
add_test(NAME vfs COMMAND test_vfs)

add_executable(test_hostfs test_hostfs.cpp)
target_link_libraries(test_hostfs PRIVATE linuxity_core)
add_test(NAME hostfs COMMAND test_hostfs)

add_executable(test_loader test_loader.cpp)
target_link_libraries(test_loader PRIVATE linuxity_core)
add_test(NAME loader COMMAND test_loader)

add_executable(test_run_native test_run_native.cpp)
target_link_libraries(test_run_native PRIVATE linuxity_core)
add_test(NAME run_native COMMAND test_run_native)

add_executable(test_file_namespace test_file_namespace.cpp)
target_link_libraries(test_file_namespace PRIVATE linuxity_core)
add_test(NAME file_namespace COMMAND test_file_namespace)

add_executable(test_run_rootfs test_run_rootfs.cpp)
target_link_libraries(test_run_rootfs PRIVATE linuxity_core)
add_test(NAME run_rootfs COMMAND test_run_rootfs)
