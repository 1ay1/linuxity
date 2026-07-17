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

add_executable(test_interp test_interp.cpp)
target_link_libraries(test_interp PRIVATE linuxity_core)
add_test(NAME interp COMMAND test_interp)

add_executable(test_run_native test_run_native.cpp)
target_link_libraries(test_run_native PRIVATE linuxity_core)
add_test(NAME run_native COMMAND test_run_native)

add_executable(test_file_namespace test_file_namespace.cpp)
target_link_libraries(test_file_namespace PRIVATE linuxity_core)
add_test(NAME file_namespace COMMAND test_file_namespace)

add_executable(test_sysfs_proctree test_sysfs_proctree.cpp)
target_link_libraries(test_sysfs_proctree PRIVATE linuxity_core)
add_test(NAME sysfs_proctree COMMAND test_sysfs_proctree)

add_executable(test_run_rootfs test_run_rootfs.cpp)
target_link_libraries(test_run_rootfs PRIVATE linuxity_core)
add_test(NAME run_rootfs COMMAND test_run_rootfs)

add_executable(test_run_multiproc test_run_multiproc.cpp)
target_link_libraries(test_run_multiproc PRIVATE linuxity_core)
add_test(NAME run_multiproc COMMAND test_run_multiproc)

add_executable(test_run_signal test_run_signal.cpp)
target_link_libraries(test_run_signal PRIVATE linuxity_core)
add_test(NAME run_signal COMMAND test_run_signal)

add_executable(test_run_identity test_run_identity.cpp)
target_link_libraries(test_run_identity PRIVATE linuxity_core)
add_test(NAME run_identity COMMAND test_run_identity)

add_executable(test_run_stat_owner test_run_stat_owner.cpp)
target_link_libraries(test_run_stat_owner PRIVATE linuxity_core)
add_test(NAME run_stat_owner COMMAND test_run_stat_owner)

add_executable(test_run_open_procfs test_run_open_procfs.cpp)
target_link_libraries(test_run_open_procfs PRIVATE linuxity_core)
add_test(NAME run_open_procfs COMMAND test_run_open_procfs)

add_executable(test_run_mutate test_run_mutate.cpp)
target_link_libraries(test_run_mutate PRIVATE linuxity_core)
add_test(NAME run_mutate COMMAND test_run_mutate)

add_executable(test_run_dev test_run_dev.cpp)
target_link_libraries(test_run_dev PRIVATE linuxity_core)
add_test(NAME run_dev COMMAND test_run_dev)

add_executable(test_run_shebang test_run_shebang.cpp)
target_link_libraries(test_run_shebang PRIVATE linuxity_core)
add_test(NAME run_shebang COMMAND test_run_shebang)

add_executable(test_run_tty_jobcontrol test_run_tty_jobcontrol.cpp)
target_link_libraries(test_run_tty_jobcontrol PRIVATE linuxity_core)
add_test(NAME run_tty_jobcontrol COMMAND test_run_tty_jobcontrol)

add_executable(test_run_pid_namespace test_run_pid_namespace.cpp)
target_link_libraries(test_run_pid_namespace PRIVATE linuxity_core)
add_test(NAME run_pid_namespace COMMAND test_run_pid_namespace)

add_executable(test_run_seccomp test_run_seccomp.cpp)
target_link_libraries(test_run_seccomp PRIVATE linuxity_core)
add_test(NAME run_seccomp COMMAND test_run_seccomp)

add_executable(test_run_meta test_run_meta.cpp)
target_link_libraries(test_run_meta PRIVATE linuxity_core)
add_test(NAME run_meta COMMAND test_run_meta)

add_executable(test_run_bind test_run_bind.cpp)
target_link_libraries(test_run_bind PRIVATE linuxity_core)
add_test(NAME run_bind COMMAND test_run_bind)

add_executable(test_run_foreign_exec test_run_foreign_exec.cpp)
target_link_libraries(test_run_foreign_exec PRIVATE linuxity_core)
add_test(NAME run_foreign_exec COMMAND test_run_foreign_exec)

add_executable(test_resources test_resources.cpp)
target_link_libraries(test_resources PRIVATE linuxity_core)
add_test(NAME resources COMMAND test_resources)
