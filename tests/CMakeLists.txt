# Portable tests: exercise the host-agnostic core (abi/kernel/vfs/loader)
# against mocks. These must build and pass on EVERY host (Linux, macOS,
# Windows) — they are the contract that keeps the core portable.
set(LX_PORTABLE_TESTS
    core authority vfs hostfs loader interp file_namespace sysfs_proctree
    resources)

# Live tests: run real guest ELF binaries through a trap backend. Today the
# only backend is ptrace (Linux), so they are Linux-only until the HVF/WHP
# backends land.
set(LX_LIVE_TESTS
    run_native run_rootfs run_multiproc run_signal run_identity run_stat_owner
    run_open_procfs run_mutate run_dev run_socket run_daemon run_shebang
    run_tty_jobcontrol run_pid_namespace run_seccomp run_meta run_bind
    run_foreign_exec run_untranslated run_empty_path)

set(LX_TESTS ${LX_PORTABLE_TESTS})
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND LX_TESTS ${LX_LIVE_TESTS})
endif()

foreach(t IN LISTS LX_TESTS)
    add_executable(test_${t} test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE linuxity_core)
    add_test(NAME ${t} COMMAND test_${t})
endforeach()
