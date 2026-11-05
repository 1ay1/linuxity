# Portable tests: exercise the host-agnostic core (abi/kernel/vfs/loader)
# against mocks. These must build and pass on EVERY host (Linux, macOS,
# Windows) — they are the contract that keeps the core portable.
set(LX_PORTABLE_TESTS
    core authority vfs hostfs loader interp file_namespace sysfs_proctree
    resources hvf_vma sysno conformance)

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

# The macOS hypervisor backend. Needs the Hypervisor framework and -- because
# hv_vm_create is entitlement-gated -- an ad-hoc code signature carrying
# com.apple.security.hypervisor. Without it the test SKIPS rather than fails,
# so an unsigned build still passes; the signing step below means a local
# developer build actually exercises the guest.
if(APPLE AND CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    add_executable(test_hvf_run test_hvf_run.cpp)
    target_link_libraries(test_hvf_run PRIVATE linuxity_core
                          "-framework Hypervisor")
    add_custom_command(TARGET test_hvf_run POST_BUILD
        COMMAND codesign -s - --entitlements
                ${CMAKE_CURRENT_SOURCE_DIR}/hypervisor.entitlements
                -f $<TARGET_FILE:test_hvf_run>
        COMMENT "Signing test_hvf_run with the hypervisor entitlement"
        VERBATIM)
    add_test(NAME hvf_run COMMAND test_hvf_run)
endif()
