# Portable tests: exercise the host-agnostic core (abi/kernel/vfs/loader)
# against mocks. These must build and pass on EVERY host (Linux, macOS,
# Windows) — they are the contract that keeps the core portable.
#
# The tests ARE assert()s, and the default build is RelWithDebInfo, whose
# -DNDEBUG compiled every one of them away: a test that checks nothing exits
# 0, so the suite stayed green while asserting nothing (the only symptom was
# a wall of unused-variable warnings). Everything in this directory keeps
# its asserts, whatever the build type; the runtime itself keeps NDEBUG.
if(MSVC)
    add_compile_options(/UNDEBUG)
else()
    add_compile_options(-UNDEBUG)
endif()
set(LX_PORTABLE_TESTS
    core authority vfs interp file_namespace sysfs_proctree
    resources address_space sysno conformance outcome wire fd_slots
    conform_law conform_hosts conform_coverage resolver landlock creds fsnotify)

# The syscall-cost benchmark. NOT a ctest: it measures, it does not assert,
# and a timing threshold in CI is a flake generator. Build it and run it by
# hand, natively and under linuxity, and compare the ratio -- which cancels
# the machine out.
#
#   cmake --build build --target bench_syscall
#   ./build/tests/bench_syscall 100000           # native baseline
#   ./build/linuxity ./build/tests/bench_syscall 100000
#
# The conformance suite proves every answer is RIGHT and says nothing about
# what it COSTS, so a change that made a hot path ten times slower would
# pass all 55 tests. This is the other half.
if(CMAKE_SYSTEM_NAME IN_LIST LX_PTRACE_HOSTS)
    enable_language(C)
    add_executable(bench_syscall EXCLUDE_FROM_ALL bench_syscall.c)
endif()

# The intercepted-syscall list that conform_coverage divides by is GENERATED
# from the dispatcher (tools/intercepted.py), because the hand-written one
# drifted -- it counted syscalls that merely forward, so coverage read 84%
# when the honest figure was 69%. This check fails if someone adds a handler
# without regenerating, which would silently shrink the denominator.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME conform_denominator
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_SOURCE_DIR}/tools/intercepted.py --check)
endif()

# Tests that instantiate PosixHost. These exercise the POSIX *host backend*
# (mmap/dirent/pread), not the portable core, so they are POSIX-only: the
# Win32 CRT has no <sys/mman.h>. Keeping them out of LX_PORTABLE_TESTS is
# what lets the portable set be a real cross-host contract rather than one
# that quietly means "POSIX".
set(LX_POSIX_HOST_TESTS hostfs loader hostcalls cpu_truth env_config)

# Live tests: run real guest ELF binaries through a trap backend. Today the
# only complete backend is ptrace (Linux), so they are Linux-only until the
# HVF/WHP backends grow their loader + fd layers.
set(LX_LIVE_TESTS
    run_native run_rootfs run_multiproc run_signal run_identity run_stat_owner
    run_open_procfs run_mutate run_dev run_socket run_daemon run_shebang
    run_tty_jobcontrol run_ttyname run_termios2 run_trap_insn run_pid_namespace run_seccomp run_meta run_bind
    run_foreign_exec run_untranslated run_empty_path run_rewinddir run_fd_reuse run_proc_self run_proc_link run_path_escape
    run_orphan_confined run_link_emulation run_root_access run_instance)

# ---- differential conformance -------------------------------------------
#
# The test that actually verifies handlers: run each scenario's probe natively
# AND under linuxity, then compare with judge(). Linux-only because it needs a
# live kernel as the oracle; on macOS/Windows the same comparison runs against
# recorded goldens instead (conform_hosts covers that path).
#
# Probes are C, built with raw syscalls and no libc conveniences -- glibc
# caches (telldir), retries (EINTR) and emulates (open->openat), so a libc
# call observes glibc's opinion of the kernel rather than the kernel.
# LX_PTRACE_HOSTS comes from the top-level CMakeLists -- the ONE place that
# says which platforms have the Linux ptrace ABI (Linux and Android). These
# live tests spawn a real guest, so they need exactly that set.
if(CMAKE_SYSTEM_NAME IN_LIST LX_PTRACE_HOSTS)
    # Probes are C; the project is C++-only, so enable C just for them.
    enable_language(C)
    set(LX_PROBES dirseek statpaths fdops rwio procid fsmutate memory signals ioctls legacy xattrs creds cwdfs jitwx proclife syscalls2 mountns namespaces sysvipc ptrace fuzz)
    foreach(p IN LISTS LX_PROBES)
        add_executable(probe_${p} probes/${p}.c)
        target_include_directories(probe_${p} PRIVATE probes)
        set_target_properties(probe_${p} PROPERTIES
            OUTPUT_NAME ${p}
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/probes)
        # A probe must observe the kernel, not the optimiser.
        target_compile_options(probe_${p} PRIVATE -O0)
    endforeach()

    add_executable(test_conform_diff test_conform_diff.cpp)
    target_link_libraries(test_conform_diff PRIVATE linuxity_core)
    add_dependencies(test_conform_diff linuxity)
    foreach(p IN LISTS LX_PROBES)
        add_dependencies(test_conform_diff probe_${p})
    endforeach()

    add_test(NAME conform_diff COMMAND test_conform_diff)
    # Absolute paths: the guest resolves its program through its own
    # namespace, so a relative path fails with ENOENT (exit 127).
    set_tests_properties(conform_diff PROPERTIES
        ENVIRONMENT "LX_PROBE_DIR=${CMAKE_BINARY_DIR}/probes;LX_BINARY=${CMAKE_BINARY_DIR}/linuxity;LX_GOLDEN_DIR=${CMAKE_SOURCE_DIR}/tests/goldens"
        TIMEOUT 120)

    # The PORTABILITY PROOF: verify linuxity against the committed goldens,
    # with no live kernel consulted. This is the test macOS and Windows will
    # run -- it needs only a ProbeRunner, not HasLinuxKernel -- so having it
    # green on Linux too means the replay path itself is exercised in CI
    # rather than only on the hosts that depend on it.
    add_executable(test_conform_replay test_conform_replay.cpp)
    target_link_libraries(test_conform_replay PRIVATE linuxity_core)
    add_dependencies(test_conform_replay linuxity)
    foreach(p IN LISTS LX_PROBES)
        add_dependencies(test_conform_replay probe_${p})
    endforeach()
    add_test(NAME conform_replay COMMAND test_conform_replay)
    set_tests_properties(conform_replay PROPERTIES
        ENVIRONMENT "LX_PROBE_DIR=${CMAKE_BINARY_DIR}/probes;LX_BINARY=${CMAKE_BINARY_DIR}/linuxity;LX_GOLDEN_DIR=${CMAKE_SOURCE_DIR}/tests/goldens"
        TIMEOUT 120)

    # The golden RECORDER. A tool, not a test: it writes files, so ctest never
    # runs it. Invoke deliberately on each Linux arch and commit the result --
    # that is what lets a macOS or Windows host verify itself with no Linux
    # kernel to compare against.
    #
    #   cmake --build build --target record_goldens
    #   LX_PROBE_DIR=$PWD/build/probes ./build/tests/record_goldens
    add_executable(record_goldens record_goldens.cpp)
    target_link_libraries(record_goldens PRIVATE linuxity_core)
    foreach(p IN LISTS LX_PROBES)
        add_dependencies(record_goldens probe_${p})
    endforeach()
endif()

# Linux-only UNIT tests: they include <linux/*.h> (seccomp, audit) but run no
# guest, so they belong with the fast tests rather than LX_LIVE_TESTS.
set(LX_LINUX_UNIT_TESTS seccomp_arch nl80211)

set(LX_TESTS ${LX_PORTABLE_TESTS})
if(NOT WIN32)
    list(APPEND LX_TESTS ${LX_POSIX_HOST_TESTS})
endif()
if(CMAKE_SYSTEM_NAME IN_LIST LX_PTRACE_HOSTS)
    list(APPEND LX_TESTS ${LX_LINUX_UNIT_TESTS})
    list(APPEND LX_TESTS ${LX_LIVE_TESTS})
endif()

foreach(t IN LISTS LX_TESTS)
    add_executable(test_${t} test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE linuxity_core)
    add_test(NAME ${t} COMMAND test_${t})
endforeach()
# drives the real binary (env, up, exec, down)
if(TARGET test_run_instance AND TARGET linuxity)
    add_dependencies(test_run_instance linuxity)
endif()

# The command line agrees with itself: every verb help shows is known to
# `help VERB` and offered by completion, and nothing else is (src/verbs.hpp).
if(TARGET linuxity AND NOT WIN32)
    add_test(NAME cli_contract
             COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/cli_contract.sh $<TARGET_FILE:linuxity>)
    # A real login shell on a pty survives commands, ^C, ^Z and pty-master
    # requests. Needs an environment: LINUXITY_TEST_ENV=<name>, else skips.
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_FOUND)
        add_test(NAME session_tty
                 COMMAND sh -c "[ -n \"$LINUXITY_TEST_ENV\" ] || exit 77; ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/session_tty.py $<TARGET_FILE:linuxity> \"$LINUXITY_TEST_ENV\"")
        set_tests_properties(session_tty PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)
    endif()
endif()

# The runtime/ layering invariants (no cross-backend includes, portable
# headers free of backend deps, shared/ free of platform APIs, every backend
# asserting the contract). A shell check rather than a C++ test because it is
# a statement about the FILE TREE, which no translation unit can observe.
if(NOT WIN32)
    add_test(NAME runtime_layout
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../tools/check_layout.sh)
endif()

# Every syscall the dispatcher HANDLES must actually be TRAPPED by the seccomp
# filter, or the handler is dead code and the guest gets the host's answer.
# This shape has caused four bugs (lseek/rewinddir, fchmodat2, creat,
# set_tid_address) -- two of them sandbox escapes -- so it is a test, not a
# convention. Linux-only: the filter is the ptrace backend's.
if(CMAKE_SYSTEM_NAME IN_LIST LX_PTRACE_HOSTS)
    add_test(NAME syscall_coverage
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../tools/check_syscall_coverage.sh)
    # the in-guest handler must answer exactly like the trap, and see
    # changes made mid-run. Both need a distro rootfs with a shell; point
    # LINUXITY_TEST_ROOT at one, or they skip.
    foreach(t diff change stress union)
        add_test(NAME inguest_${t}
                 COMMAND sh -c "[ -n \"$LINUXITY_TEST_ROOT\" ] || exit 77; u=$(mktemp -d); bash ${CMAKE_CURRENT_SOURCE_DIR}/inguest/${t}.sh $<TARGET_FILE:linuxity> \"$LINUXITY_TEST_ROOT\" $u; r=$?; rm -rf $u; exit $r")
        set_tests_properties(inguest_${t} PROPERTIES SKIP_RETURN_CODE 77)
    endforeach()
endif()

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

    # The tree-wide Hypervisor.framework VM budget: pure shared-memory
    # arithmetic, no VM needed.
    add_executable(test_vm_budget test_vm_budget.cpp)
    target_link_libraries(test_vm_budget PRIVATE linuxity_core)
    add_test(NAME vm_budget COMMAND test_vm_budget)
endif()

# The Windows hypervisor backend (WHP). The test is split internally: the
# offline half (Linux/Win32 flag + struct translation, the page-table walk)
# runs anywhere, and the live half creates a real partition and SKIPS cleanly
# when Hyper-V is unavailable -- so a developer without virtualization
# enabled still gets a green suite. WinHvPlatform.dll is loaded at runtime,
# so there is nothing to link.
if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_executable(test_whp test_whp.cpp)
    target_link_libraries(test_whp PRIVATE linuxity_core)
    add_test(NAME whp COMMAND test_whp)

    # The ELF loader + SysV startup stack. Synthesizes real static x86-64
    # ELFs on disk, loads them, and (with a hypervisor) RUNS them -- the
    # guest reads argc off its own stack and exits with it, so a wrong stack
    # layout fails loudly instead of passing by luck.
    add_executable(test_whp_load test_whp_load.cpp)
    target_link_libraries(test_whp_load PRIVATE linuxity_core)
    add_test(NAME whp_load COMMAND test_whp_load)

    # The memory manager and fd table: the frame allocator's uniqueness and
    # arena containment, the fd table's stdio duplication and refcounting,
    # rootfs path containment, and -- the important one -- that the fault
    # arbiter can tell lazy memory from a genuine SIGSEGV.
    add_executable(test_whp_mm test_whp_mm.cpp)
    target_link_libraries(test_whp_mm PRIVATE linuxity_core)
    add_test(NAME whp_mm COMMAND test_whp_mm)
endif()
