/* Version script for the linuxity aarch64 vDSO: exactly the Linux ABI names,
 * under LINUX_2.6.39, which is what glibc's dl_vdso_vsym() asks for. */
LINUX_2.6.39 {
    global:
        __kernel_clock_gettime;
        __kernel_gettimeofday;
        __kernel_clock_getres;
        __kernel_rt_sigreturn;
    local: *;
};
