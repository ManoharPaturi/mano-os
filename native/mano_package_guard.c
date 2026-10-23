#define _GNU_SOURCE
#include <errno.h>
#include <linux/capability.h>
#include <sched.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *what) {
    int saved_errno = errno;
    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    int observed = syscall(SYS_capget, &header, caps) == 0;
    uint64_t effective = (uint64_t)caps[0].effective | ((uint64_t)caps[1].effective << 32);
    uint64_t permitted = (uint64_t)caps[0].permitted | ((uint64_t)caps[1].permitted << 32);
    /* what is always a fixed literal below, never package data or a path. */
    fprintf(stderr, "MANO_PACKAGE_ERROR={\"stage\":\"native-guard\","
        "\"error_type\":\"NativeGuard\",\"check\":\"%s\",\"errno\":%d,"
        "\"pid\":%ld,\"uid\":%lu,\"euid\":%lu,\"capget_ok\":%s,"
        "\"effective\":%llu,\"permitted\":%llu}\n", what, saved_errno,
        (long)getpid(), (unsigned long)getuid(), (unsigned long)geteuid(),
        observed ? "true" : "false", (unsigned long long)effective,
        (unsigned long long)permitted);
    exit(125);
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getuid() != 0 || geteuid() != 0 || getpid() != 2) {
        errno = EPERM; fail("private package namespace required");
    }
    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    uint64_t allowed = (1ULL << CAP_CHOWN) | (1ULL << CAP_DAC_OVERRIDE) |
        (1ULL << CAP_FOWNER) | (1ULL << CAP_FSETID) | (1ULL << CAP_SETUID) |
        (1ULL << CAP_SETGID);
    if (syscall(SYS_capget, &header, caps) != 0) fail("package capabilities");
    uint64_t effective = (uint64_t)caps[0].effective | ((uint64_t)caps[1].effective << 32);
    uint64_t permitted = (uint64_t)caps[0].permitted | ((uint64_t)caps[1].permitted << 32);
    if ((effective | permitted) & ~allowed) { errno = EPERM; fail("excess package capability"); }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) fail("package no_new_privs");
    scmp_filter_ctx filter = seccomp_init(SCMP_ACT_ALLOW);
    if (!filter) fail("package seccomp init");
    const char *denied[] = {
        "mount", "umount2", "pivot_root", "chroot", "unshare", "setns", "clone3",
        "fsopen", "fsconfig", "fsmount", "move_mount", "open_tree", "fspick",
        "ptrace", "process_vm_readv", "process_vm_writev", "pidfd_getfd",
        "bpf", "perf_event_open", "io_uring_setup", "keyctl", "add_key", "request_key",
        "reboot", "kexec_load", "kexec_file_load", "init_module", "finit_module",
        "delete_module", "iopl", "ioperm", "swapon", "swapoff", NULL
    };
    for (int i = 0; denied[i]; ++i) {
        int nr = seccomp_syscall_resolve_name(denied[i]);
        if (nr < 0 || seccomp_rule_add(filter, SCMP_ACT_ERRNO(EPERM), nr, 0) < 0)
            fail("package forbidden syscall rule");
    }
    unsigned long flags[] = { CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWPID,
        CLONE_NEWNET, CLONE_NEWIPC, CLONE_NEWUTS, CLONE_NEWCGROUP };
    for (size_t i = 0; i < sizeof(flags)/sizeof(flags[0]); ++i)
        if (seccomp_rule_add(filter, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
            SCMP_A0(SCMP_CMP_MASKED_EQ, flags[i], flags[i])) < 0) fail("package clone rule");
    int families[] = {AF_INET, AF_INET6, AF_NETLINK, AF_PACKET};
    for (size_t i = 0; i < sizeof(families)/sizeof(families[0]); ++i)
        if (seccomp_rule_add(filter, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
            SCMP_A0(SCMP_CMP_EQ, families[i])) < 0) fail("package network rule");
    if (seccomp_load(filter) < 0) fail("package seccomp load");
    seccomp_release(filter);
    errno = 0;
    if (unshare(0) != -1 || errno != EPERM) fail("package namespace denial self-check");
    char *const command[] = {"/usr/bin/python3", "-P", "-m",
        "mano_runtime.package_apt", "--commit", NULL};
    execv(command[0], command);
    fail("package fixed worker exec");
}
