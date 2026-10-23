#define _GNU_SOURCE
#include <errno.h>
#include <linux/capability.h>
#include <linux/securebits.h>
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
    uint64_t setup = allowed | (1ULL << CAP_SYS_ADMIN) | (1ULL << CAP_NET_ADMIN) |
        (1ULL << CAP_SETPCAP);
    if (((effective | permitted) & ~setup) || (permitted & allowed) != allowed ||
        !(effective & (1ULL << CAP_SETPCAP))) {
        errno = EPERM; fail("unexpected controller capabilities");
    }
    /* UID 0 must not regain setup privileges on a later exec. Keep normal
       setuid fixups (locked off for NO_SETUID_FIXUP), and preserve only the
       explicit six capabilities through ambient inheritance into fixed Python. */
    unsigned int secure = SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
        SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED;
    if (prctl(PR_SET_SECUREBITS, secure, 0, 0, 0)) fail("package securebits lock");
    uint64_t bounding = 0;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        errno = 0;
        int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (present < 0 && errno == EINVAL) break;
        if (present < 0) fail("package bounding observation");
        if (!(allowed & (1ULL << cap)) &&
            prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) fail("package bounding drop");
        if (allowed & (1ULL << cap)) {
            if (!present) { errno = EPERM; fail("package bounding capability absent"); }
            bounding |= 1ULL << cap;
        }
    }
    if (bounding != allowed) { errno = EPERM; fail("package bounding mismatch"); }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
        fail("package ambient clear");
    struct __user_cap_data_struct reduced[2] = {{0}, {0}};
    reduced[0].effective = reduced[0].permitted = reduced[0].inheritable = (uint32_t)allowed;
    reduced[1].effective = reduced[1].permitted = reduced[1].inheritable = (uint32_t)(allowed >> 32);
    if (syscall(SYS_capset, &header, reduced)) fail("package exact capability drop");
    for (unsigned int cap = 0; cap < 64; ++cap)
        if ((allowed & (1ULL << cap)) &&
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0))
            fail("package ambient inheritance");
    if (syscall(SYS_capget, &header, caps)) fail("package capability recheck");
    effective = (uint64_t)caps[0].effective | ((uint64_t)caps[1].effective << 32);
    permitted = (uint64_t)caps[0].permitted | ((uint64_t)caps[1].permitted << 32);
    if (effective != allowed || permitted != allowed ||
        prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != (int)secure) {
        errno = EPERM; fail("package capability lock verification");
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) fail("package no_new_privs");
    scmp_filter_ctx filter = seccomp_init(SCMP_ACT_ALLOW);
    if (!filter) fail("package seccomp init");
    const char *denied[] = {
        "mount", "umount2", "pivot_root", "chroot", "unshare", "setns",
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
    /* clone3's pointer flags cannot be inspected by seccomp. Deny it as
       unavailable so glibc can use legacy clone, whose namespace flags below
       remain filtered. EPERM would also break ordinary pthread creation. */
    if (seccomp_rule_add(filter, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0) < 0)
        fail("package clone3 fallback rule");
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
    errno = 0;
    if (syscall(SYS_clone3, NULL, 0) != -1 || errno != ENOSYS)
        fail("package clone3 denial self-check");
    char *const command[] = {"/usr/bin/python3", "-P", "-m",
        "mano_runtime.package_apt", "--commit", NULL};
    execv(command[0], command);
    fail("package fixed worker exec");
}
