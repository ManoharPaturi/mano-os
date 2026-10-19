#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <sched.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <termios.h>
#include <unistd.h>

/* ABI 5 UAPI bit, absent from Ubuntu 24.04's older build headers. Runtime
 * enforcement still requires ABI >= 5 and never drops this restriction. */
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

static void fail(const char *operation) {
    perror(operation);
    exit(125);
}

static void path_rule(int ruleset, const char *path, uint64_t access) {
    int fd = open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) fail("guard path");
    struct landlock_path_beneath_attr rule = { .allowed_access = access, .parent_fd = fd };
    if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule, 0))
        fail("guard Landlock rule");
    close(fd);
}

static void landlock(void) {
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 5) { errno = ENOTSUP; fail("guard requires Landlock ABI 5"); }
    uint64_t read = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    uint64_t execute = read | LANDLOCK_ACCESS_FS_EXECUTE;
    uint64_t mutable = execute | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_SYM |
        LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE;
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = mutable | LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            LANDLOCK_ACCESS_FS_IOCTL_DEV,
        .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
    };
    int ruleset = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (ruleset < 0) fail("guard Landlock ruleset");
    path_rule(ruleset, "/usr", execute);
    path_rule(ruleset, "/proc", read);
    path_rule(ruleset, "/dev", read | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_IOCTL_DEV);
    const char *writable[] = { "/workspace", "/task-cwd", "/tmp", "/home/task" };
    for (size_t i = 0; i < sizeof(writable)/sizeof(writable[0]); ++i)
        path_rule(ruleset, writable[i], mutable);
    if (syscall(SYS_landlock_restrict_self, ruleset, 0)) fail("guard Landlock enforcement");
    close(ruleset);
    errno = 0;
    int probe = open("/etc/mano-guard-denial-canary", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (probe >= 0) { close(probe); unlink("/etc/mano-guard-denial-canary"); errno = EACCES; }
    else if (errno == EACCES) return;
    fail("guard Landlock denial self-check");
}

static void filter(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) fail("guard seccomp init");
    if (seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS) < 0 ||
        seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1) < 0) fail("guard seccomp attributes");
    const char *denied[] = {
        "ptrace", "process_vm_readv", "process_vm_writev", "bpf", "perf_event_open",
        "keyctl", "add_key", "request_key", "io_uring_setup", "io_uring_enter", "io_uring_register",
        "mount", "umount2", "pivot_root", "open_tree", "move_mount", "fsopen", "fsconfig",
        "fsmount", "fspick", "mount_setattr", "setns", "unshare", "open_by_handle_at",
        "name_to_handle_at", "init_module", "finit_module", "delete_module", "kexec_load",
        "kexec_file_load", "reboot", "swapon", "swapoff", "acct", "mknod", "mknodat",
        "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "setgroups",
        "setfsuid", "setfsgid"
    };
    for (size_t i = 0; i < sizeof(denied)/sizeof(denied[0]); ++i) {
        int number = seccomp_syscall_resolve_name(denied[i]);
        if (number == __NR_SCMP_ERROR) continue; /* Not a syscall on this native architecture. */
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), number, 0) < 0)
            fail("guard seccomp deny rule");
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0) < 0)
        fail("guard clone3 rule"); /* libc can use clone, whose namespace flags are filtered. */
    unsigned long namespaces[] = { CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWNET,
        CLONE_NEWIPC, CLONE_NEWUTS, CLONE_NEWCGROUP };
    for (size_t i = 0; i < sizeof(namespaces)/sizeof(namespaces[0]); ++i)
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
            SCMP_A0(SCMP_CMP_MASKED_EQ, namespaces[i], namespaces[i])) < 0)
            fail("guard clone namespace rule");
    int families[] = { AF_INET, AF_INET6, AF_NETLINK, AF_PACKET };
    for (size_t i = 0; i < sizeof(families)/sizeof(families[0]); ++i)
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
            SCMP_A0(SCMP_CMP_EQ, families[i])) < 0) fail("guard socket family rule");
    if (seccomp_load(ctx) < 0) fail("guard seccomp load");
    seccomp_release(ctx);
    errno = 0;
    if (unshare(0) != -1 || errno != EPERM) fail("guard unshare denial self-check");
    errno = 0;
    if (setresuid(-1, -1, -1) != -1 || errno != EPERM) fail("guard identity denial self-check");
}

int main(int argc, char **argv) {
    if (argc < 2 || geteuid() == 0 || getuid() != geteuid() ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 || access("/etc", W_OK)) {
        errno = EPERM; fail("guard unprivileged sandbox preconditions");
    }
    if (syscall(SYS_close_range, 3U, ~0U, 0)) fail("guard FD closure");
    int first = 1;
    if (!strcmp(argv[1], "--task-pty")) {
        struct stat initial, other;
        if (argc < 3 || fstat(0, &initial) || !S_ISCHR(initial.st_mode) ||
            initial.st_uid != geteuid() || !isatty(0)) {
            errno = EPERM; fail("guard task-owned PTY");
        }
        for (int fd = 1; fd <= 2; ++fd) {
            if (fstat(fd, &other) || !isatty(fd) || initial.st_dev != other.st_dev ||
                initial.st_ino != other.st_ino || initial.st_rdev != other.st_rdev) {
                errno = EPERM; fail("guard exact PTY streams");
            }
        }
        if (getsid(0) != getpid() && setsid() < 0) fail("guard PTY session");
        /* Never force/steal a terminal belonging to another session. */
        if (ioctl(0, TIOCSCTTY, 0) || tcgetsid(0) != getsid(0))
            fail("guard PTY controlling session");
        first = 2;
    }
    landlock();
    filter();
    execvp(argv[first], &argv[first]);
    fail("guard task exec");
}
