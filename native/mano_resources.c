/* Pin a beneath-only object. No pathname-based fallback on old kernels. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int mano_pin_beneath(int root_fd, const char *relative) {
    struct open_how how = {
        .flags = O_PATH | O_CLOEXEC,
        .mode = 0,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
                   RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
    };
    return (int)syscall(SYS_openat2, root_fd, relative, &how, sizeof(how));
}

/* Reopen only an already-held O_PATH regular inode; never a submitted pathname. */
int mano_read_pinned(int pinned) {
    struct stat before,after;
    int flags=fcntl(pinned,F_GETFL);
    if (flags<0 || !(flags&O_PATH) || fstat(pinned,&before) ||
        !S_ISREG(before.st_mode) || before.st_nlink!=1) {errno=EPERM;return -1;}
    char path[64];int n=snprintf(path,sizeof(path),"/proc/self/fd/%d",pinned);
    if (n<0 || (size_t)n>=sizeof(path)) {errno=EINVAL;return -1;}
    int fd=open(path,O_RDONLY|O_NONBLOCK|O_CLOEXEC);
    if (fd<0) return -1;
    if (fstat(fd,&after) || !S_ISREG(after.st_mode) || after.st_nlink!=1 ||
        before.st_dev!=after.st_dev || before.st_ino!=after.st_ino) {
        close(fd);errno=EPERM;return -1;
    }
    return fd;
}
