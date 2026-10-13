/* Pin a beneath-only object. No pathname-based fallback on old kernels. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/openat2.h>
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
