/* Fixed-file read-only F_GETLK observer; disposable Root Linux CI only. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static bool marker(void) {
    char text[64] = {0};
    struct stat info;
    int fd = open("/etc/mano-lab-disposable", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t count = read(fd, text, sizeof(text) - 1);
    bool okay = !fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_uid == 0 &&
        info.st_nlink == 1 && !(info.st_mode & 022) &&
        (count == 14 || (count == 15 && text[14] == '\n')) &&
        !memcmp(text, "mano-phase0-ci", 14);
    close(fd);
    return okay;
}

static bool observe(const char *path, const char *label) {
    int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat info;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};
    bool okay = !fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_uid == 0 &&
        info.st_nlink == 1 && !(info.st_mode & 022) && !fcntl(fd, F_GETLK, &lock);
    close(fd);
    if (!okay) return false;
    if (lock.l_type != F_WRLCK || lock.l_whence != SEEK_SET || lock.l_start != 0 ||
        lock.l_len != 0 || lock.l_pid <= 0) {
        fprintf(stderr, "%s lock observation: type=%d pid=%ld\n", label,
                (int)lock.l_type, (long)lock.l_pid);
        return false;
    }
    printf("\"%s\":{\"pid\":%ld,\"inode\":%llu,\"major\":%u,\"minor\":%u,"
           "\"kind\":\"POSIX\",\"range\":\"0:EOF\"}", label, (long)lock.l_pid,
           (unsigned long long)info.st_ino, major(info.st_dev), minor(info.st_dev));
    return true;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getuid() != 0 || geteuid() != 0 || !marker()) return 2;
    printf("{\"observer_pid\":%ld,\"query\":\"F_GETLK\",\"owners\":{", (long)getpid());
    if (!observe("/var/lib/dpkg/lock-frontend", "frontend")) return 2;
    putchar(',');
    if (!observe("/var/lib/dpkg/lock", "backend")) return 2;
    puts("}}");
    return 0;
}
