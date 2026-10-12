/* Fixed CI watchdog/stop route. No arbitrary command executor or Python runtime. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

#define BASE "/run/mano-stop-fixture"
#define SOCKET BASE "/human.sock"
#define EPOCH "/var/lib/mano-broker/grant-epoch"
#define LATCH "/var/lib/mano-broker/stop-latched"
static char group[512];

static int fixed_write(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    size_t length = strlen(text);
    int ok = write(fd, text, length) == (ssize_t)length && fsync(fd) == 0;
    close(fd); return ok ? 0 : -1;
}
static int stop_all(void) {
    if (access(LATCH, F_OK)) {
        FILE *file = fopen(EPOCH, "r"); unsigned long long epoch;
        if (!file || fscanf(file, "%llu", &epoch) != 1) { if (file) fclose(file); return -1; }
        fclose(file);
        if (fixed_write(LATCH, "latched\n")) return -1;
        char value[64]; snprintf(value, sizeof(value), "%llu\n", epoch + 1);
        if (fixed_write(EPOCH ".new", value) || rename(EPOCH ".new", EPOCH)) return -1;
    }
    if (chown("/run/mano-stop-agent", 0, 0) || chmod("/run/mano-stop-agent", 0700)) return -1;
    char kill_path[544]; snprintf(kill_path, sizeof(kill_path), "%s/cgroup.kill", group);
    int fd = open(kill_path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    int ok = write(fd, "1", 1) == 1;
    close(fd); return ok ? 0 : -1;
}
int main(void) {
    if (geteuid() != 0) return 2;
    FILE *marker = fopen("/etc/mano-lab-disposable", "r"); char value[64];
    if (!marker || !fgets(value, sizeof(value), marker)) return 2;
    fclose(marker); value[strcspn(value, "\n")] = 0;
    if (strcmp(value, "mano-phase0-ci")) return 2;
    struct stat info;
    if (lstat(BASE "/cgroup-path", &info) || !S_ISREG(info.st_mode) || info.st_uid != 0 || (info.st_mode & 077)) return 2;
    FILE *config = fopen(BASE "/cgroup-path", "r");
    if (!config || !fgets(group, sizeof(group), config)) return 2;
    fclose(config); group[strcspn(group, "\n")] = 0;
    if (strncmp(group, "/sys/fs/cgroup/", 15) || strstr(group, "..") || !strstr(group, "mano-stop-tasks.slice")) return 2;
    int first = open(BASE "/ever-started", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (first < 0) { if (errno != EEXIST || stop_all()) return 2; }
    else close(first);
    struct passwd *human = getpwnam("mano-human");
    if (!human) return 2;
    int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX}; strcpy(address.sun_path, SOCKET);
    unlink(SOCKET); /* root-owned fixed fixture directory only, including restart. */
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
        chown(SOCKET, human->pw_uid, human->pw_gid) || chmod(SOCKET, 0600) || listen(listener, 8)) return 2;
    sd_notify(0, "READY=1");
    for (;;) {
        sd_notify(0, "WATCHDOG=1");
        struct pollfd pending = {.fd = listener, .events = POLLIN};
        int polled = poll(&pending, 1, 100);
        if (polled < 0 && errno != EINTR) return 2;
        if (polled <= 0) continue;
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) continue;
        struct timeval timeout = {.tv_sec = 0, .tv_usec = 200000};
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        struct ucred peer; socklen_t length = sizeof(peer); char command[16];
        ssize_t received = recv(client, command, sizeof(command), 0);
        int permitted = !getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &length) &&
            peer.uid == human->pw_uid && received == 4 && !memcmp(command, "STOP", 4);
        const char *reply = permitted ? (stop_all() ? "FAILED" : "STOPPED") : "DENIED";
        send(client, reply, strlen(reply), MSG_NOSIGNAL); close(client);
    }
}
