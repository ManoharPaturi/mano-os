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

/* Fixed leaf-only staged publication; no caller-supplied absolute path or flags. */
#include <string.h>
#include <linux/fs.h>

static int write_leaf(const char *name, int token) {
    if (!name || !*name || strlen(name)>255 || strchr(name,'/') ||
        !strcmp(name,".") || !strcmp(name,"..") || !strcmp(name,".mano-write-staging"))
        return 0;
    if (token) {
        if (strlen(name)!=32) return 0;
        for (size_t i=0;i<32;i++)
            if (!((name[i]>='0' && name[i]<='9') || (name[i]>='a' && name[i]<='f'))) return 0;
    }
    return 1;
}

static int private_stage(int fd) {
    struct stat info;
    return fstat(fd,&info)==0 && S_ISDIR(info.st_mode) && info.st_uid==geteuid() &&
           (info.st_mode&0777)==0700;
}

int mano_create_write_stage(int stage, const char *token) {
    if (!private_stage(stage) || !write_leaf(token,1)) {errno=EPERM;return -1;}
    /* Trusted single-threaded broker only. Restore before returning to Python;
       fixed0660 grants the task group read/write after atomic publication. No
       chmod/chown or privileged service-filter exception is introduced. */
    mode_t previous=umask(0007);
    int fd=openat(stage,token,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0660);
    int saved=errno;
    umask(previous);
    errno=saved;
    return fd;
}

int mano_publish_write(int stage, const char *token, int parent,
                       const char *leaf, int create_only) {
    struct stat directory,source;
    if (!private_stage(stage) || !write_leaf(token,1) || !write_leaf(leaf,0) ||
        (create_only!=0 && create_only!=1) || fstat(parent,&directory) ||
        !S_ISDIR(directory.st_mode) ||
        fstatat(stage,token,&source,AT_SYMLINK_NOFOLLOW) || !S_ISREG(source.st_mode) ||
        source.st_uid!=geteuid() || source.st_nlink!=1 || source.st_size<0 ||
        source.st_size>32768 || (source.st_mode&0777)!=0660 ||
        source.st_dev!=directory.st_dev) {errno=EPERM;return -1;}
    /* Destination symlinks/hardlinks are replaced as directory entries, never
       followed or written through. No unsafe check/rollback exchange sequence. */
    return (int)syscall(SYS_renameat2,stage,token,parent,leaf,
                        create_only ? RENAME_NOREPLACE : 0);
}
