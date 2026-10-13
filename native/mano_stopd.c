/* Native fixed emergency Stop, independent of Python services. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <poll.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

#define HUMAN_SOCKET "/run/mano-stopd/human.sock"
#define STATE_DIR "/var/lib/mano-stopd"
#define GROUP "/sys/fs/cgroup/system.slice/mano-launcher.service"
static bool expected_fd(int fd, const char *path) {
    struct sockaddr_un address={0};socklen_t size=sizeof(address);int type=0,accepting=0,cred=0;
    socklen_t length=sizeof(int);
    if (getsockname(fd,(struct sockaddr *)&address,&size) || address.sun_family!=AF_UNIX ||
        strnlen(address.sun_path,sizeof(address.sun_path))>=sizeof(address.sun_path) ||
        strcmp(address.sun_path,path)) return false;
    if (getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&length) || type!=SOCK_SEQPACKET ||
        getsockopt(fd,SOL_SOCKET,SO_ACCEPTCONN,&accepting,&length) || !accepting ||
        getsockopt(fd,SOL_SOCKET,SO_PASSCRED,&cred,&length) || !cred) return false;
    return true;
}
static uid_t human_policy(void) {
    int dir=open("/etc/mano",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat st;char data[32]={0};uid_t invalid=(uid_t)-1;
    if (dir<0) return invalid;
    if (fstat(dir,&st) || st.st_uid!=0 || (st.st_mode&022)) {close(dir);return invalid;}
    int fd=openat(dir,"human.uid",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);close(dir);
    if (fd<0) return invalid;
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=0 ||
        (st.st_mode&0777)!=0600 || st.st_nlink!=1 || st.st_size<1 || st.st_size>30) {
        close(fd);return invalid;
    }
    ssize_t n=read(fd,data,sizeof(data)-1);close(fd);
    if (n!=st.st_size || !data[0] || strspn(data,"0123456789") == 0) return invalid;
    errno=0;char *end=NULL;unsigned long uid=strtoul(data,&end,10);
    if (errno || uid<1000 || uid>INT_MAX || (*end && strcmp(end,"\n"))) return invalid;
    struct passwd *account=getpwuid((uid_t)uid);
    if (!account || !account->pw_name ||
        !strcmp(account->pw_name,"mano-core") || !strcmp(account->pw_name,"mano-agent") ||
        !strcmp(account->pw_name,"mano-worker") || !strcmp(account->pw_name,"mano-broker")) return invalid;
    return (uid_t)uid;
}
static bool credentials(int fd, unsigned char *packet, size_t capacity, ssize_t *size, uid_t human) {
    struct ucred peer={0};socklen_t length=sizeof(peer);
    if (getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length) || length!=sizeof(peer) || peer.uid!=human) return false;
    union {struct cmsghdr aligned;unsigned char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(253*sizeof(int))];} ancillary;
    memset(&ancillary,0,sizeof(ancillary));struct iovec io={packet,capacity};
    struct msghdr message={0};message.msg_iov=&io;message.msg_iovlen=1;
    message.msg_control=ancillary.bytes;message.msg_controllen=sizeof(ancillary.bytes);
    *size=recvmsg(fd,&message,MSG_CMSG_CLOEXEC);bool okay=*size>0;unsigned count=0;
    for (struct cmsghdr *c=CMSG_FIRSTHDR(&message);c;c=CMSG_NXTHDR(&message,c)) {
        if (c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS) {
            size_t bytes=c->cmsg_len-CMSG_LEN(0);int *fds=(int *)CMSG_DATA(c);
            for (size_t i=0;i<bytes/sizeof(int);i++) {close(fds[i]);}
            okay=false;
        } else if (c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_CREDENTIALS &&
                   c->cmsg_len==CMSG_LEN(sizeof(struct ucred))) {
            struct ucred sender;memcpy(&sender,CMSG_DATA(c),sizeof(sender));count++;
            if (sender.pid!=peer.pid || sender.uid!=peer.uid || sender.gid!=peer.gid) okay=false;
        } else okay=false;
    }
    return okay && count==1 && !(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC));
}

static int state_directory(void) {
    int fd=open(STATE_DIR,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat st;
    if (fd<0) return -1;
    if (fstat(fd,&st) || st.st_uid!=0 || (st.st_mode&0777)!=0755) {
        close(fd);return -1;
    }
    return fd;
}
static bool state_file(int fd) {
    struct stat st;
    return !fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_uid==0 &&
        (st.st_mode&0777)==0644 && st.st_nlink==1;
}
static bool read_state(int directory,const char *name,unsigned long long *generation,bool *stopped,
                       bool *legacy) {
    int fd=openat(directory,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return false;
    char data[65]={0};ssize_t n=read(fd,data,sizeof(data)-1);
    bool valid=state_file(fd);close(fd);
    if (!valid || n<=0 || n>=64) return false;
    *legacy=false;
    if (n==6 && !memcmp(data,"armed\n",6)) {*generation=0;*stopped=false;*legacy=true;return true;}
    if (n==8 && !memcmp(data,"latched\n",8)) {*generation=1;*stopped=true;*legacy=true;return true;}
    if (memcmp(data,"v1:",3) || data[3]<'0' || data[3]>'9') return false;
    errno=0;char *end=NULL;unsigned long long value=strtoull(data+3,&end,10);
    if (errno || value>(unsigned long long)LLONG_MAX || (data[3]=='0' && end!=data+4)) return false;
    if (!strcmp(end,":armed\n")) *stopped=false;
    else if (!strcmp(end,":latched\n")) *stopped=true;
    else return false;
    *generation=value;return true;
}
static bool publish(int directory,unsigned long long generation,bool stopped,bool recovering) {
    int flags=O_WRONLY|O_NOFOLLOW|O_CLOEXEC;
    flags|=recovering?0:(O_CREAT|O_EXCL);
    int fd=openat(directory,"state.pending",flags,0644);
    if (fd<0) return false;
    char data[64];int n=snprintf(data,sizeof(data),"v1:%llu:%s\n",generation,
                               stopped?"latched":"armed");
    bool okay=state_file(fd) && n>0 && (size_t)n<sizeof(data) && ftruncate(fd,0)==0 &&
        write(fd,data,(size_t)n)==n && fsync(fd)==0 && fsync(directory)==0;
    close(fd);
    if (!okay || renameat(directory,"state.pending",directory,"state")) return false;
    return fsync(directory)==0;
}
static bool initialize(int directory) {
    unsigned long long generation=0;bool stopped=false,legacy=false;
    struct stat info;
    if (fstatat(directory,"state",&info,AT_SYMLINK_NOFOLLOW)==0) {
        if (!read_state(directory,"state",&generation,&stopped,&legacy)) return false;
    } else if (errno!=ENOENT) return false;
    if (fstatat(directory,"state.pending",&info,AT_SYMLINK_NOFOLLOW)==0) {
        int fd=openat(directory,"state.pending",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if (fd<0) return false;
        bool trusted=state_file(fd);close(fd);if (!trusted) return false;
        unsigned long long pending=0;bool pending_stop=false,pending_legacy=false;
        if (read_state(directory,"state.pending",&pending,&pending_stop,&pending_legacy) &&
            pending>generation) generation=pending;
        if (generation==(unsigned long long)LLONG_MAX) return false;
        /* An interrupted armed or latched write always recovers to a NEW Stop. */
        return publish(directory,generation+1,true,true);
    }
    if (errno!=ENOENT) return false;
    if (legacy) return publish(directory,generation,stopped,false);
    if (fstatat(directory,"state",&info,AT_SYMLINK_NOFOLLOW)<0)
        return errno==ENOENT && publish(directory,0,false,false);
    return true;
}
static bool latch(int directory) {
    unsigned long long generation=0;bool stopped=false,legacy=false;
    if (!read_state(directory,"state",&generation,&stopped,&legacy) ||
        generation==(unsigned long long)LLONG_MAX) return false;
    return publish(directory,generation+1,true,false);
}
static bool task_name(const char *name) {
    if (strlen(name)!=37 || strncmp(name,"task-",5)) return false;
    for (size_t i=5;i<37;i++) if (!((name[i]>='0' && name[i]<='9') ||
                                  (name[i]>='a' && name[i]<='f'))) return false;
    return true;
}
static bool kill_tasks(void) {
    int fd=open(GROUP,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return errno==ENOENT;
    struct stat st;struct statfs filesystem;
    if (fstat(fd,&st) || st.st_uid!=0 || (st.st_mode&022) ||
        fstatfs(fd,&filesystem) || filesystem.f_type!=CGROUP2_SUPER_MAGIC) {
        close(fd);return false;
    }
    DIR *directory=fdopendir(fd);if (!directory) {close(fd);return false;}
    bool okay=true;unsigned count=0;struct dirent *entry;
    for (;;) {
        errno=0;entry=readdir(directory);
        if (!entry) {if (errno) okay=false;break;}
        if (!task_name(entry->d_name)) continue;
        if (++count>64) {okay=false;break;}
        int child=openat(fd,entry->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (child<0) {if (errno!=ENOENT) okay=false;continue;}
        if (fstat(child,&st) || st.st_uid!=0 || (st.st_mode&022)) {
            close(child);okay=false;continue;
        }
        int control=openat(child,"cgroup.kill",O_WRONLY|O_NOFOLLOW|O_CLOEXEC);
        if (control<0) {if (errno!=ENOENT) okay=false;}
        else {if (write(control,"1",1)!=1) okay=false;close(control);}
        close(child);
    }
    closedir(directory);return okay;
}
int main(int argc,char **argv) {
    (void)argv;
    if (argc!=1 || geteuid()!=0 || sd_listen_fds(1)!=1 ||
        !expected_fd(3,HUMAN_SOCKET)) return 2;
    uid_t human=human_policy();if (human==(uid_t)-1) return 2;
    int directory=state_directory();if (directory<0 || !initialize(directory)) return 2;
    sd_notify(0,"READY=1");struct pollfd listener={3,POLLIN,0};
    for (;;) {
        sd_notify(0,"WATCHDOG=1");int ready=poll(&listener,1,500);
        if (ready<0) {if (errno==EINTR) continue;return 3;}
        if (!ready) continue;
        int fd=accept4(3,NULL,NULL,SOCK_CLOEXEC);if (fd<0) continue;
        struct timeval timeout={1,0};
        setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
        setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
        unsigned char packet[2]={0};ssize_t size=0;
        bool valid=credentials(fd,packet,sizeof(packet),&size,human) &&
            size==1 && packet[0]=='S';
        bool durable=true,killed=false;
        if (valid) {durable=latch(directory);killed=kill_tasks();}
        bool okay=valid && durable && killed;
        const char *response=okay?"stopped":"denied";
        (void)send(fd,response,strlen(response),MSG_NOSIGNAL);close(fd);
        if (valid && !durable) return 4; /* Restart into fail-closed pending recovery. */
    }
}
