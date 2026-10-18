/* Fixed unprivileged human Stop client; independent of Python and GTK. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/run/mano-stopd/human.sock"

static bool stop(void) {
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    if (fd<0) return false;
    bool okay=false;int enabled=1;
    struct timeval timeout={2,0};
    struct sockaddr_un address={.sun_family=AF_UNIX};
    memcpy(address.sun_path,SOCKET_PATH,sizeof(SOCKET_PATH));
    if (setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled)) ||
        setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
        setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)) ||
        connect(fd,(struct sockaddr *)&address,sizeof(address))) goto done;
    struct ucred peer={0};socklen_t length=sizeof(peer);
    if (getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length) || length!=sizeof(peer) ||
        peer.pid<=0 || peer.uid!=0 || peer.gid!=0) goto done;
    if (send(fd,"S",1,MSG_NOSIGNAL)!=1) goto done;
    unsigned char packet[8]={0};
    union {struct cmsghdr aligned;unsigned char bytes[
        CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(253*sizeof(int))];} ancillary;
    memset(&ancillary,0,sizeof(ancillary));
    struct iovec io={packet,sizeof(packet)};
    struct msghdr message={0};message.msg_iov=&io;message.msg_iovlen=1;
    message.msg_control=ancillary.bytes;message.msg_controllen=sizeof(ancillary.bytes);
    ssize_t size=recvmsg(fd,&message,MSG_CMSG_CLOEXEC);
    okay=size==7 && !memcmp(packet,"stopped",7) &&
        !(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC));
    unsigned count=0;
    for (struct cmsghdr *c=CMSG_FIRSTHDR(&message);c;c=CMSG_NXTHDR(&message,c)) {
        if (c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS) {
            size_t bytes=c->cmsg_len-CMSG_LEN(0);int *fds=(int *)CMSG_DATA(c);
            for (size_t i=0;i<bytes/sizeof(int);i++) close(fds[i]);
            okay=false;
        } else if (c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_CREDENTIALS &&
                   c->cmsg_len==CMSG_LEN(sizeof(struct ucred))) {
            struct ucred sender;memcpy(&sender,CMSG_DATA(c),sizeof(sender));count++;
            /* systemd owns the listener; the Root daemon sends the reply. */
            if (sender.pid<=0 || sender.uid!=0 || sender.gid!=0) okay=false;
        } else okay=false;
    }
    okay=okay && count==1;
done:
    close(fd);return okay;
}

int main(int argc,char **argv) {
    (void)argv;
    if (argc!=1) {fputs("Usage: mano-stop\n",stderr);return 2;}
    if (!stop()) {
        fputs("Stop not acknowledged. Use the trusted recovery terminal.\n",stderr);
        return 1;
    }
    puts("Emergency Stop acknowledged: new work blocked; task termination requested.");
    return 0;
}
