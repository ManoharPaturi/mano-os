/* Fixed socket-activated PAM adapter; no command execution or caller-selected paths. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <systemd/sd-daemon.h>
#include <time.h>
#include <unistd.h>

#define HUMAN_SOCKET "/run/mano-approval/human.sock"
#define CONTROL_SOCKET "/run/mano-broker/control.sock"
#define MAX_REPLY 131072
#define CONFIRM_HEADER 164
static const char denied[] = "{\"schema_version\":\"1.0\",\"ok\":false,\"error\":\"denied\"}";

static bool hex(const char *s, size_t n) {
    for (size_t i=0;i<n;i++) if (!((s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f'))) return false;
    return true;
}
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
static int converse(int count,const struct pam_message **messages,struct pam_response **reply,void *data) {
    if (count<1 || count>PAM_MAX_NUM_MSG) return PAM_CONV_ERR;
    struct pam_response *answers=calloc((size_t)count,sizeof(*answers));if (!answers) return PAM_BUF_ERR;
    for (int i=0;i<count;i++) {
        if (messages[i]->msg_style==PAM_PROMPT_ECHO_OFF) answers[i].resp=strdup((const char *)data);
        else if (messages[i]->msg_style!=PAM_ERROR_MSG && messages[i]->msg_style!=PAM_TEXT_INFO) {
            for (int j=0;j<i;j++) {if (answers[j].resp) {explicit_bzero(answers[j].resp,strlen(answers[j].resp));free(answers[j].resp);}}
            free(answers);return PAM_CONV_ERR;
        }
        if (messages[i]->msg_style==PAM_PROMPT_ECHO_OFF && !answers[i].resp) {
            for (int j=0;j<i;j++) {if (answers[j].resp) {explicit_bzero(answers[j].resp,strlen(answers[j].resp));free(answers[j].resp);}}
            free(answers);return PAM_BUF_ERR;
        }
    }
    *reply=answers;return PAM_SUCCESS; /* PAM owns successful response buffers. */
}
static bool authenticate(uid_t human,char *password) {
    struct passwd *account=getpwuid(human);if (!account || !account->pw_name || strlen(account->pw_name)>255) return false;
    char username[256];strcpy(username,account->pw_name);
    struct pam_conv conversation={converse,password};pam_handle_t *handle=NULL;
    int result=pam_start("mano-approve",username,&conversation,&handle);
    if (result==PAM_SUCCESS) result=pam_authenticate(handle,PAM_DISALLOW_NULL_AUTHTOK);
    if (result==PAM_SUCCESS) result=pam_acct_mgmt(handle,0);
    const void *user=NULL;
    if (result==PAM_SUCCESS) {
        result=pam_get_item(handle,PAM_USER,&user);
        if (result==PAM_SUCCESS && (!user || strcmp(user,username))) result=PAM_AUTH_ERR;
    }
    if (handle) pam_end(handle,result);
    return result==PAM_SUCCESS;
}
static struct json_object *exchange(const char *path,const unsigned char *wire,size_t wire_size,uid_t sender_uid) {
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);if (fd<0) return NULL;
    int passcred=1;
    if (setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&passcred,sizeof(passcred))) {close(fd);return NULL;}
    struct timeval timeout={2,0};
    if (setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
        setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))) {close(fd);return NULL;}
    struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,path);
    struct ucred peer; socklen_t size=sizeof(peer);struct json_object *result=NULL;
    if (connect(fd,(struct sockaddr *)&address,sizeof(address)) ||
        getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size) || peer.uid!=0) {close(fd);return NULL;}
    if (send(fd,wire,wire_size,MSG_NOSIGNAL)!=(ssize_t)wire_size) goto done;
    char *reply=malloc(MAX_REPLY+1);if (!reply) goto done;
    union {struct cmsghdr aligned;unsigned char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(253*sizeof(int))];} ancillary;
    memset(&ancillary,0,sizeof(ancillary));
    struct iovec io={reply,MAX_REPLY};struct msghdr message={0};message.msg_iov=&io;message.msg_iovlen=1;
    message.msg_control=ancillary.bytes;message.msg_controllen=sizeof(ancillary.bytes);
    ssize_t n=recvmsg(fd,&message,MSG_CMSG_CLOEXEC);bool valid=n>0;unsigned count=0;
    for (struct cmsghdr *c=CMSG_FIRSTHDR(&message);c;c=CMSG_NXTHDR(&message,c)) {
        if (c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_CREDENTIALS && c->cmsg_len==CMSG_LEN(sizeof(struct ucred))) {
            struct ucred sender;memcpy(&sender,CMSG_DATA(c),sizeof(sender));count++;
            if (sender.uid!=sender_uid || (sender_uid==0 && sender.gid!=0) || sender.pid<=0) valid=false;
        } else {
            valid=false;
            if (c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS) {
                size_t bytes=c->cmsg_len-CMSG_LEN(0);int *received=(int *)CMSG_DATA(c);
                for (size_t i=0;i<bytes/sizeof(int);i++) close(received[i]);
            }
        }
    }
    if (valid && count==1 && !(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))) {
        reply[n]=0;struct json_tokener *parser=json_tokener_new_ex(32);
        if (parser) {
            json_tokener_set_flags(parser,JSON_TOKENER_STRICT|JSON_TOKENER_VALIDATE_UTF8);
            result=json_tokener_parse_ex(parser,reply,(int)n);
            if (json_tokener_get_error(parser)!=json_tokener_success || json_tokener_get_parse_end(parser)!=(size_t)n) {
                if (result) {json_object_put(result);}
                result=NULL;
            }
            json_tokener_free(parser);
        }
    }
    free(reply);
done:close(fd);return result;
}
static struct json_object *control(const char *operation,const char *id,uid_t human,const char *nonce,const char *digest) {
    struct passwd *broker=getpwnam("mano-broker");if (!broker || !broker->pw_uid) return NULL;
    uid_t broker_uid=broker->pw_uid;
    struct json_object *request=json_object_new_object(),*body=json_object_new_object();
    json_object_object_add(request,"schema_version",json_object_new_string("1.0"));
    json_object_object_add(request,"operation",json_object_new_string(operation));
    json_object_object_add(body,"approval_id",json_object_new_string(id));
    json_object_object_add(body,"human_uid",json_object_new_int64(human));
    if (nonce) json_object_object_add(body,"nonce",json_object_new_string(nonce));
    if (digest) json_object_object_add(body,"operation_digest",json_object_new_string(digest));
    json_object_object_add(request,"body",body);
    const char *wire=json_object_to_json_string_ext(request,JSON_C_TO_STRING_PLAIN);size_t wire_size=strlen(wire);
    struct json_object *result=exchange(CONTROL_SOCKET,(const unsigned char *)wire,wire_size,broker_uid);
    json_object_put(request);return result;
}
static bool field_hex(struct json_object *view,const char *name,const char *expected,size_t length) {
    struct json_object *field=NULL;
    if (!json_object_object_get_ex(view,name,&field) || !json_object_is_type(field,json_type_string) ||
        json_object_get_string_len(field)!=(int)length) return false;
    const char *value=json_object_get_string(field);return hex(value,length) && !memcmp(value,expected,length);
}
static struct json_object *prompt_control(uid_t human,const char *id,const char *prompt,size_t length) {
    struct passwd *broker=getpwnam("mano-broker");if (!broker || !broker->pw_uid) return NULL;
    uid_t broker_uid=broker->pw_uid;
    struct json_object *request=json_object_new_object(),*body=json_object_new_object();
    json_object_object_add(request,"schema_version",json_object_new_string("1.0"));
    json_object_object_add(request,"operation",json_object_new_string(prompt?"submit_prompt":"prompt_status"));
    json_object_object_add(body,"human_uid",json_object_new_int64(human));
    json_object_object_add(body,prompt?"request_key":"prompt_id",json_object_new_string(id));
    if (prompt) json_object_object_add(body,"prompt",json_object_new_string_len(prompt,(int)length));
    json_object_object_add(request,"body",body);
    const char *wire=json_object_to_json_string_ext(request,JSON_C_TO_STRING_PLAIN);
    struct json_object *result=exchange(CONTROL_SOCKET,(const unsigned char *)wire,strlen(wire),broker_uid);
    json_object_put(request);return result;
}
static void handle(int fd,uid_t human) {
    unsigned char packet[8229]={0};ssize_t size=0;struct json_object *reply=NULL;
    struct timeval timeout={2,0};
    if (setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
        setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))) goto done;
    if (!credentials(fd,packet,sizeof(packet)-1,&size,human) || size<2 || packet[0]!=1) goto done;
    if (packet[1]==3 && size==2) {
        const unsigned char query='V';
        reply=exchange("/run/mano-stopd/control.sock",&query,1,0);
        if (reply) goto send_reply;
        goto failed;
    }
    if (packet[1]==4) {
        if (size<77 || !hex((char *)packet+10,64)) goto failed;
        unsigned length=((unsigned)packet[74]<<8)|packet[75];
        if (!length || length>256 || size!=76+(ssize_t)length || memchr(packet+76,0,length)) goto failed;
        if (!authenticate(human,(char *)packet+76)) goto failed;
        unsigned char command[41]={0};command[0]='R';memcpy(command+1,packet+2,8);
        for (unsigned i=0;i<32;i++) {
            unsigned char high=packet[10+2*i],low=packet[11+2*i];
            command[9+i]=(unsigned char)(((high<='9'?high-'0':high-'a'+10)<<4)|
                                       (low<='9'?low-'0':low-'a'+10));
        }
        reply=exchange("/run/mano-stopd/control.sock",command,sizeof(command),0);
        explicit_bzero(command,sizeof(command));
        if (reply) goto send_reply;
        goto failed;
    }
    if (size<34 || !hex((char *)packet+2,32)) goto done;
    char id[33]={0};memcpy(id,packet+2,32);
    if (packet[1]==5 || packet[1]==6) {
        if (packet[1]==6 && size==34) reply=prompt_control(human,id,NULL,0);
        else if (packet[1]==5 && size>=37) {
            unsigned length=((unsigned)packet[34]<<8)|packet[35];
            if (!length || length>8192 || size!=36+(ssize_t)length || memchr(packet+36,0,length)) goto failed;
            reply=prompt_control(human,id,(char *)packet+36,length);
        }
        if (reply) goto send_reply;
        goto failed;
    }
    reply=control("approval_view",id,human,NULL,NULL);
    struct json_object *ok=NULL,*view=NULL;
    if (!reply || !json_object_object_get_ex(reply,"ok",&ok) || !json_object_is_type(ok,json_type_boolean) ||
        !json_object_get_boolean(ok) || !json_object_object_get_ex(reply,"view",&view) || !json_object_is_type(view,json_type_object)) goto failed;
    if (packet[1]==1 && size==34) goto send_reply;
    if (packet[1]!=2 || size<CONFIRM_HEADER+1 || !hex((char *)packet+34,64) || !hex((char *)packet+98,64)) goto failed;
    unsigned length=((unsigned)packet[162]<<8)|packet[163];
    if (!length || length>256 || size!=CONFIRM_HEADER+(ssize_t)length || memchr(packet+CONFIRM_HEADER,0,length) ||
        !field_hex(view,"nonce",(char *)packet+34,64) || !field_hex(view,"operation_digest",(char *)packet+98,64)) goto failed;
    if (!authenticate(human,(char *)packet+CONFIRM_HEADER)) goto failed;
    char nonce[65]={0},digest[65]={0};memcpy(nonce,packet+34,64);memcpy(digest,packet+98,64);
    json_object_put(reply);reply=control("confirm_approval",id,human,nonce,digest);
    explicit_bzero(packet,sizeof(packet));
    if (!reply) goto failed;
send_reply: {
        const char *wire=json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN);
        size_t n=strlen(wire);if (n<=MAX_REPLY) send(fd,wire,n,MSG_NOSIGNAL);
        goto done;
    }
failed:if (reply) {json_object_put(reply);reply=NULL;}
done:explicit_bzero(packet,sizeof(packet));if (reply) json_object_put(reply);else send(fd,denied,sizeof(denied)-1,MSG_NOSIGNAL);
}
int main(int argc,char **argv) {
    (void)argv;char pid[32];snprintf(pid,sizeof(pid),"%ld",(long)getpid());
    const char *listen_pid=getenv("LISTEN_PID"),*fds=getenv("LISTEN_FDS"),*names=getenv("LISTEN_FDNAMES");
    if (argc!=1 || geteuid()!=0 || !listen_pid || strcmp(listen_pid,pid) || !fds || strcmp(fds,"1") ||
        !names || strcmp(names,"human") || !expected_fd(3,HUMAN_SOCKET)) return 2;
    uid_t human=human_policy();if (human==(uid_t)-1) return 2;
    if (fcntl(3,F_SETFD,FD_CLOEXEC)) return 2;
    unsetenv("LISTEN_PID");unsetenv("LISTEN_FDS");unsetenv("LISTEN_FDNAMES");
    sd_notify(0,"READY=1");struct pollfd listener={3,POLLIN,0};
    for (;;) {
        sd_notify(0,"WATCHDOG=1");int ready=poll(&listener,1,500);
        if (ready<0) {if (errno==EINTR) continue;return 1;}
        if (ready==0) continue;
        int fd=accept4(3,NULL,NULL,SOCK_CLOEXEC);if (fd<0) continue;
        handle(fd,human);close(fd);
        struct timespec delay={0,200000000};nanosleep(&delay,NULL);
    }
}
