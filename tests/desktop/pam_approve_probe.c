/* Fixed CI helper: OS-authenticate mano-human; no privilege/effectful operation. */
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char password[257];
static int converse(int count, const struct pam_message **messages,
                    struct pam_response **reply, void *data) {
    (void)data;
    if (count < 1 || count > PAM_MAX_NUM_MSG) return PAM_CONV_ERR;
    struct pam_response *responses = calloc((size_t)count, sizeof(*responses));
    if (!responses) return PAM_BUF_ERR;
    for (int i = 0; i < count; i++) {
        switch (messages[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF: responses[i].resp = strdup(password); break;
        case PAM_PROMPT_ECHO_ON: responses[i].resp = strdup("mano-human"); break;
        case PAM_ERROR_MSG: case PAM_TEXT_INFO: break;
        default:
            for (int j = 0; j < i; j++) free(responses[j].resp);
            free(responses); return PAM_CONV_ERR;
        }
    }
    *reply = responses; return PAM_SUCCESS;
}
int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || geteuid() != 0) return 2;
    FILE *marker = fopen("/etc/mano-lab-disposable", "r");
    char value[64];
    if (!marker || !fgets(value, sizeof(value), marker)) return 2;
    fclose(marker);
    value[strcspn(value, "\n")] = 0;
    if (strcmp(value, "mano-phase0-ci")) return 2;
    if (!fgets(password, sizeof(password), stdin)) return 1;
    password[strcspn(password, "\n")] = 0;
    if (!password[0] || strlen(password) > 256) return 1;
    struct pam_conv conversation = {converse, NULL};
    pam_handle_t *handle = NULL;
    int result = pam_start("mano-lab-approve", "mano-human", &conversation, &handle);
    if (result == PAM_SUCCESS) result = pam_authenticate(handle, PAM_DISALLOW_NULL_AUTHTOK);
    if (result == PAM_SUCCESS) result = pam_acct_mgmt(handle, 0);
    const void *user = NULL;
    if (result == PAM_SUCCESS) {
        result = pam_get_item(handle, PAM_USER, &user);
        if (result == PAM_SUCCESS && (!user || strcmp(user, "mano-human"))) result = PAM_AUTH_ERR;
    }
    if (handle) pam_end(handle, result);
    explicit_bzero(password, sizeof(password));
    return result == PAM_SUCCESS ? 0 : 1;
}
