#include "kreamlink.h"

#include <string.h>

/* The v1 control vocabulary uses flat objects, plain string identifiers,
 * booleans and integer timestamps/codes. Pointers refer to the input buffer. */
static char *skip_space(char *p) {
    return p + strspn(p, " \t\r\n");
}

static char *read_string(char **cursor) {
    char *p = *cursor;
    if (*p != '"') return NULL;
    char *start = ++p;
    while (*p != '"') {
        if ((unsigned char)*p < 0x20 || *p == '\\') return NULL;
        p++;
    }
    *p = '\0';
    *cursor = p + 1;
    return start;
}

static bool set_string(const char **field, const char *value) {
    if (*field || !value) return false;
    *field = value;
    return true;
}

bool kl_control_parse(char *buf, size_t len, kl_control_t *msg) {
    *msg = (kl_control_t){.online = -1, .peer_online = -1, .authenticated = -1};
    if (memchr(buf, '\0', len)) return false;
    buf[len] = '\0';
    char *p = skip_space(buf);
    if (*p++ != '{') return false;
    p = skip_space(p);
    if (*p == '}') return *skip_space(p + 1) == '\0';

    for (;;) {
        char *key = read_string(&p);
        if (!key) return false;
        p = skip_space(p);
        if (*p++ != ':') return false;
        p = skip_space(p);

        char *str = NULL;
        int boolean = -1;
        if (*p == '"') {
            str = read_string(&p);
            if (!str) return false;
        } else if (!strncmp(p, "true", 4)) {
            boolean = 1;
            p += 4;
        } else if (!strncmp(p, "false", 5)) {
            boolean = 0;
            p += 5;
        } else {
            if (*p == '-') p++;
            if (*p < '0' || *p > '9') return false;
            p += *p == '0' ? 1 : strspn(p, "0123456789");
        }

        if (!strcmp(key, "online") || !strcmp(key, "peer_online")) {
            int *field = !strcmp(key, "online") ? &msg->online : &msg->peer_online;
            if (*field != -1 || boolean == -1) return false;
            *field = boolean;
        } else if (!strcmp(key, "authenticated")) {
            if (msg->authenticated != -1 || boolean == -1) return false;
            msg->authenticated = boolean;
        } else if (!strcmp(key, "status")) {
            if (!set_string(&msg->status, str)) return false;
        } else if (!strcmp(key, "type")) {
            if (!set_string(&msg->type, str)) return false;
        } else if (!strcmp(key, "action")) {
            if (!set_string(&msg->action, str)) return false;
        } else if (!strcmp(key, "role")) {
            if (!set_string(&msg->role, str)) return false;
        } else if (!strcmp(key, "hub_auth")) {
            if (!set_string(&msg->hub_auth, str)) return false;
        } else if (!strcmp(key, "channel")) {
            if (!set_string(&msg->channel, str)) return false;
        }

        p = skip_space(p);
        if (*p == '}') return *skip_space(p + 1) == '\0';
        if (*p++ != ',') return false;
        p = skip_space(p);
    }
}
