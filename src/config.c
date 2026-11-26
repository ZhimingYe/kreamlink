#include "kreamlink.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void kl_config_init(kl_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = KL_MODE_NONE;
    cfg->log_level = KL_LOG_INFO;
    snprintf(cfg->ws_path, sizeof(cfg->ws_path), "/api/v1/stream");
    snprintf(cfg->user_agent, sizeof(cfg->user_agent),
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");
    cfg->heartbeat_sec = 15;
    cfg->wait_peer_ms = 5000;
    cfg->padding_max = 192;
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) {
        s[--n] = '\0';
    }
    return s;
}

/* Strip inline # comments outside quotes */
static void strip_comment(char *s) {
    bool in_single = false;
    bool in_double = false;
    for (char *p = s; *p; p++) {
        if (*p == '\'' && !in_double) {
            in_single = !in_single;
        } else if (*p == '"' && !in_single) {
            in_double = !in_double;
        } else if (*p == '#' && !in_single && !in_double &&
                   (p == s || isspace((unsigned char)p[-1]))) {
            *p = '\0';
            break;
        }
    }
}

static char *unquote(char *s) {
    s = trim(s);
    size_t n = strlen(s);
    if (n >= 2 && ((s[0] == '"' && s[n - 1] == '"') ||
                   (s[0] == '\'' && s[n - 1] == '\''))) {
        s[n - 1] = '\0';
        return s + 1;
    }
    if (*s == '\'' || *s == '"') return NULL;
    return s;
}

int kl_parse_int(const char *value, int min, int max, int *out) {
    if (!*value || strspn(value, "0123456789") != strlen(value)) return -1;
    errno = 0;
    long n = strtol(value, NULL, 10);
    if (errno == ERANGE || n < min || n > max) return -1;
    *out = (int)n;
    return 0;
}

static bool setting_fits(const char *value, size_t cap) {
    for (size_t i = 0; i < cap; i++) {
        unsigned char c = (unsigned char)value[i];
        if (c == 0) return true;
        if (c < 32 || c == 127) return false;
    }
    return false;
}

int kl_copy_setting(char *dest, size_t cap, const char *value) {
    if (!setting_fits(value, cap)) return -1;
    size_t n = strlen(value);
    memcpy(dest, value, n + 1);
    return 0;
}

static int set_scalar(kl_config_t *cfg, const char *key, const char *val) {
    struct { const char *key; char *dest; size_t cap; } strings[] = {
        {"listen", cfg->listen_addr, sizeof(cfg->listen_addr)},
        {"ws_path", cfg->ws_path, sizeof(cfg->ws_path)},
        {"hub", cfg->hub_url, sizeof(cfg->hub_url)},
        {"channel", cfg->channel, sizeof(cfg->channel)},
        {"target", cfg->target_addr, sizeof(cfg->target_addr)},
        {"user_agent", cfg->user_agent, sizeof(cfg->user_agent)},
        {"cookie", cfg->cookie, sizeof(cfg->cookie)},
        {"subprotocol", cfg->subprotocol, sizeof(cfg->subprotocol)},
        {"tls_cert", cfg->tls_cert, sizeof(cfg->tls_cert)},
        {"tls_key", cfg->tls_key, sizeof(cfg->tls_key)},
    };
    for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); i++) {
        if (strcmp(key, strings[i].key) == 0)
            return kl_copy_setting(strings[i].dest, strings[i].cap, val);
    }
    if (strcmp(key, "mode") == 0) {
        if (strcmp(val, "hub") == 0) cfg->mode = KL_MODE_HUB;
        else if (strcmp(val, "recv") == 0 || strcmp(val, "receiver") == 0) cfg->mode = KL_MODE_RECV;
        else if (strcmp(val, "send") == 0 || strcmp(val, "sender") == 0) cfg->mode = KL_MODE_SEND;
        else return -1;
    } else if (strcmp(key, "insecure") == 0) {
        if (!strcmp(val, "true") || !strcmp(val, "1") || !strcmp(val, "yes") || !strcmp(val, "on"))
            cfg->insecure_tls = true;
        else if (!strcmp(val, "false") || !strcmp(val, "0") || !strcmp(val, "no") || !strcmp(val, "off"))
            cfg->insecure_tls = false;
        else return -1;
    } else if (!strcmp(key, "heartbeat") || !strcmp(key, "heartbeat_sec")) {
        return kl_parse_int(val, 1, INT_MAX, &cfg->heartbeat_sec);
    } else if (!strcmp(key, "wait_peer_ms")) {
        return kl_parse_int(val, 0, INT_MAX, &cfg->wait_peer_ms);
    } else if (!strcmp(key, "padding_max")) {
        return kl_parse_int(val, 0, KL_MAX_PADDING, &cfg->padding_max);
    } else if (!strcmp(key, "log_level")) {
        if (!strcmp(val, "debug")) cfg->log_level = KL_LOG_DEBUG;
        else if (!strcmp(val, "info")) cfg->log_level = KL_LOG_INFO;
        else if (!strcmp(val, "warn")) cfg->log_level = KL_LOG_WARN;
        else if (!strcmp(val, "error")) cfg->log_level = KL_LOG_ERROR;
        else return -1;
    } else {
        return -1;
    }
    return 0;
}

int kl_config_load_yaml(kl_config_t *cfg, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        KL_ERROR("Failed to open config file: %s", path);
        return -1;
    }
    kl_config_t parsed = *cfg;
    char line[1024];
    bool in_list = false, need_item = false;
    unsigned long lineno = 0;
    for (;;) {
        size_t len = 0;
        int c;
        lineno++;
        while ((c = fgetc(fp)) != EOF && c != '\n') {
            if (c == 0 || len == sizeof(line) - 1) goto invalid;
            line[len++] = (char)c;
        }
        if (ferror(fp)) goto invalid;
        if (c == EOF && len == 0) break;
        line[len] = '\0';
        strip_comment(line);
        char *s = trim(line);
        if (!*s) continue;
        if (s[0] == '-' && isspace((unsigned char)s[1])) {
            char *item = unquote(s + 1);
            if (!in_list || !item || !*item || parsed.allowed_token_count >= KL_MAX_ALLOWED_TOKENS)
                goto invalid;
            char *id = parsed.allowed_channel_ids[parsed.allowed_token_count];
            if (strlen(item) == KL_CHAN_HASH_HEX_LEN && strspn(item, "0123456789abcdef") == KL_CHAN_HASH_HEX_LEN) {
                memcpy(id, item, KL_CHAN_HASH_HEX_LEN + 1);
            } else {
                if (!setting_fits(item, sizeof(parsed.channel)) ||
                    kl_channel_hash_hex(item, id) != 0) goto invalid;
            }
            parsed.allowed_token_count++;
            need_item = false;
            continue;
        }
        if (need_item) goto invalid;
        char *colon = strchr(s, ':');
        if (!colon) goto invalid;
        *colon = '\0';
        char *key = trim(s);
        in_list = !strcmp(key, "allowed_tokens");
        if (in_list) {
            if (*trim(colon + 1)) goto invalid;
            need_item = true;
        } else {
            char *val = unquote(colon + 1);
            if (!val || set_scalar(&parsed, key, val) != 0) goto invalid;
        }
    }
    if (need_item) goto invalid;
    fclose(fp);
    *cfg = parsed;
    return 0;
invalid:
    KL_ERROR("Invalid or unreadable configuration at %s line %lu", path, lineno);
    fclose(fp);
    return -1;
}

int kl_parse_hostport(const char *addr, char *host, size_t host_sz, uint16_t *port) {
    if (!addr || !*addr) return -1;

    const char *colon = NULL;
    if (addr[0] == '[') {
        /* IPv6 literal [::1]:8080 */
        const char *rb = strchr(addr, ']');
        if (!rb || rb[1] != ':') return -1;
        size_t hlen = (size_t)(rb - (addr + 1));
        if (hlen == 0 || hlen >= host_sz) return -1;
        memcpy(host, addr + 1, hlen);
        host[hlen] = '\0';
        colon = rb + 1;
    } else {
        colon = strrchr(addr, ':');
        if (!colon || strchr(addr, ':') != colon) return -1;
        size_t hlen = (size_t)(colon - addr);
        if (hlen == 0) {
            if (kl_copy_setting(host, host_sz, "0.0.0.0") != 0) return -1;
        } else {
            if (hlen >= host_sz) return -1;
            memcpy(host, addr, hlen);
            host[hlen] = '\0';
        }
    }

    int p;
    if (kl_parse_int(colon + 1, 1, 65535, &p) != 0) return -1;
    *port = (uint16_t)p;
    return 0;
}

int kl_parse_url(const char *url, kl_url_t *out) {
    if (!url || strpbrk(url, " \t\r\n#")) return -1;
    memset(out, 0, sizeof(*out));
    const char *p = NULL;
    if (strncmp(url, "wss://", 6) == 0) {
        out->use_tls = true;
        out->port = 443;
        p = url + 6;
    } else if (strncmp(url, "ws://", 5) == 0) {
        out->use_tls = false;
        out->port = 80;
        p = url + 5;
    } else {
        return -1;
    }

    const char *slash = strpbrk(p, "/?");
    size_t hostport_len = slash ? (size_t)(slash - p) : strlen(p);
    if (hostport_len == 0 || hostport_len >= sizeof(out->host)) return -1;

    char hostport[256];
    memcpy(hostport, p, hostport_len);
    hostport[hostport_len] = '\0';

    if (strchr(hostport, '@')) return -1;
    out->path[0] = '/';
    if (slash && *slash == '?') {
        if (kl_copy_setting(out->path + 1, sizeof(out->path) - 1, slash) != 0) return -1;
    } else if (slash && kl_copy_setting(out->path, sizeof(out->path), slash) != 0) {
        return -1;
    }

    /* Check if hostport has explicit port */
    if (hostport[0] == '[') {
        char *rb = strchr(hostport, ']');
        if (!rb || (rb[1] && rb[1] != ':')) return -1;
        *rb = '\0';
        snprintf(out->host, sizeof(out->host), "%s", hostport + 1);
        if (rb[1] == ':') {
            int port;
            if (kl_parse_int(rb + 2, 1, 65535, &port) != 0) return -1;
            out->port = (uint16_t)port;
        }
    } else {
        char *colon = strrchr(hostport, ':');
        if (colon) {
            *colon = '\0';
            int port;
            if (strchr(hostport, ':') || kl_parse_int(colon + 1, 1, 65535, &port) != 0) return -1;
            out->port = (uint16_t)port;
        }
        snprintf(out->host, sizeof(out->host), "%s", hostport);
    }

    return out->host[0] != '\0' ? 0 : -1;
}
