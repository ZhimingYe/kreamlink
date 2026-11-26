#include "kreamlink.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define KL_IO_TIMEOUT_MS 15000

int64_t kl_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000LL + (int64_t)(ts.tv_nsec / 1000000L);
}

void kl_set_tcp_nodelay(int fd) {
    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
#endif
}

int kl_set_nonblocking(int fd, bool nb) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (nb) flags |= O_NONBLOCK;
    else    flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

/* Bounded wait for socket readability/writability, interruptible by kl_stop_requested */
static int wait_fd_io(int fd, bool for_write, int timeout_ms) {
    int64_t deadline = kl_now_ms() + timeout_ms;
    while (!kl_stop_requested) {
        int64_t rem = deadline - kl_now_ms();
        if (rem <= 0) return -1;
        int slice = rem > 500 ? 500 : (int)rem;

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = for_write ? POLLOUT : POLLIN;
        pfd.revents = 0;

        int rc = poll(&pfd, 1, slice);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (rc > 0) {
            if (pfd.revents & (POLLERR | POLLNVAL)) return -1;
            if (for_write && (pfd.revents & POLLHUP)) return -1;
            return 0;
        }
    }
    return -1;
}

/* fd must be nonblocking. One deadline covers all partial writes and retries. */
int kl_tcp_write_all(int fd, const uint8_t *data, size_t len, int timeout_ms) {
    int64_t deadline = kl_now_ms() + timeout_ms;
    while (len && !kl_stop_requested) {
        int64_t remaining = deadline - kl_now_ms();
        if (remaining <= 0) return -1;
        ssize_t n = write(fd, data, len);
        if (n > 0) {
            data += n;
            len -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
            wait_fd_io(fd, true, (int)remaining) == 0) continue;
        return -1;
    }
    return len == 0 ? 0 : -1;
}

/* Returns an accepted fd, or -1 on stop or permanent listener failure. */
int kl_tcp_accept(int listen_fd) {
    struct pollfd pfd = {.fd = listen_fd, .events = POLLIN};
    while (!kl_stop_requested) {
        int rc = poll(&pfd, 1, 500);
        if (rc == 0 || (rc < 0 && errno == EINTR)) continue;
        if (rc < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            KL_ERROR("Listener poll failed (events=%d)", pfd.revents);
            return -1;
        }
        int fd = accept(listen_fd, NULL, NULL);
        if (fd >= 0) return fd;
        int err = errno;
        if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK || err == ECONNABORTED) continue;
        if (err == EBADF || err == ENOTSOCK || err == EINVAL) {
            KL_ERROR("Listener failed: %s", strerror(err));
            return -1;
        }
        /* A pending connection keeps the listener readable under EMFILE/ENFILE.
         * Yield before retrying so existing connections can release resources. */
        struct timespec delay = {.tv_nsec = 100000000};
        nanosleep(&delay, NULL);
    }
    return -1;
}

int kl_tcp_listen(const char *addr) {
    char host[256];
    uint16_t port = 0;
    if (kl_parse_hostport(addr, host, sizeof(host), &port) != 0) {
        KL_ERROR("Invalid listen address: %s", addr);
        return -1;
    }

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints, *res = NULL, *rp = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int rc = getaddrinfo(host[0] ? host : NULL, port_str, &hints, &res);
    if (rc != 0) {
        KL_ERROR("getaddrinfo(%s:%s): %s", host, port_str, gai_strerror(rc));
        return -1;
    }

    int listen_fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen(fd, 128) == 0 &&
            kl_set_nonblocking(fd, true) == 0) {
            listen_fd = fd;
            break;
        }
        close(fd);
    }

    freeaddrinfo(res);
    if (listen_fd < 0) {
        KL_ERROR("Failed to bind/listen on %s: %s", addr, strerror(errno));
    }
    return listen_fd;
}

int kl_tcp_connect(const char *host, uint16_t port, int timeout_ms) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints, *res = NULL, *rp = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        KL_WARN("DNS resolve failed for %s:%s: %s", host, port_str, gai_strerror(rc));
        return -1;
    }

    int sock = -1;
    int64_t deadline = kl_now_ms() + (timeout_ms > 0 ? timeout_ms : 5000);
    for (rp = res; rp != NULL && !kl_stop_requested; rp = rp->ai_next) {
        int64_t remaining = deadline - kl_now_ms();
        if (remaining <= 0) break;
        int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        kl_set_tcp_nodelay(fd);
        if (kl_set_nonblocking(fd, true) != 0) {
            close(fd);
            continue;
        }

        int c = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (c < 0 && errno == EINPROGRESS) {
            if (wait_fd_io(fd, true, (int)remaining) == 0) {
                int so_err = 0;
                socklen_t len = sizeof(so_err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len) == 0 && so_err == 0) c = 0;
            }
        }
        if (c == 0 && kl_set_nonblocking(fd, false) == 0) {
            sock = fd;
            break;
        }
        close(fd);
    }

    freeaddrinfo(res);
    return sock;
}

/* Non-blocking + bounded-poll write so a blackholed socket NEVER hangs indefinitely */
static ssize_t transport_write_all(kl_ws_conn_t *conn, const uint8_t *buf, size_t len) {
    if (!conn->ssl)
        return kl_tcp_write_all(conn->fd, buf, len, KL_IO_TIMEOUT_MS) == 0 ? (ssize_t)len : -1;
    size_t sent = 0;
    int64_t deadline = kl_now_ms() + KL_IO_TIMEOUT_MS;

    while (sent < len && !kl_stop_requested) {
        int64_t rem = deadline - kl_now_ms();
        if (rem <= 0) return -1;

        ERR_clear_error();
        int n = SSL_write(conn->ssl, buf + sent, (int)(len - sent));
        if (n <= 0) {
            int err = SSL_get_error(conn->ssl, (int)n);
            if (err == SSL_ERROR_WANT_WRITE) {
                if (wait_fd_io(conn->fd, true, (int)rem) != 0) return -1;
                continue;
            }
            if (err == SSL_ERROR_WANT_READ) {
                if (wait_fd_io(conn->fd, false, (int)rem) != 0) return -1;
                continue;
            }
            ERR_clear_error();
            return -1;
        }
        sent += (size_t)n;
    }
    return (sent == len) ? (ssize_t)sent : -1;
}

/* Non-blocking + bounded-poll read so a mid-frame blackhole NEVER hangs indefinitely */
static ssize_t transport_read_exact(kl_ws_conn_t *conn, uint8_t *buf, size_t len, int64_t deadline) {
    size_t got = 0;

    while (got < len && !kl_stop_requested) {
        int64_t rem = deadline - kl_now_ms();
        if (rem <= 0) return -1;

        ssize_t n;
        if (conn->ssl) {
            ERR_clear_error();
            n = SSL_read(conn->ssl, buf + got, (int)(len - got));
            if (n <= 0) {
                int err = SSL_get_error(conn->ssl, (int)n);
                if (err == SSL_ERROR_WANT_READ) {
                    if (wait_fd_io(conn->fd, false, (int)rem) != 0) return -1;
                    continue;
                }
                if (err == SSL_ERROR_WANT_WRITE) {
                    if (wait_fd_io(conn->fd, true, (int)rem) != 0) return -1;
                    continue;
                }
                ERR_clear_error();
                return -1;
            }
        } else {
            n = recv(conn->fd, buf + got, len - got, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (wait_fd_io(conn->fd, false, (int)rem) != 0) return -1;
                    continue;
                }
                return -1;
            }
            if (n == 0) return -1;
        }
        got += (size_t)n;
    }
    return (got == len) ? (ssize_t)got : -1;
}

static int ssl_handshake_bounded(SSL *ssl, int fd, bool is_client, int timeout_ms) {
    int64_t deadline = kl_now_ms() + timeout_ms;
    while (!kl_stop_requested) {
        ERR_clear_error();
        int rc = is_client ? SSL_connect(ssl) : SSL_accept(ssl);
        if (rc == 1) return 0;
        int err = SSL_get_error(ssl, rc);
        int64_t rem = deadline - kl_now_ms();
        if (rem <= 0) {
            ERR_clear_error();
            return -1;
        }
        if (err == SSL_ERROR_WANT_READ) {
            if (wait_fd_io(fd, false, (int)rem) != 0) return -1;
            continue;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            if (wait_fd_io(fd, true, (int)rem) != 0) return -1;
            continue;
        }
        return -1;
    }
    return -1;
}

static int read_http_headers(kl_ws_conn_t *conn, char *buf, size_t cap) {
    int64_t deadline = kl_now_ms() + KL_IO_TIMEOUT_MS;
    size_t pos = 0;
    while (pos + 1 < cap) {
        uint8_t c;
        if (transport_read_exact(conn, &c, 1, deadline) != 1 || c == 0) return -1;
        buf[pos++] = (char)c;
        buf[pos] = '\0';
        if (pos >= 4 &&
            buf[pos - 4] == '\r' && buf[pos - 3] == '\n' &&
            buf[pos - 2] == '\r' && buf[pos - 1] == '\n') {
            return (int)pos;
        }
    }
    return -1;
}

static int compute_ws_accept(const char *client_key, char *out, size_t out_sz) {
    char combined[256];
    int n = snprintf(combined, sizeof(combined), "%s%s", client_key, WS_GUID);
    if (n <= 0 || (size_t)n >= sizeof(combined)) return -1;

    uint8_t sha1[SHA_DIGEST_LENGTH];
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) return -1;
    unsigned int dlen = 0;
    int ok = (EVP_DigestInit_ex(md, EVP_sha1(), NULL) == 1 &&
              EVP_DigestUpdate(md, combined, (size_t)n) == 1 &&
              EVP_DigestFinal_ex(md, sha1, &dlen) == 1);
    EVP_MD_CTX_free(md);
    if (!ok) return -1;

    return kl_base64_encode(sha1, SHA_DIGEST_LENGTH, out, out_sz) > 0 ? 0 : -1;
}

/* Return 1 for one value, 0 if absent, -1 for duplicate or oversized fields. */
static int extract_header_value(const char *headers, const char *name,
                                 char *val, size_t val_sz) {
    size_t name_len = strlen(name);
    const char *p = headers;
    bool found = false;
    while (*p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        if ((size_t)(eol - p) >= name_len + 1 &&
            strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
            const char *v = p + name_len + 1;
            while (v < eol && (*v == ' ' || *v == '\t')) v++;
            const char *ve = eol;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
            size_t len = (size_t)(ve - v);
            if (found || len >= val_sz) return -1;
            memcpy(val, v, len);
            val[len] = '\0';
            found = true;
        }
        p = eol + 2;
    }
    return found;
}

static bool header_has_item(const char *value, const char *item, char separator,
                            bool ignore_case) {
    size_t item_len = strlen(item);
    while (*value) {
        const char *next = strchr(value, separator);
        const char *end = next ? next : value + strlen(value);
        while (value < end && (*value == ' ' || *value == '\t')) value++;
        while (end > value && (end[-1] == ' ' || end[-1] == '\t')) end--;
        if ((size_t)(end - value) == item_len &&
            (ignore_case ? strncasecmp(value, item, item_len) : strncmp(value, item, item_len)) == 0)
            return true;
        if (!next) break;
        value = next + 1;
    }
    return false;
}

static bool has_upgrade_headers(const char *headers) {
    char upgrade[64], connection[256];
    return extract_header_value(headers, "Upgrade", upgrade, sizeof(upgrade)) == 1 &&
           strcasecmp(upgrade, "websocket") == 0 &&
           extract_header_value(headers, "Connection", connection, sizeof(connection)) == 1 &&
           header_has_item(connection, "upgrade", ',', true);
}

/* Takes ownership of fd, including on handshake failure. */
static int ws_connect_fd(kl_ws_conn_t *conn, int fd, const kl_url_t *url,
                         const kl_config_t *cfg, int timeout_ms) {
    memset(conn, 0, sizeof(*conn));
    conn->is_client = true;
    conn->fd = fd;
    /* Keep WS socket non-blocking for bounded poll-driven I/O */
    if (kl_set_nonblocking(fd, true) != 0) {
        kl_ws_close(conn);
        return -1;
    }

    if (url->use_tls) {
        conn->ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!conn->ssl_ctx) {
            ERR_clear_error();
            kl_ws_close(conn);
            return -1;
        }
        conn->owns_ctx = true;
        if (!SSL_CTX_set_min_proto_version(conn->ssl_ctx, TLS1_2_VERSION)) {
            kl_ws_close(conn);
            return -1;
        }

        if (cfg->insecure_tls) {
            SSL_CTX_set_verify(conn->ssl_ctx, SSL_VERIFY_NONE, NULL);
        } else {
            if (!SSL_CTX_set_default_verify_paths(conn->ssl_ctx)) {
                kl_ws_close(conn);
                return -1;
            }
            SSL_CTX_set_verify(conn->ssl_ctx, SSL_VERIFY_PEER, NULL);
        }

        conn->ssl = SSL_new(conn->ssl_ctx);
        if (!conn->ssl) {
            ERR_clear_error();
            kl_ws_close(conn);
            return -1;
        }
        unsigned char ip[sizeof(struct in6_addr)];
        bool numeric = inet_pton(AF_INET, url->host, ip) == 1 ||
                       inet_pton(AF_INET6, url->host, ip) == 1;
        if ((!numeric && !SSL_set_tlsext_host_name(conn->ssl, url->host)) ||
            (!cfg->insecure_tls && !(numeric
                ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(conn->ssl), url->host)
                : SSL_set1_host(conn->ssl, url->host))) ||
            !SSL_set_fd(conn->ssl, fd)) {
            kl_ws_close(conn);
            return -1;
        }

        if (ssl_handshake_bounded(conn->ssl, fd, true, timeout_ms > 0 ? timeout_ms : 10000) != 0) {
            unsigned long e = ERR_get_error();
            char ebuf[256] = "timeout/io error";
            if (e) ERR_error_string_n(e, ebuf, sizeof(ebuf));
            ERR_clear_error();
            KL_WARN("TLS handshake failed to %s:%u: %s", url->host, url->port, ebuf);
            kl_ws_close(conn);
            return -1;
        }
    }

    /* Generate Sec-WebSocket-Key */
    uint8_t key_raw[16];
    if (kl_random_bytes(key_raw, sizeof(key_raw)) != 0) {
        kl_ws_close(conn);
        return -1;
    }
    char ws_key[64];
    if (kl_base64_encode(key_raw, sizeof(key_raw), ws_key, sizeof(ws_key)) < 0) {
        kl_ws_close(conn);
        return -1;
    }

    char expected_accept[64];
    if (compute_ws_accept(ws_key, expected_accept, sizeof(expected_accept)) != 0) {
        kl_ws_close(conn);
        return -1;
    }

    const char *left = strchr(url->host, ':') ? "[" : "";
    const char *right = *left ? "]" : "";
    char host_hdr[300];
    if ((url->use_tls && url->port == 443) || (!url->use_tls && url->port == 80)) {
        snprintf(host_hdr, sizeof(host_hdr), "%s%s%s", left, url->host, right);
    } else {
        snprintf(host_hdr, sizeof(host_hdr), "%s%s%s:%u", left, url->host, right, url->port);
    }

    char req[2048];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: %s\r\n%s%s%s%s%s%s\r\n",
        url->path, host_hdr, ws_key, cfg->user_agent,
        cfg->cookie[0] ? "Cookie: " : "", cfg->cookie, cfg->cookie[0] ? "\r\n" : "",
        cfg->subprotocol[0] ? "Sec-WebSocket-Protocol: " : "", cfg->subprotocol,
        cfg->subprotocol[0] ? "\r\n" : "");

    if (req_len < 0 || (size_t)req_len >= sizeof(req) ||
        transport_write_all(conn, (const uint8_t *)req, (size_t)req_len) != req_len) {
        kl_ws_close(conn);
        return -1;
    }

    char resp[4096];
    if (read_http_headers(conn, resp, sizeof(resp)) < 0) {
        kl_ws_close(conn);
        return -1;
    }

    if (strncmp(resp, "HTTP/1.1 101", 12) != 0 || (resp[12] != ' ' && resp[12] != '\r') ||
        !has_upgrade_headers(resp)) {
        KL_WARN("WebSocket upgrade rejected by server (non-101 response)");
        kl_ws_close(conn);
        return -1;
    }

    char selected[128];
    int has_protocol = extract_header_value(resp, "Sec-WebSocket-Protocol", selected, sizeof(selected));
    if (has_protocol < 0 || (has_protocol && (!selected[0] ||
        !header_has_item(cfg->subprotocol, selected, ',', false)))) {
        kl_ws_close(conn);
        return -1;
    }
    char accept_val[128];
    if (extract_header_value(resp, "Sec-WebSocket-Accept", accept_val, sizeof(accept_val)) != 1 ||
        strcmp(accept_val, expected_accept) != 0) {
        KL_WARN("WebSocket Sec-WebSocket-Accept mismatch");
        kl_ws_close(conn);
        return -1;
    }

    return 0;
}

int kl_ws_connect(kl_ws_conn_t *conn, const kl_config_t *cfg, int timeout_ms) {
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
    kl_url_t url;
    if (kl_parse_url(cfg->hub_url, &url) != 0) {
        KL_ERROR("Invalid Hub URL: %s", cfg->hub_url);
        return -1;
    }

    int fd = kl_tcp_connect(url.host, url.port, timeout_ms);
    if (fd < 0) {
        return -1;
    }
    return ws_connect_fd(conn, fd, &url, cfg, timeout_ms);
}

static void send_decoy_response(kl_ws_conn_t *conn) {
    const char *body = "{\"status\":\"ok\",\"service\":\"gateway\",\"version\":\"2.4.1\"}\n";
    char resp[512];
    int n = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Server: nginx/1.24.0\r\n\r\n%s",
        strlen(body), body);
    if (n > 0) {
        transport_write_all(conn, (const uint8_t *)resp, (size_t)n);
    }
}

int kl_ws_accept_server(kl_ws_conn_t *conn, int client_fd, SSL_CTX *tls_ctx,
                        const kl_config_t *cfg) {
    memset(conn, 0, sizeof(*conn));
    conn->fd = client_fd;
    conn->is_client = false;
    kl_set_tcp_nodelay(client_fd);
    if (kl_set_nonblocking(client_fd, true) != 0) {
        kl_ws_close(conn);
        return -1;
    }

    if (tls_ctx) {
        conn->ssl = SSL_new(tls_ctx);
        if (!conn->ssl) {
            ERR_clear_error();
            kl_ws_close(conn);
            return -1;
        }
        if (!SSL_set_fd(conn->ssl, client_fd) ||
            ssl_handshake_bounded(conn->ssl, client_fd, false, 10000) != 0) {
            ERR_clear_error();
            kl_ws_close(conn);
            return -1;
        }
    }

    char req[4096];
    if (read_http_headers(conn, req, sizeof(req)) < 0) {
        kl_ws_close(conn);
        return -1;
    }

    /* Parse request line: GET <path> HTTP/1.1 */
    char *path = req + 4;
    char *line_end = strstr(req, "\r\n");
    char *version = strncmp(req, "GET ", 4) == 0 ? strchr(path, ' ') : NULL;
    if (!version || !line_end || line_end - version != 9 ||
        memcmp(version, " HTTP/1.1", 9) != 0) {
        send_decoy_response(conn);
        kl_ws_close(conn);
        return -1;
    }

    /* Strip query string when comparing ws_path */
    *version = '\0';
    char *q = strchr(path, '?');
    if (q) *q = '\0';

    char ws_version[16], ws_key[128] = {0}, proto[128] = {0}, cookie[256] = {0};
    bool has_key = extract_header_value(line_end + 2, "Sec-WebSocket-Key", ws_key, sizeof(ws_key)) == 1;

    if (strcmp(path, cfg->ws_path) != 0 ||
        !has_upgrade_headers(line_end + 2) ||
        extract_header_value(line_end + 2, "Sec-WebSocket-Version", ws_version, sizeof(ws_version)) != 1 ||
        strcmp(ws_version, "13") || !has_key || strlen(ws_key) != 24 ||
        strcmp(ws_key + 22, "==") || strspn(ws_key, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") != 22) {
        /* Layer-1 anti-probing decoy response */
        send_decoy_response(conn);
        kl_ws_close(conn);
        return -1;
    }

    /* Optional Layer-1 disguise checks */
    if (cfg->subprotocol[0]) {
        if (extract_header_value(line_end + 2, "Sec-WebSocket-Protocol", proto, sizeof(proto)) != 1 ||
            !header_has_item(proto, cfg->subprotocol, ',', false)) {
            send_decoy_response(conn);
            kl_ws_close(conn);
            return -1;
        }
    }
    if (cfg->cookie[0]) {
        if (extract_header_value(line_end + 2, "Cookie", cookie, sizeof(cookie)) != 1 ||
            (strcmp(cookie, cfg->cookie) && !header_has_item(cookie, cfg->cookie, ';', false))) {
            send_decoy_response(conn);
            kl_ws_close(conn);
            return -1;
        }
    }

    char accept_val[64];
    if (compute_ws_accept(ws_key, accept_val, sizeof(accept_val)) != 0) {
        kl_ws_close(conn);
        return -1;
    }

    char resp[512];
    int resp_len;
    if (cfg->subprotocol[0]) {
        resp_len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "Sec-WebSocket-Protocol: %s\r\n\r\n",
            accept_val, cfg->subprotocol);
    } else {
        resp_len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n\r\n",
            accept_val);
    }

    if (transport_write_all(conn, (const uint8_t *)resp, (size_t)resp_len) != resp_len) {
        kl_ws_close(conn);
        return -1;
    }

    return 0;
}

void kl_ws_close(kl_ws_conn_t *conn) {
    if (!conn) return;
    if (conn->ssl) {
        /* Socket is already non-blocking, so SSL_shutdown is best-effort and never hangs */
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->owns_ctx && conn->ssl_ctx) {
        SSL_CTX_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
    }
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
    ERR_clear_error();
}

int kl_ws_send_frame(kl_ws_conn_t *conn, uint8_t opcode,
                     const uint8_t *payload, size_t len) {
    if (len > KL_MAX_WS_FRAME) return -1;

    uint8_t hdr[14];
    size_t hdr_len = 0;
    hdr[0] = (uint8_t)(0x80 | (opcode & 0x0F)); /* FIN=1 */

    uint8_t mask_bit = conn->is_client ? 0x80 : 0x00;
    if (len < 126) {
        hdr[1] = (uint8_t)(mask_bit | len);
        hdr_len = 2;
    } else if (len <= 0xFFFF) {
        hdr[1] = (uint8_t)(mask_bit | 126);
        hdr[2] = (uint8_t)((len >> 8) & 0xFF);
        hdr[3] = (uint8_t)(len & 0xFF);
        hdr_len = 4;
    } else {
        hdr[1] = (uint8_t)(mask_bit | 127);
        for (int i = 0; i < 8; i++) {
            hdr[2 + i] = (uint8_t)(((uint64_t)len >> (56 - i * 8)) & 0xFF);
        }
        hdr_len = 10;
    }

    uint8_t mask_key[4] = {0};
    if (conn->is_client) {
        if (kl_random_bytes(mask_key, 4) != 0) return -1;
        memcpy(hdr + hdr_len, mask_key, 4);
        hdr_len += 4;
    }

    uint8_t stack_buf[4096];
    uint8_t *out = stack_buf;
    bool heap = false;
    if (hdr_len + len > sizeof(stack_buf)) {
        out = malloc(hdr_len + len);
        if (!out) return -1;
        heap = true;
    }

    memcpy(out, hdr, hdr_len);
    if (len > 0) {
        if (conn->is_client) {
            for (size_t i = 0; i < len; i++) {
                out[hdr_len + i] = payload[i] ^ mask_key[i & 3];
            }
        } else {
            memcpy(out + hdr_len, payload, len);
        }
    }

    ssize_t w = transport_write_all(conn, out, hdr_len + len);
    if (heap) free(out);
    return (w == (ssize_t)(hdr_len + len)) ? 0 : -1;
}

int kl_ws_send_text(kl_ws_conn_t *conn, const char *text) {
    return kl_ws_send_frame(conn, WS_OP_TEXT, (const uint8_t *)text, strlen(text));
}

enum ws_read_mode { WS_READ_MESSAGE, WS_READ_EVENT, WS_READ_REGISTRATION };

static int recv_message(kl_ws_conn_t *conn, uint8_t *opcode_out,
                        uint8_t *buf, size_t buf_cap, enum ws_read_mode mode) {
    int64_t deadline = kl_now_ms() + KL_IO_TIMEOUT_MS;
    size_t total = 0;
    uint8_t msg_opcode = 0;
    bool started = false;
    /* Limit work and control replies before authentication, including frames
     * interleaved with fragments. All frames share the same read deadline. */
    for (unsigned frames = 0; mode != WS_READ_REGISTRATION || frames < KL_REGISTRATION_MAX_FRAMES; frames++) {
        uint8_t h[2];
        if (transport_read_exact(conn, h, 2, deadline) != 2) return -1;

        bool fin = (h[0] & 0x80) != 0;
        uint8_t op = h[0] & 0x0F;
        bool masked = (h[1] & 0x80) != 0;
        uint64_t plen = h[1] & 0x7F;

        if ((h[0] & 0x70) || masked == conn->is_client) return -1;
        if (op >= 8) {
            if ((op != WS_OP_PING && op != WS_OP_PONG && op != WS_OP_CLOSE) ||
                !fin || plen > 125 || (op == WS_OP_CLOSE && plen == 1)) return -1;
        } else if (started ? op != WS_OP_CONT : (op != WS_OP_TEXT && op != WS_OP_BINARY)) {
            return -1;
        }

        if (plen == 126) {
            uint8_t ext[2];
            if (transport_read_exact(conn, ext, 2, deadline) != 2) return -1;
            plen = ((uint64_t)ext[0] << 8) | ext[1];
            if (plen < 126) return -1;
        } else if (plen == 127) {
            uint8_t ext[8];
            if (transport_read_exact(conn, ext, 8, deadline) != 8) return -1;
            plen = 0;
            for (int i = 0; i < 8; i++) {
                plen = (plen << 8) | ext[i];
            }
            if ((ext[0] & 0x80) || plen <= 65535) return -1;
        }

        uint8_t mask_key[4] = {0};
        if (masked) {
            if (transport_read_exact(conn, mask_key, 4, deadline) != 4) return -1;
        }

        /* Handle control frames inline (RFC 6455 allows them mid-fragment) */
        if (op == WS_OP_PING || op == WS_OP_PONG || op == WS_OP_CLOSE) {

            uint8_t ctrl[128];
            if (plen > 0) {
                if (transport_read_exact(conn, ctrl, (size_t)plen, deadline) != (ssize_t)plen) return -1;
                if (masked) {
                    for (size_t i = 0; i < (size_t)plen; i++) ctrl[i] ^= mask_key[i & 3];
                }
            }
            if (op == WS_OP_CLOSE) {
                kl_ws_send_frame(conn, WS_OP_CLOSE, NULL, 0);
                return -2;
            }
            if (op == WS_OP_PING && kl_ws_send_frame(conn, WS_OP_PONG, ctrl, (size_t)plen) != 0)
                return -1;
            if (!started && mode == WS_READ_EVENT) {
                *opcode_out = op;
                return 0;
            }
            continue;
        }

        if (plen > buf_cap - total || plen > KL_MAX_WS_FRAME - total) return -1;

        if (plen > 0) {
            if (transport_read_exact(conn, buf + total, (size_t)plen, deadline) != (ssize_t)plen) {
                return -1;
            }
            if (masked) {
                for (size_t i = 0; i < (size_t)plen; i++) {
                    buf[total + i] ^= mask_key[i & 3];
                }
            }
        }

        if (!started) {
            msg_opcode = op;
            started = true;
        }
        total += (size_t)plen;

        if (fin) {
            *opcode_out = msg_opcode;
            return (int)total;
        }
    }
    return -1;
}

int kl_ws_recv_registration(kl_ws_conn_t *conn, uint8_t *opcode_out, uint8_t *buf, size_t cap) {
    return recv_message(conn, opcode_out, buf, cap, WS_READ_REGISTRATION);
}

int kl_ws_recv_msg(kl_ws_conn_t *conn, uint8_t *opcode_out, uint8_t *buf, size_t cap) {
    return recv_message(conn, opcode_out, buf, cap, WS_READ_MESSAGE);
}

int kl_ws_recv_event(kl_ws_conn_t *conn, uint8_t *opcode_out, uint8_t *buf, size_t cap) {
    return recv_message(conn, opcode_out, buf, cap, WS_READ_EVENT);
}

int kl_ws_poll_read(kl_ws_conn_t *conn, int wakeup_fd, int timeout_ms, bool *wakeup_ready) {
    if (wakeup_ready) *wakeup_ready = false;

    /* Check if OpenSSL already buffered decrypted bytes */
    if (conn->ssl && SSL_pending(conn->ssl) > 0) {
        if (wakeup_fd >= 0 && wakeup_ready) {
            struct pollfd wp = { .fd = wakeup_fd, .events = POLLIN, .revents = 0 };
            if (poll(&wp, 1, 0) > 0 && (wp.revents & POLLIN)) {
                *wakeup_ready = true;
            }
        }
        return 1;
    }

    struct pollfd fds[2];
    nfds_t nfds = 1;
    fds[0].fd = conn->fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    if (wakeup_fd >= 0) {
        fds[1].fd = wakeup_fd;
        fds[1].events = POLLIN;
        fds[1].revents = 0;
        nfds = 2;
    }

    int rc = poll(fds, nfds, timeout_ms);
    if (rc < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }
    if (rc == 0) return 0;

    if (nfds == 2 && (fds[1].revents & POLLIN) && wakeup_ready) {
        *wakeup_ready = true;
    }
    if ((fds[0].revents & POLLNVAL) ||
        (nfds == 2 && (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)))) return -1;
    if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
        return 1;
    }
    return 0;
}
