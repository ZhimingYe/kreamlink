#include "kreamlink.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define KL_HUB_QUEUE_BYTES (8u * 1024 * 1024)

typedef struct ws_out_frame {
    uint8_t opcode;
    size_t  len;
    struct ws_out_frame *next;
    uint8_t data[];
} ws_out_frame_t;

typedef struct hub_client {
    kl_ws_conn_t conn;
    int wake_pipe[2];
    pthread_mutex_t q_mu;
    ws_out_frame_t *q_head;
    ws_out_frame_t *q_tail;
    int q_count;
    bool closing;
    size_t q_bytes;
    char channel_hash[KL_CHAN_HASH_HEX_LEN + 1];
    bool is_sender;
    const kl_config_t *cfg;
    SSL_CTX *tls_ctx;
    int client_fd;
} hub_client_t;

typedef struct hub_channel {
    char channel_hash[KL_CHAN_HASH_HEX_LEN + 1];
    hub_client_t *sender;
    hub_client_t *receiver;
    struct hub_channel *next;
} hub_channel_t;

static pthread_mutex_t g_hub_mu = PTHREAD_MUTEX_INITIALIZER;
static hub_channel_t *g_channels = NULL;

static void wake_client(hub_client_t *c) {
    uint8_t b = 1;
    ssize_t r;
    do {
        r = write(c->wake_pipe[1], &b, 1);
    } while (r < 0 && errno == EINTR);
}

static void client_destroy(hub_client_t *c) {
    ws_out_frame_t *f = c->q_head;
    while (f) {
        ws_out_frame_t *next = f->next;
        free(f);
        f = next;
    }
    pthread_mutex_destroy(&c->q_mu);
    close(c->wake_pipe[0]);
    close(c->wake_pipe[1]);
    free(c);
}

static void client_mark_closing(hub_client_t *c) {
    pthread_mutex_lock(&c->q_mu);
    c->closing = true;
    pthread_mutex_unlock(&c->q_mu);
    wake_client(c);
}

/* Routing holds g_hub_mu until enqueue completes, pinning the recipient. */
static void client_enqueue(hub_client_t *c, uint8_t opcode,
                           const uint8_t *data, size_t len) {
    pthread_mutex_lock(&c->q_mu);
    if (!c->closing) {
        ws_out_frame_t *f = NULL;
        if (c->q_count < 2048 && len <= KL_HUB_QUEUE_BYTES - c->q_bytes)
            f = malloc(sizeof(*f) + len);
        if (!f) {
            c->closing = true;
        } else {
            f->opcode = opcode;
            f->len = len;
            f->next = NULL;
            if (len) memcpy(f->data, data, len);
            if (c->q_tail) c->q_tail->next = f;
            else c->q_head = f;
            c->q_tail = f;
            c->q_count++;
            c->q_bytes += len;
        }
    }
    pthread_mutex_unlock(&c->q_mu);
    wake_client(c);
}

static void client_enqueue_text(hub_client_t *c, const char *text) {
    client_enqueue(c, WS_OP_TEXT, (const uint8_t *)text, strlen(text));
}

static bool token_is_allowed(const kl_config_t *cfg, const char *chan_hash) {
    if (cfg->allowed_token_count == 0) return true;
    for (int i = 0; i < cfg->allowed_token_count; i++) {
        if (!strcmp(cfg->allowed_channel_ids[i], chan_hash)) return true;
    }
    return false;
}

static hub_channel_t *find_or_create_channel_locked(const char *chan_hash) {
    for (hub_channel_t *ch = g_channels; ch; ch = ch->next) {
        if (strcmp(ch->channel_hash, chan_hash) == 0) return ch;
    }
    hub_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) return NULL;
    snprintf(ch->channel_hash, sizeof(ch->channel_hash), "%s", chan_hash);
    ch->next = g_channels;
    g_channels = ch;
    return ch;
}

static void relay_frame(hub_client_t *self, const uint8_t *buf, size_t len) {
    pthread_mutex_lock(&g_hub_mu);
    for (hub_channel_t *ch = g_channels; ch; ch = ch->next) {
        hub_client_t *peer = NULL;
        if (ch->sender == self) peer = ch->receiver;
        else if (ch->receiver == self) peer = ch->sender;
        else continue;
        if (peer) client_enqueue(peer, WS_OP_BINARY, buf, len);
        break;
    }
    pthread_mutex_unlock(&g_hub_mu);
}

static bool register_client(hub_client_t *c, bool *peer_online_out) {
    pthread_mutex_lock(&g_hub_mu);
    hub_channel_t *ch = find_or_create_channel_locked(c->channel_hash);
    if (!ch) {
        pthread_mutex_unlock(&g_hub_mu);
        return false;
    }
    hub_client_t **slot = c->is_sender ? &ch->sender : &ch->receiver;
    hub_client_t **other = c->is_sender ? &ch->receiver : &ch->sender;
    if (*slot) {
        client_mark_closing(*slot);
        if (*other) {
            client_mark_closing(*other);
            *other = NULL;
        }
    }
    *slot = c;
    *peer_online_out = *other != NULL;
    if (*other) client_enqueue_text(*other, "{\"type\":\"peer\",\"online\":true}");
    pthread_mutex_unlock(&g_hub_mu);
    return true;
}

static void unregister_client(hub_client_t *c) {
    pthread_mutex_lock(&g_hub_mu);
    for (hub_channel_t **pp = &g_channels; *pp; pp = &(*pp)->next) {
        hub_channel_t *ch = *pp;
        hub_client_t *peer;
        if (ch->sender == c) peer = ch->receiver;
        else if (ch->receiver == c) peer = ch->sender;
        else continue;
        /* Old queued or in-flight frames belong only to this pairing. */
        if (peer) client_mark_closing(peer);
        *pp = ch->next;
        free(ch);
        break;
    }
    pthread_mutex_unlock(&g_hub_mu);
}

static int flush_client_queue(hub_client_t *c) {
    /* Drain wake pipe */
    uint8_t drain[64];
    while (read(c->wake_pipe[0], drain, sizeof(drain)) > 0) {}

    for (unsigned batch = 0; batch < 16; batch++) {
        pthread_mutex_lock(&c->q_mu);
        bool closing = c->closing;
        ws_out_frame_t *f = c->q_head;
        if (f) {
            c->q_head = f->next;
            if (!c->q_head) c->q_tail = NULL;
            c->q_count--;
            c->q_bytes -= f->len;
        }
        pthread_mutex_unlock(&c->q_mu);

        if (closing) {
            free(f);
            return -1;
        }
        if (!f) return 0;

        int rc = kl_ws_send_frame(&c->conn, f->opcode, f->data, f->len);
        free(f);
        if (rc != 0) return -1;
    }
    wake_client(c); /* Continue draining after servicing incoming frames. */
    return 0;
}

static void serve_client(hub_client_t *c) {
    if (kl_ws_accept_server(&c->conn, c->client_fd, c->tls_ctx, c->cfg) != 0) {
        return;
    }

    uint8_t registration[KL_REGISTRATION_MAX_BYTES + 1];
    uint8_t op = 0;
    int n = kl_ws_recv_registration(&c->conn, &op, registration, sizeof(registration) - 1);
    if (n <= 0 || op != WS_OP_TEXT) {
        kl_ws_close(&c->conn);
        return;
    }
    kl_control_t msg;
    if (!kl_control_parse((char *)registration, (size_t)n, &msg) ||
        !msg.action || strcmp(msg.action, "subscribe") ||
        !msg.role || (strcmp(msg.role, "recv") && strcmp(msg.role, "send")) ||
        !msg.channel || strlen(msg.channel) != KL_CHAN_HASH_HEX_LEN ||
        strspn(msg.channel, "0123456789abcdef") != KL_CHAN_HASH_HEX_LEN) {
        kl_ws_send_text(&c->conn, "{\"status\":\"error\",\"code\":400}");
        kl_ws_close(&c->conn);
        return;
    }

    const char *chan = msg.channel;
    size_t auth_len = strlen(c->cfg->hub_auth);
    if (!auth_len || !msg.hub_auth || strlen(msg.hub_auth) != auth_len ||
        CRYPTO_memcmp(msg.hub_auth, c->cfg->hub_auth, auth_len) != 0) {
        kl_ws_send_text(&c->conn, "{\"status\":\"error\",\"code\":403}");
        kl_ws_close(&c->conn);
        return;
    }
    if (!token_is_allowed(c->cfg, chan)) {
        KL_WARN("Rejected unauthorized channel %.12s..", chan);
        kl_ws_send_text(&c->conn, "{\"status\":\"error\",\"code\":403}");
        kl_ws_close(&c->conn);
        return;
    }

    uint8_t *buf = malloc(KL_MAX_WS_FRAME + 1);
    if (!buf) {
        kl_ws_close(&c->conn);
        return;
    }
    c->is_sender = (strcmp(msg.role, "send") == 0);
    memcpy(c->channel_hash, chan, KL_CHAN_HASH_HEX_LEN);
    c->channel_hash[KL_CHAN_HASH_HEX_LEN] = '\0';

    bool peer_online = false;
    char sess[33];
    if (kl_random_hex(sess, 16) != 0 || !register_client(c, &peer_online)) {
        free(buf);
        kl_ws_close(&c->conn);
        return;
    }
    char reply[256];
    snprintf(reply, sizeof(reply),
             "{\"status\":\"ok\",\"authenticated\":true,\"session\":\"%s\",\"peer_online\":%s}",
             sess, peer_online ? "true" : "false");
    if (kl_ws_send_text(&c->conn, reply) != 0) {
        unregister_client(c);
        free(buf);
        kl_ws_close(&c->conn);
        return;
    }

    KL_INFO("Channel %.12s..: %s online (peer_online=%s)",
            c->channel_hash, c->is_sender ? "sender" : "receiver",
            peer_online ? "true" : "false");

    /* Main zero-trust relay loop with monotonic zombie-client watchdog (90s) */
    const int64_t idle_timeout_ms = 90000;
    int64_t last_rx_ms = kl_now_ms();

    while (!kl_stop_requested) {
        bool wake = false;
        int pr = kl_ws_poll_read(&c->conn, c->wake_pipe[0], 1000, &wake);
        if (pr < 0) break;

        if (wake) {
            if (flush_client_queue(c) != 0) break;
        }

        if (pr > 0) {
            int mlen = kl_ws_recv_event(&c->conn, &op, buf, KL_MAX_WS_FRAME);
            if (mlen < 0) break;
            last_rx_ms = kl_now_ms();

            if (op == WS_OP_TEXT) {
                if (!kl_control_parse((char *)buf, (size_t)mlen, &msg)) break;
                if (msg.type && !strcmp(msg.type, "ping")) {
                    char pong[128];
                    snprintf(pong, sizeof(pong), "{\"type\":\"pong\",\"ts\":%ld}", (long)time(NULL));
                    if (kl_ws_send_text(&c->conn, pong) != 0) break;
                }
            } else if (op == WS_OP_BINARY) {
                /* Blind zero-trust relay: forward encrypted+padded binary frame verbatim */
                relay_frame(c, buf, (size_t)mlen);
            }
        } else if (kl_now_ms() - last_rx_ms > idle_timeout_ms) {
            KL_WARN("Channel %.12s..: %s idle/dead for >90s, reaping zombie",
                    c->channel_hash, c->is_sender ? "sender" : "receiver");
            break;
        }
    }

    unregister_client(c);
    free(buf);
    kl_ws_close(&c->conn);
}

static void *hub_client_thread(void *arg) {
    hub_client_t *c = arg;
    serve_client(c);
    client_destroy(c);
    return NULL;
}

static SSL_CTX *create_hub_tls_ctx(const kl_config_t *cfg) {
    if (!cfg->tls_cert[0] || !cfg->tls_key[0]) {
        KL_ERROR("Direct TLS requires both a certificate and a private key");
        return NULL;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) ||
        SSL_CTX_use_certificate_chain_file(ctx, cfg->tls_cert) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, cfg->tls_key, SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx)) {
        KL_ERROR("Failed to load Hub TLS cert/key (%s, %s)", cfg->tls_cert, cfg->tls_key);
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

int kl_hub_run(const kl_config_t *cfg) {
    const char *listen_addr = cfg->listen_addr[0] ? cfg->listen_addr : "127.0.0.1:8080";
    SSL_CTX *tls_ctx = NULL;
    if (cfg->tls_cert[0] || cfg->tls_key[0]) {
        tls_ctx = create_hub_tls_ctx(cfg);
        if (!tls_ctx) return -1;
    }

    int listen_fd = kl_tcp_listen(listen_addr);
    if (listen_fd < 0) {
        if (tls_ctx) SSL_CTX_free(tls_ctx);
        return -1;
    }

    kl_workers_t workers;
    if (kl_workers_init(&workers) != 0) {
        close(listen_fd);
        SSL_CTX_free(tls_ctx);
        return -1;
    }

    KL_INFO("kreamlink Hub listening on %s (ws_path=%s, tls=%s)",
            listen_addr, cfg->ws_path, tls_ctx ? "direct" : "off");

    int result = 0;
    while (!kl_stop_requested) {
        int cfd = kl_tcp_accept(listen_fd);
        if (cfd < 0) {
            if (!kl_stop_requested) result = -1;
            break;
        }

        hub_client_t *c = calloc(1, sizeof(*c));
        if (!c) {
            close(cfd);
            continue;
        }
        if (pipe(c->wake_pipe) != 0) {
            free(c);
            close(cfd);
            continue;
        }
        if (kl_set_nonblocking(c->wake_pipe[0], true) != 0 ||
            kl_set_nonblocking(c->wake_pipe[1], true) != 0 ||
            pthread_mutex_init(&c->q_mu, NULL) != 0) {
            close(c->wake_pipe[0]);
            close(c->wake_pipe[1]);
            close(cfd);
            free(c);
            continue;
        }
        c->cfg = cfg;
        c->tls_ctx = tls_ctx;
        c->client_fd = cfd;
        c->conn.fd = -1;

        if (!kl_workers_start(&workers, hub_client_thread, c)) {
            close(cfd);
            client_destroy(c);
        }
    }

    close(listen_fd);
    kl_workers_join(&workers);
    pthread_mutex_destroy(&workers.mu);
    if (tls_ctx) SSL_CTX_free(tls_ctx);
    KL_INFO("kreamlink Hub stopped.");
    return result;
}
