#ifndef KREAMLINK_H
#define KREAMLINK_H

#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/ssl.h>

/* Version */
#define KREAMLINK_VERSION "0.1.0"

/* Protocol & framing constants */
#define KL_KEY_LEN           32   /* AES-256-GCM key */
#define KL_NONCE_LEN         12   /* GCM IV/nonce */
#define KL_TAG_LEN           16   /* GCM auth tag */
#define KL_CHAN_HASH_HEX_LEN 64   /* SHA-256 hex digest */

#define KL_MUX_HDR_LEN       5    /* 1-byte cmd + 4-byte stream_id (big-endian) */
#define KL_MAX_PAYLOAD       16384 /* Max plaintext chunk per mux frame */
#define KL_MAX_PADDING       256  /* Max random padding bytes */
#define KL_MAX_WS_FRAME      (64 * 1024)

/* Encrypted inner mux commands (invisible to Hub) */
enum {
    KL_CMD_OPEN      = 1,
    KL_CMD_OPEN_OK   = 2,
    KL_CMD_OPEN_FAIL = 3,
    KL_CMD_DATA      = 4,
    KL_CMD_CLOSE     = 5,
    KL_CMD_EOF       = 6
};

/* Operating modes */
typedef enum {
    KL_MODE_NONE = 0,
    KL_MODE_HUB,
    KL_MODE_RECV,
    KL_MODE_SEND
} kl_mode_t;

/* Log levels */
typedef enum {
    KL_LOG_DEBUG = 0,
    KL_LOG_INFO  = 1,
    KL_LOG_WARN  = 2,
    KL_LOG_ERROR = 3
} kl_log_level_t;

/* Maximum allowed tokens in Hub allowlist */
#define KL_MAX_ALLOWED_TOKENS 64
#define KL_REGISTRATION_MAX_BYTES 1024
#define KL_REGISTRATION_MAX_FRAMES 16
#define KL_HUB_AUTH_CAP 341 /* Base64 of up to 255 password bytes, plus NUL */

/* Configuration structure */
typedef struct {
    kl_mode_t mode;

    /* Common */
    kl_log_level_t log_level;
    char hub_auth[KL_HUB_AUTH_CAP];
    char hub_password_file[1024];
    char channel_file[1024];
    char ws_path[256];          /* Default: /api/v1/stream */
    char subprotocol[128];      /* Optional Sec-WebSocket-Protocol disguise */
    char user_agent[256];       /* Optional User-Agent disguise */
    char cookie[256];           /* Optional Cookie disguise */

    /* Hub-specific */
    char listen_addr[128];      /* e.g. "127.0.0.1:8080" (Hub or Sender) */
    char tls_cert[256];         /* Optional direct TLS cert for Hub */
    char tls_key[256];          /* Optional direct TLS key for Hub */
    char allowed_channel_ids[KL_MAX_ALLOWED_TOKENS][KL_CHAN_HASH_HEX_LEN + 1];
    int  allowed_token_count;

    /* Agent-specific */
    char hub_url[512];          /* e.g. "wss://your-domain.com/api/v1/stream" */
    char channel[256];          /* Shared secret channel token */
    char target_addr[128];      /* Receiver target, e.g. "127.0.0.1:22" */
    bool insecure_tls;          /* Skip TLS certificate verification (for testing) */
    int  heartbeat_sec;         /* Default: 15 */
    int  wait_peer_ms;          /* Sender wait timeout when peer offline, default: 5000 */
    int  padding_max;           /* Max random padding bytes (0..256), default: 192 */
} kl_config_t;

/* Parsed URL */
typedef struct {
    bool use_tls;
    char host[256];
    uint16_t port;
    char path[256];
} kl_url_t;

/* WebSocket opcodes (RFC 6455) */
enum {
    WS_OP_CONT   = 0x0,
    WS_OP_TEXT   = 0x1,
    WS_OP_BINARY = 0x2,
    WS_OP_CLOSE  = 0x8,
    WS_OP_PING   = 0x9,
    WS_OP_PONG   = 0xA
};

/* Transport connection (plain TCP or OpenSSL TLS) */
typedef struct {
    int      fd;
    SSL     *ssl;
    SSL_CTX *ssl_ctx;
    bool     is_client;
    bool     owns_ctx;
} kl_ws_conn_t;

/* Crypto context for E2EE */
typedef struct {
    uint8_t key[KL_KEY_LEN];
    char    channel_hash[KL_CHAN_HASH_HEX_LEN + 1];
    int     padding_max;
} kl_crypto_t;

/* ---------------- Logging (src/log.c) ---------------- */
void kl_log_set_level(kl_log_level_t lvl);
void kl_log(kl_log_level_t lvl, const char *fmt, ...);

#define KL_DEBUG(...) kl_log(KL_LOG_DEBUG, __VA_ARGS__)
#define KL_INFO(...)  kl_log(KL_LOG_INFO,  __VA_ARGS__)
#define KL_WARN(...)  kl_log(KL_LOG_WARN,  __VA_ARGS__)
#define KL_ERROR(...) kl_log(KL_LOG_ERROR, __VA_ARGS__)

/* v1 control message. A missing boolean is -1. Parsing modifies buf,
 * which must have room for a terminator at buf[len]. */
typedef struct {
    const char *action, *role, *channel, *type, *status, *hub_auth;
    int online, peer_online, authenticated;
} kl_control_t;
bool kl_control_parse(char *buf, size_t len, kl_control_t *msg);

/* ---------------- Config (src/config.c) ---------------- */
int  kl_copy_setting(char *dest, size_t cap, const char *value);
int  kl_parse_int(const char *value, int min, int max, int *out);
int  kl_load_credentials(kl_config_t *cfg);
int  kl_set_hub_password(kl_config_t *cfg, const char *password);
void kl_config_init(kl_config_t *cfg);
int  kl_config_load_yaml(kl_config_t *cfg, const char *path);
int  kl_parse_url(const char *url, kl_url_t *out);
int  kl_parse_hostport(const char *addr, char *host, size_t host_sz, uint16_t *port);

/* ---------------- Crypto & Padding (src/crypto.c) ---------------- */
int  kl_crypto_init(kl_crypto_t *ctx, const char *channel, int padding_max);
int  kl_channel_hash_hex(const char *channel, char out_hex[KL_CHAN_HASH_HEX_LEN + 1]);
int  kl_random_bytes(uint8_t *buf, size_t len);
int  kl_random_hex(char *out, size_t bytes);
int  kl_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_sz);

/* Encrypt mux command + payload and wrap with Layer-2 dynamic random padding.
 * Output format: [2B real_len][2B pad_len][12B nonce][16B tag][ciphertext][random_pad]
 * Returns total output length or -1 on error. */
int  kl_frame_seal(const kl_crypto_t *ctx,
                   uint8_t cmd, uint32_t stream_id,
                   const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_cap);

/* Unwrap padding and decrypt AEAD frame.
 * Returns plaintext data length (>= 0) or -1 on error/auth failure. */
int  kl_frame_open(const kl_crypto_t *ctx,
                   const uint8_t *in, size_t in_len,
                   uint8_t *cmd_out, uint32_t *stream_id_out,
                   uint8_t *data_out, size_t data_cap);

/* ---------------- WebSocket & Network (src/ws.c) ---------------- */
int64_t kl_now_ms(void);
int  kl_tcp_listen(const char *addr);
int  kl_tcp_accept(int listen_fd);
/* Write to a nonblocking stream socket within a single monotonic deadline. */
int  kl_tcp_write_all(int fd, const uint8_t *data, size_t len, int timeout_ms);
int  kl_tcp_connect(const char *host, uint16_t port, int timeout_ms);
void kl_set_tcp_nodelay(int fd);
int  kl_set_nonblocking(int fd, bool nb);

int  kl_ws_connect(kl_ws_conn_t *conn, const kl_config_t *cfg, int timeout_ms);
int  kl_ws_accept_server(kl_ws_conn_t *conn, int client_fd, SSL_CTX *tls_ctx,
                         const kl_config_t *cfg);
void kl_ws_close(kl_ws_conn_t *conn);

int  kl_ws_send_frame(kl_ws_conn_t *conn, uint8_t opcode,
                      const uint8_t *payload, size_t len);
int  kl_ws_send_text(kl_ws_conn_t *conn, const char *text);

/* Reads one complete WebSocket message (handling fragmentation and auto-responding to PING).
 * Returns payload length (>= 0), -1 on error/EOF, -2 on CLOSE frame. */
int  kl_ws_recv_msg(kl_ws_conn_t *conn, uint8_t *opcode_out,
                    uint8_t *buf, size_t buf_cap);

/* Registration shares one read deadline and a bounded number of wire frames. */
int  kl_ws_recv_registration(kl_ws_conn_t *conn, uint8_t *opcode_out, uint8_t *buf, size_t cap);

/* Event-loop variant also returns 0 for standalone PING/PONG after handling it. */
int  kl_ws_recv_event(kl_ws_conn_t *conn, uint8_t *opcode_out, uint8_t *buf, size_t cap);

/* Returns >0 if data is immediately readable (including OpenSSL internal buffer) or becomes readable within timeout_ms.
 * Returns 0 on timeout, -1 on error. */
int  kl_ws_poll_read(kl_ws_conn_t *conn, int wakeup_fd, int timeout_ms, bool *wakeup_ready);

/* Joinable, bounded workers shared by Hub clients and Agent streams. */
#define KL_MAX_WORKERS 128
typedef struct {
    pthread_t tid;
    pthread_mutex_t *mu;
    void *(*run)(void *);
    void *arg;
    bool active, done;
} kl_worker_slot_t;
typedef struct {
    pthread_mutex_t mu;
    kl_worker_slot_t slots[KL_MAX_WORKERS];
} kl_workers_t;
int  kl_workers_init(kl_workers_t *workers);
bool kl_workers_start(kl_workers_t *workers, void *(*run)(void *), void *arg);
void kl_workers_join(kl_workers_t *workers);

/* ---------------- Hub & Agent entrypoints ---------------- */
int  kl_hub_run(const kl_config_t *cfg);
int  kl_agent_run(const kl_config_t *cfg);

/* Global stop flag (set by SIGINT/SIGTERM) */
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal handler requires lock-free atomic int");
extern atomic_int kl_stop_requested;

#endif /* KREAMLINK_H */
