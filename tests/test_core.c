/* Exercise the private session/worker boundaries using real duplex descriptors. */
#include <sys/socket.h>
#include <errno.h>

/* Inject descriptor exhaustion only into accept, without modifying process limits. */
static unsigned accept_failures;
static int accept_for_test(int fd, struct sockaddr *addr, socklen_t *len) {
    if (accept_failures) {
        accept_failures--;
        errno = EMFILE;
        return -1;
    }
    return accept(fd, addr, len);
}
#define accept accept_for_test
#include "../src/ws.c"
#undef accept
#include "../src/hub.c"
#include "../src/agent.c"
#include <assert.h>
#include <limits.h>
#include <signal.h>

atomic_int kl_stop_requested = 0;

static const size_t frame_sizes[] = {0, 1, 125, 126, 65535, KL_MAX_WS_FRAME};
typedef struct {
    kl_ws_conn_t *conn;
    const uint8_t *data;
} writer_arg_t;

static void *write_frames(void *arg) {
    writer_arg_t *writer = arg;
    for (size_t i = 0; i < sizeof(frame_sizes) / sizeof(frame_sizes[0]); i++)
        assert(kl_ws_send_frame(writer->conn, WS_OP_BINARY, writer->data, frame_sizes[i]) == 0);
    return NULL;
}

static void test_frames(void) {
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    kl_ws_conn_t client = { .fd = fd[0], .is_client = true };
    kl_ws_conn_t server = { .fd = fd[1] };
    uint8_t input[KL_MAX_WS_FRAME], output[KL_MAX_WS_FRAME], op;
    for (size_t i = 0; i < sizeof(input); i++) input[i] = (uint8_t)i;
    writer_arg_t writer = {&client, input};
    pthread_t tid;
    assert(pthread_create(&tid, NULL, write_frames, &writer) == 0);
    for (size_t i = 0; i < sizeof(frame_sizes) / sizeof(frame_sizes[0]); i++) {
        size_t n = frame_sizes[i];
        assert(kl_ws_recv_msg(&server, &op, output, sizeof(output)) == (int)n);
        assert(op == WS_OP_BINARY && !memcmp(input, output, n));
    }
    assert(pthread_join(tid, NULL) == 0);
    assert(kl_ws_send_frame(&client, WS_OP_PING, NULL, 0) == 0);
    assert(kl_ws_recv_event(&server, &op, output, sizeof(output)) == 0 && op == WS_OP_PING);
    assert(kl_ws_recv_event(&client, &op, output, sizeof(output)) == 0 && op == WS_OP_PONG);
    /* A control frame between two fragments must preserve message boundaries. */
    const uint8_t fragments[] = {0x01, 1, 'a', 0x89, 1, 'p', 0x80, 1, 'b'};
    assert(write(server.fd, fragments, sizeof(fragments)) == sizeof(fragments));
    assert(kl_ws_recv_msg(&client, &op, output, 2) == 2);
    assert(op == WS_OP_TEXT && !memcmp(output, "ab", 2));
    assert(kl_ws_send_text(&client, "done") == 0);
    assert(kl_ws_recv_msg(&server, &op, output, 4) == 4 && !memcmp(output, "done", 4));

    const uint8_t over_capacity[] = {0x02, 1, 'x', 0x80, 2, 'y', 'z'};
    assert(write(server.fd, over_capacity, sizeof(over_capacity)) == sizeof(over_capacity));
    assert(kl_ws_recv_msg(&client, &op, output, 2) < 0);
    kl_ws_close(&client);
    kl_ws_close(&server);
}

typedef struct {
    pthread_t tid;
    kl_ws_conn_t conn;
} test_peer_t;

static int connect_peer(test_peer_t *peer, const kl_config_t *cfg, SSL_CTX *tls, const char *host) {
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    hub_client_t *c = calloc(1, sizeof(*c));
    assert(c);
    c->client_fd = fd[1];
    c->cfg = cfg;
    c->tls_ctx = tls;
    assert(pipe(c->wake_pipe) == 0);
    assert(kl_set_nonblocking(c->wake_pipe[0], true) == 0);
    assert(kl_set_nonblocking(c->wake_pipe[1], true) == 0);
    assert(pthread_mutex_init(&c->q_mu, NULL) == 0);
    assert(pthread_create(&peer->tid, NULL, hub_client_thread, c) == 0);

    kl_url_t url = {.use_tls = true, .port = 443};
    assert(kl_copy_setting(url.host, sizeof(url.host), host) == 0);
    assert(kl_copy_setting(url.path, sizeof(url.path), cfg->ws_path) == 0);
    return ws_connect_fd(&peer->conn, fd[0], &url, cfg, 3000);
}

static void expect_text(test_peer_t *peer, const char *expected) {
    uint8_t op, buf[256];
    int n = kl_ws_recv_msg(&peer->conn, &op, buf, sizeof(buf) - 1);
    assert(n > 0 && op == WS_OP_TEXT);
    buf[n] = 0;
    assert(strstr((char *)buf, expected));
}

static void subscribe_peer(test_peer_t *peer, const char *role, const char *channel) {
    char req[256];
    snprintf(req, sizeof(req), "{\"action\":\"subscribe\",\"role\":\"%s\",\"channel\":\"%s\"}",
             role, channel);
    assert(kl_ws_send_text(&peer->conn, req) == 0);
}

static void finish_peer(test_peer_t *peer) {
    kl_ws_close(&peer->conn);
    assert(pthread_join(peer->tid, NULL) == 0);
}

static void test_tls_hub(const char *cert, const char *key) {
    kl_config_t cfg;
    kl_config_init(&cfg);
    assert(kl_copy_setting(cfg.tls_cert, sizeof(cfg.tls_cert), cert) == 0);
    assert(kl_copy_setting(cfg.tls_key, sizeof(cfg.tls_key), key) == 0);
    assert(kl_channel_hash_hex("test channel", cfg.allowed_channel_ids[0]) == 0);
    cfg.allowed_token_count = 1;
    SSL_CTX *tls = create_hub_tls_ctx(&cfg);
    assert(tls);

    test_peer_t recv_peer, send_peer, replacement;
    assert(connect_peer(&recv_peer, &cfg, tls, "incorrect.test") != 0);
    finish_peer(&recv_peer);
    assert(connect_peer(&recv_peer, &cfg, tls, "127.0.0.2") != 0);
    finish_peer(&recv_peer);
    assert(connect_peer(&recv_peer, &cfg, tls, "localhost") == 0);
    char hash[KL_CHAN_HASH_HEX_LEN + 1];
    assert(kl_channel_hash_hex("different channel", hash) == 0);
    subscribe_peer(&recv_peer, "recv", hash);
    expect_text(&recv_peer, "\"code\":403");
    finish_peer(&recv_peer);

    memcpy(hash, cfg.allowed_channel_ids[0], sizeof(hash));
    assert(connect_peer(&recv_peer, &cfg, tls, "127.0.0.1") == 0);
    subscribe_peer(&recv_peer, "recv", hash);
    expect_text(&recv_peer, "\"peer_online\":false");
    assert(connect_peer(&send_peer, &cfg, tls, "localhost") == 0);
    subscribe_peer(&send_peer, "send", hash);
    expect_text(&send_peer, "\"peer_online\":true");
    expect_text(&recv_peer, "\"online\":true");
    uint8_t op, buf[64];
    assert(kl_ws_send_frame(&send_peer.conn, WS_OP_BINARY, (const uint8_t *)"hello", 5) == 0);
    assert(kl_ws_recv_msg(&recv_peer.conn, &op, buf, sizeof(buf)) == 5);
    assert(op == WS_OP_BINARY && !memcmp(buf, "hello", 5));

    assert(connect_peer(&replacement, &cfg, tls, "localhost") == 0);
    subscribe_peer(&replacement, "send", hash);
    expect_text(&replacement, "\"peer_online\":false");
    assert(kl_ws_recv_msg(&recv_peer.conn, &op, buf, sizeof(buf)) < 0);
    assert(kl_ws_recv_msg(&send_peer.conn, &op, buf, sizeof(buf)) < 0);
    finish_peer(&recv_peer);
    finish_peer(&send_peer);
    finish_peer(&replacement);
    assert(!g_channels);
    SSL_CTX_free(tls);
}

static int next_command(agent_t *ag, kl_ws_conn_t *tx, kl_ws_conn_t *rx,
                        uint8_t *cmd, uint32_t *sid, uint8_t *data) {
    struct pollfd fds[] = {{ag->wake_pipe[0], POLLIN, 0}, {rx->fd, POLLIN, 0}};
    for (;;) {
        assert(poll(fds, 2, 3000) > 0);
        if (fds[0].revents & POLLIN) assert(flush_agent_queue(ag, tx) == 0);
        if (fds[1].revents & POLLIN) break;
    }
    uint8_t op, buf[KL_MAX_WS_FRAME];
    int n = kl_ws_recv_msg(rx, &op, buf, sizeof(buf));
    assert(n >= 0 && op == WS_OP_BINARY);
    return kl_frame_open(&ag->crypto, buf, (size_t)n, cmd, sid, data, KL_MAX_PAYLOAD);
}

static void feed_command(agent_t *ag, uint8_t cmd, uint32_t sid, const char *payload) {
    uint8_t buf[KL_MAX_WS_FRAME];
    int n = kl_frame_seal(&ag->crypto, cmd, sid, (const uint8_t *)payload, strlen(payload),
                          buf, sizeof(buf));
    assert(n > 0 && handle_mux_frame(ag, buf, (size_t)n) == 0);
}

static void wait_for_workers(agent_t *ag) {
    kl_workers_join(&ag->workers);
    assert(!ag->streams);
}

/* Give the authenticated dispatcher a live stream whose worker is parked. Its small kernel socket buffer cannot hold these frames. */
#define PAUSED_FRAMES 16
static kl_stream_t *make_local_stream(agent_t *ag, int app[2]) {
    int sndbuf = 4096;
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, app));
    assert(!setsockopt(app[1], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)));
    assert(!kl_set_nonblocking(app[1], true));
    kl_stream_t *s = stream_create(ag, 0, app[1]);
    assert(s);
    s->open_ok = true;
    return s;
}

static void queue_paused_stream(agent_t *ag, kl_stream_t *s) {
    uint8_t frame[KL_MAX_WS_FRAME], data[KL_MAX_PAYLOAD];
    s->produced = s->consumed = UINT_MAX - 100;
    for (int i = 0; i < PAUSED_FRAMES; i++) {
        memset(data, i, sizeof(data));
        int n = kl_frame_seal(&ag->crypto, KL_CMD_DATA, s->id, data, sizeof(data), frame, sizeof(frame));
        assert(n > 0 && !handle_mux_frame(ag, frame, (size_t)n));
    }
    feed_command(ag, KL_CMD_EOF, s->id, "");
    assert(s->produced - s->consumed == PAUSED_FRAMES * KL_MAX_PAYLOAD);
}

typedef struct {
    agent_t *ag;
    kl_stream_t *stream;
    int gate[2];
} paused_pump_t;

static void *wait_to_pump(void *arg) {
    paused_pump_t *worker = arg;
    char signal_byte;
    assert(read(worker->gate[0], &signal_byte, 1) == 1);
    pump_stream(worker->ag, worker->stream, worker->stream->local_fd);
    return NULL;
}

static void *read_paused_stream(void *arg) {
    int fd = *(int *)arg;
    uint8_t data[KL_MAX_PAYLOAD];
    for (int i = 0; i < PAUSED_FRAMES; i++) {
        assert(recv(fd, data, sizeof(data), MSG_WAITALL) == sizeof(data));
        for (size_t j = 0; j < sizeof(data); j++) assert(data[j] == i);
    }
    assert(read(fd, data, 1) == 0);
    close(fd);
    return NULL;
}

static void test_local_deadline(agent_t *ag, kl_ws_conn_t *tx, kl_ws_conn_t *rx) {
    int app[2];
    kl_stream_t *s = make_local_stream(ag, app);
    uint8_t data[KL_MAX_PAYLOAD] = {0};
    while (write(app[1], data, sizeof(data)) > 0) {}
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    feed_command(ag, KL_CMD_DATA, s->id, "one queued frame");
    int64_t start = kl_now_ms();
    pump_stream(ag, s, app[1]);
    assert(kl_now_ms() - start >= KL_LOCAL_STALL_MS && s->closed && !ag->session_failed);
    uint8_t cmd;
    uint32_t sid;
    assert(!next_command(ag, tx, rx, &cmd, &sid, data) && cmd == KL_CMD_CLOSE && sid == s->id);
    stream_release(ag, s);
    close(app[0]);
}

static void test_receiver_worker(bool test_isolation) {
    kl_config_t cfg;
    kl_config_init(&cfg);
    cfg.mode = KL_MODE_RECV;
    agent_t ag = {.cfg = &cfg, .ws_connected = true, .peer_online = true};
    assert(!kl_workers_init(&ag.workers));
    assert(!pthread_mutex_init(&ag.mu, NULL));
    assert(!pthread_cond_init(&ag.q_cv, NULL));
    assert(!pthread_cond_init(&ag.peer_cv, NULL));
    assert(pipe(ag.wake_pipe) == 0);
    assert(kl_set_nonblocking(ag.wake_pipe[0], true) == 0);
    assert(kl_set_nonblocking(ag.wake_pipe[1], true) == 0);
    assert(kl_crypto_init(&ag.crypto, "test secret", 192) == 0);
    int fd[2], app[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    kl_ws_conn_t tx = {.fd = fd[0], .is_client = true}, rx = {.fd = fd[1]};
    int paused_app[2];
    kl_stream_t *paused = NULL;
    paused_pump_t pump = {.ag = &ag};
    pthread_t parked;
    if (test_isolation) {
        paused = make_local_stream(&ag, paused_app);
        pump.stream = paused;
        assert(!pipe(pump.gate));
        assert(!pthread_create(&parked, NULL, wait_to_pump, &pump));
        queue_paused_stream(&ag, paused);
    }
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, app) == 0);
    assert(start_worker(&ag, app[1], NULL));
    uint8_t cmd, data[KL_MAX_PAYLOAD];
    uint32_t sid, id;
    assert(next_command(&ag, &tx, &rx, &cmd, &sid, data) == 0 && cmd == KL_CMD_OPEN);
    feed_command(&ag, KL_CMD_OPEN_OK, sid, "");
    assert(write(app[0], "abc", 3) == 3);
    assert(next_command(&ag, &tx, &rx, &cmd, &id, data) == 3 && cmd == KL_CMD_DATA && id == sid);
    assert(!memcmp(data, "abc", 3));
    feed_command(&ag, KL_CMD_DATA, sid, "reply");
    assert(recv(app[0], data, 5, MSG_WAITALL) == 5 && !memcmp(data, "reply", 5));
    bool half_closed = shutdown(app[0], SHUT_WR) == 0;
    if (!half_closed) {
        assert(errno == EPERM);
        puts("SKIP kernel half-close check: shutdown(2) is denied");
        close(app[0]);
    }
    assert(next_command(&ag, &tx, &rx, &cmd, &id, data) == 0 && cmd == KL_CMD_EOF && id == sid);
    if (half_closed) {
        feed_command(&ag, KL_CMD_DATA, sid, "late");
        assert(recv(app[0], data, 4, MSG_WAITALL) == 4 && !memcmp(data, "late", 4));
    }
    feed_command(&ag, KL_CMD_EOF, sid, "");
    kl_workers_join(&ag.workers);
    assert(ag.streams == paused);
    if (paused) {
        pthread_t reader;
        assert(!pthread_create(&reader, NULL, read_paused_stream, &paused_app[0]));
        assert(write(pump.gate[1], "x", 1) == 1);
        assert(!pthread_join(parked, NULL));
        close(pump.gate[0]);
        close(pump.gate[1]);
        assert(!pthread_join(reader, NULL));
        assert(paused->consumed == paused->produced && !paused->reset_on_close);
        assert(!next_command(&ag, &tx, &rx, &cmd, &id, data) && cmd == KL_CMD_EOF && id == paused->id);
        stream_release(&ag, paused);
        test_local_deadline(&ag, &tx, &rx);
    }
    if (half_closed) {
        assert(read(app[0], data, 1) == 0);
        close(app[0]);
    }

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, app) == 0);
    assert(start_worker(&ag, app[1], NULL));
    assert(next_command(&ag, &tx, &rx, &cmd, &sid, data) == 0 && cmd == KL_CMD_OPEN);
    stream_close_all(&ag);
    wait_for_workers(&ag);
    assert(read(app[0], data, 1) == 0);
    close(app[0]);
    kl_ws_close(&tx);
    kl_ws_close(&rx);
    close(ag.wake_pipe[0]);
    close(ag.wake_pipe[1]);
    pthread_cond_destroy(&ag.peer_cv);
    pthread_cond_destroy(&ag.q_cv);
    pthread_mutex_destroy(&ag.workers.mu);
    pthread_mutex_destroy(&ag.mu);
}

static void test_addresses(void) {
    char host[256];
    uint16_t port;
    assert(kl_parse_hostport(":8080", host, sizeof(host), &port) == 0 && port == 8080);
    assert(!strcmp(host, "0.0.0.0"));
    assert(kl_parse_hostport("[::1]:443", host, sizeof(host), &port) == 0 && port == 443);
    assert(!strcmp(host, "::1"));
    assert(kl_parse_hostport("host:80extra", host, sizeof(host), &port) < 0);
    kl_url_t url;
    assert(kl_parse_url("wss://[::1]:443", &url) == 0 && !strcmp(url.path, "/"));
    assert(kl_parse_url("ws://localhost?q=1", &url) == 0 && !strcmp(url.path, "/?q=1"));
    assert(kl_parse_url("ws://[::1]junk/", &url) < 0);
    assert(kl_parse_url("ws://host:65536/", &url) < 0);
}

static void test_authenticated_frames(void) {
    kl_crypto_t sender, other;
    assert(kl_crypto_init(&sender, "frame test", KL_MAX_PADDING) == 0);
    assert(kl_crypto_init(&other, "different key", 0) == 0);
    uint8_t input[KL_MAX_PAYLOAD], sealed[KL_MAX_WS_FRAME], output[KL_MAX_PAYLOAD];
    for (size_t i = 0; i < sizeof(input); i++) input[i] = (uint8_t)i;
    const size_t lengths[] = {0, 1, sizeof(input)};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        size_t len = lengths[i];
        int n = kl_frame_seal(&sender, KL_CMD_DATA, 7, input, len, sealed, sizeof(sealed));
        uint32_t sid = 0;
        uint8_t cmd = 0;
        assert(n > 0);
        assert(kl_frame_open(&sender, sealed, (size_t)n, &cmd, &sid, output, sizeof(output)) == (int)len);
        assert(cmd == KL_CMD_DATA && sid == 7 && !memcmp(input, output, len));
        memset(output, 0xa5, sizeof(output));
        cmd = 42;
        sid = 99;
        assert(kl_frame_open(&other, sealed, (size_t)n, &cmd, &sid, output, sizeof(output)) < 0);
        sealed[4 + KL_NONCE_LEN] ^= 1;
        assert(kl_frame_open(&sender, sealed, (size_t)n, &cmd, &sid, output, sizeof(output)) < 0);
        assert(cmd == 42 && sid == 99);
        for (size_t j = 0; j < sizeof(output); j++) assert(output[j] == 0xa5);
    }
}

static void test_control_messages(void) {
    char response[] = " { \"peer_online\" : true, \"status\" : \"ok\", \"ts\": 123 }\r\n";
    kl_control_t msg;
    assert(kl_control_parse(response, sizeof(response) - 1, &msg));
    assert(msg.status && !strcmp(msg.status, "ok") && msg.peer_online == 1 && msg.online == -1);

    const char *bad[] = {
        "{\"online\":false,\"online\":true}", "{\"online\":\"false\"}",
        "{\"type\":\"peer\"} extra", "{\"online\" false}", "{\"type\":\"peer\",}",
        "{\"status\":true}", "{\"role\":\"recv}", "{\"ts\":01}"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char input[128];
        strcpy(input, bad[i]);
        assert(!kl_control_parse(input, strlen(input), &msg));
    }
    char embedded_nul[] = "{\"status\":\"ok\"}\0tail";
    assert(!kl_control_parse(embedded_nul, sizeof(embedded_nul) - 1, &msg));
}

static void test_allowlist(void) {
    char path[] = "/tmp/kreamlink-allowlist-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "w");
    assert(f);
    char first[65], second[65], unintended[65];
    assert(!kl_channel_hash_hex("test secret one", first));
    assert(!kl_channel_hash_hex("test secret two", second));
    assert(!kl_channel_hash_hex(second, unintended));
    assert(fprintf(f, "allowed_tokens:\n  - test secret one\n  - %s\n", second) > 0);
    assert(!fclose(f));
    kl_config_t cfg;
    kl_config_init(&cfg);
    assert(!kl_config_load_yaml(&cfg, path));
    assert(!unlink(path));
    assert(cfg.allowed_token_count == 2);
    assert(token_is_allowed(&cfg, first) && token_is_allowed(&cfg, second));
    assert(!token_is_allowed(&cfg, unintended));
}

static void test_write_deadline(void) {
    int fd[2], size = 4096;
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
    assert(!setsockopt(fd[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)));
    char data[4096] = {0};
    assert(!kl_set_nonblocking(fd[0], true));
    while (write(fd[0], data, sizeof(data)) > 0) {}
    assert(errno == EWOULDBLOCK || errno == EAGAIN);
    int64_t start = kl_now_ms();
    assert(kl_tcp_write_all(fd[0], (const uint8_t *)data, sizeof(data), 100) < 0);
    assert(kl_now_ms() - start >= 90);
    close(fd[0]);
    close(fd[1]);
}

/* Use an actual loopback listener in the TCP suite, leaving the socketpair
 * tests usable on systems without permission to bind an Internet socket. */
static void test_accept_recovery(void) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(listener, 1) == 0 && kl_set_nonblocking(listener, true) == 0);
    socklen_t len = sizeof(addr);
    assert(getsockname(listener, (struct sockaddr *)&addr, &len) == 0);
    int client = socket(AF_INET, SOCK_STREAM, 0);
    assert(client >= 0 && connect(client, (struct sockaddr *)&addr, len) == 0);
    accept_failures = 2;
    int64_t start = kl_now_ms();
    int server = kl_tcp_accept(listener);
    assert(server >= 0 && accept_failures == 0 && kl_now_ms() - start >= 190);
    close(server);
    close(client);
    close(listener);
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--test-isolation")) {
        signal(SIGPIPE, SIG_IGN);
        alarm(45);
        test_receiver_worker(true);
        puts("Paused worker, ordered half-close, counter wrap and stalled write deadline passed.");
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--test-accept")) {
        alarm(5);
        test_accept_recovery();
        return 0;
    }
    assert(argc == 3);
    signal(SIGPIPE, SIG_IGN);
    alarm(45);
    kl_log_set_level(KL_LOG_ERROR);
    test_authenticated_frames();
    test_control_messages();
    test_allowlist();
    test_write_deadline();
    test_addresses();
    test_frames();
    test_tls_hub(argv[1], argv[2]);
    test_receiver_worker(false);
    puts("Frame, verified TLS, Hub pairing and receiver worker tests passed.");
    return 0;
}
