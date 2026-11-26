#include "kreamlink.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define KL_AGENT_QUEUE_MAX 512
#define KL_LOCAL_BUFFER_SIZE (1024u * 1024u)
#define KL_LOCAL_STALL_MS 15000
_Static_assert((KL_LOCAL_BUFFER_SIZE & (KL_LOCAL_BUFFER_SIZE - 1)) == 0,
               "stream ring capacity must be a power of two");

typedef struct out_frame {
    uint8_t opcode;
    size_t  len;
    struct out_frame *next;
    uint8_t data[];
} out_frame_t;

typedef struct kl_stream {
    uint32_t id;
    int      local_fd;   /* Closed ONLY when refcount reaches 0 (prevents FD-reuse race) */
    bool     open_done;
    bool     open_ok;
    atomic_bool remote_eof;
    atomic_bool closed;
    bool reset_on_close;
    /* Only the WS thread publishes bytes; only the stream worker consumes them.
     * Unsigned subtraction gives the occupancy even across counter wrap. */
    atomic_uint produced;
    atomic_uint consumed;
    uint8_t *local_buf;
    int wake_pipe[2];
    atomic_uint refcount;
    pthread_cond_t open_cv;
    struct kl_stream *next;
} kl_stream_t;

typedef struct {
    const kl_config_t *cfg;
    kl_crypto_t crypto;

    pthread_mutex_t mu;
    pthread_cond_t  peer_cv;
    pthread_cond_t  q_cv; /* Backpressure condition variable */

    bool ws_connected;
    bool peer_online;
    bool session_failed;
    kl_workers_t workers;
    uint32_t next_stream_id;

    int wake_pipe[2];
    out_frame_t *q_head;
    out_frame_t *q_tail;
    int q_count;

    kl_stream_t *streams;
    bool listener_failed;
    int listen_fd; /* Permanent port-holding socket in RECV mode */
} agent_t;

static void wake_fd(int fd) {
    uint8_t b = 1;
    ssize_t r;
    do {
        r = write(fd, &b, 1);
    } while (r < 0 && errno == EINTR);
}

/* ag->mu is held. A reset wakes both pre-open and established workers. */
static void stream_cancel_locked(agent_t *ag, kl_stream_t *s, bool reset) {
    s->reset_on_close |= reset;
    s->closed = true;
    pthread_cond_broadcast(&s->open_cv);
    pthread_cond_broadcast(&ag->q_cv);
    wake_fd(s->wake_pipe[1]);
}

/* Enqueue frame with true backpressure (never silently drops bytes mid-stream).
 * Returns 0 on success, -1 if disconnected or stopped. */
static int agent_send_mux(agent_t *ag, kl_stream_t *stream, uint8_t cmd, uint32_t sid,
                          const uint8_t *data, size_t len) {
    uint8_t sealed[4 + KL_NONCE_LEN + KL_TAG_LEN + KL_MUX_HDR_LEN + KL_MAX_PAYLOAD + KL_MAX_PADDING];
    int n = kl_frame_seal(&ag->crypto, cmd, sid, data, len, sealed, sizeof(sealed));
    out_frame_t *f = NULL;
    if (n >= 0) {
        f = malloc(sizeof(*f) + (size_t)n);
        if (f) {
            f->opcode = WS_OP_BINARY;
            f->len = (size_t)n;
            f->next = NULL;
            memcpy(f->data, sealed, f->len);
        }
    }

    pthread_mutex_lock(&ag->mu);
    while (f && cmd == KL_CMD_DATA && ag->q_count >= KL_AGENT_QUEUE_MAX &&
           ag->ws_connected && !ag->session_failed && !stream->closed && !kl_stop_requested) {
        pthread_cond_wait(&ag->q_cv, &ag->mu);
    }
    if (!ag->ws_connected || ag->session_failed || (stream && stream->closed) || kl_stop_requested) {
        pthread_mutex_unlock(&ag->mu);
        free(f);
        return -1;
    }
    /* Commit CLOSE and exclude subsequent local DATA in the same critical section. */
    if (cmd == KL_CMD_CLOSE) stream_cancel_locked(ag, stream, true);
    if (!f || ag->q_count >= KL_AGENT_QUEUE_MAX + KL_MAX_WORKERS) {
        ag->session_failed = true;
        pthread_cond_broadcast(&ag->q_cv);
        pthread_mutex_unlock(&ag->mu);
        free(f);
        wake_fd(ag->wake_pipe[1]);
        return -1;
    }
    if (ag->q_tail) ag->q_tail->next = f;
    else ag->q_head = f;
    ag->q_tail = f;
    ag->q_count++;
    pthread_mutex_unlock(&ag->mu);
    wake_fd(ag->wake_pipe[1]);
    return 0;
}

/* The final owner closes the descriptors outside the session lock. */
static void stream_unref(kl_stream_t *s) {
    if (atomic_fetch_sub_explicit(&s->refcount, 1, memory_order_acq_rel) != 1) return;
    if (s->local_fd >= 0) {
        if (s->reset_on_close) {
            struct linger reset = {.l_onoff = 1, .l_linger = 0};
            setsockopt(s->local_fd, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset));
        }
        close(s->local_fd);
    }
    close(s->wake_pipe[0]);
    close(s->wake_pipe[1]);
    free(s->local_buf);
    pthread_cond_destroy(&s->open_cv);
    free(s);
}

static kl_stream_t *stream_create(agent_t *ag, uint32_t id, int local_fd) {
    kl_stream_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->local_fd = local_fd;
    atomic_init(&s->refcount, 2); /* 1 for table + 1 for caller */
    if (pthread_cond_init(&s->open_cv, NULL) != 0) {
        free(s);
        return NULL;
    }

    atomic_init(&s->remote_eof, false);
    atomic_init(&s->closed, false);
    atomic_init(&s->produced, 0);
    atomic_init(&s->consumed, 0);
    if (pipe(s->wake_pipe) != 0) goto fail;
    if (kl_set_nonblocking(s->wake_pipe[0], true) != 0 ||
        kl_set_nonblocking(s->wake_pipe[1], true) != 0) goto fail_pipe;

    pthread_mutex_lock(&ag->mu);
    if (!ag->ws_connected || !ag->peer_online || kl_stop_requested) {
        pthread_mutex_unlock(&ag->mu);
        goto fail_pipe;
    }
    if (local_fd >= 0) {
        /* Keep zero reserved and skip live IDs if the counter wraps. */
        bool in_use;
        do {
            id = ++ag->next_stream_id;
            in_use = id == 0;
            for (kl_stream_t *it = ag->streams; it && !in_use; it = it->next)
                in_use = it->id == id;
        } while (in_use);
    }
    s->id = id;
    s->next = ag->streams;
    ag->streams = s;
    pthread_mutex_unlock(&ag->mu);
    return s;

fail_pipe:
    close(s->wake_pipe[0]);
    close(s->wake_pipe[1]);
fail:
    pthread_cond_destroy(&s->open_cv);
    free(s);
    return NULL;
}

static kl_stream_t *stream_find_ref(agent_t *ag, uint32_t id) {
    pthread_mutex_lock(&ag->mu);
    kl_stream_t *s = ag->streams;
    while (s) {
        if (s->id == id && !s->closed) {
            atomic_fetch_add_explicit(&s->refcount, 1, memory_order_relaxed);
            break;
        }
        s = s->next;
    }
    pthread_mutex_unlock(&ag->mu);
    return s;
}

static void stream_release(agent_t *ag, kl_stream_t *target) {
    pthread_mutex_lock(&ag->mu);
    kl_stream_t **pp = &ag->streams;
    while (*pp) {
        if (*pp == target) {
            *pp = target->next;
            target->next = NULL;
            /* The worker still pins the stream while we drop the table reference. */
            atomic_fetch_sub_explicit(&target->refcount, 1, memory_order_relaxed);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&ag->mu);
    stream_unref(target);
}

static void stream_close_all(agent_t *ag) {
    pthread_mutex_lock(&ag->mu);
    for (kl_stream_t *s = ag->streams; s; s = s->next)
        stream_cancel_locked(ag, s, false);
    pthread_mutex_unlock(&ag->mu);
}

/* The producer never waits for space or takes a lock owned by the writer.
 * A release-store publishes complete frames only. The worker keeps its share
 * of the buffer until write() has accepted the corresponding bytes. */
static bool queue_local_data(kl_stream_t *s, const uint8_t *data, unsigned len) {
    unsigned head = atomic_load_explicit(&s->produced, memory_order_relaxed);
    unsigned tail = atomic_load_explicit(&s->consumed, memory_order_acquire);
    if (len > KL_LOCAL_BUFFER_SIZE - (head - tail)) return false;
    if (!s->local_buf) {
        s->local_buf = malloc(KL_LOCAL_BUFFER_SIZE);
        if (!s->local_buf) return false;
    }
    unsigned offset = head % KL_LOCAL_BUFFER_SIZE;
    unsigned first = KL_LOCAL_BUFFER_SIZE - offset;
    if (first > len) first = len;
    memcpy(s->local_buf + offset, data, first);
    memcpy(s->local_buf, data + first, len - first);
    atomic_store_explicit(&s->produced, head + len, memory_order_release);
    wake_fd(s->wake_pipe[1]);
    return true;
}

static void pump_stream(agent_t *ag, kl_stream_t *s, int fd) {
    bool read_eof = false, write_eof = false;
    unsigned tail = atomic_load_explicit(&s->consumed, memory_order_relaxed);
    int64_t deadline = 0;
    uint8_t buf[KL_MAX_PAYLOAD];

    while (!kl_stop_requested && !s->closed) {
        /* Read EOF before head: seeing EOF must also expose all preceding DATA. */
        bool eof = atomic_load_explicit(&s->remote_eof, memory_order_acquire);
        unsigned head = atomic_load_explicit(&s->produced, memory_order_acquire);
        unsigned pending = head - tail;
        if (eof && !pending) {
            if (read_eof) return;
            if (!write_eof) {
                if (shutdown(fd, SHUT_WR) != 0) break;
                write_eof = true;
            }
        }

        int timeout = -1;
        if (pending) {
            int64_t now = kl_now_ms();
            if (!deadline) deadline = now + KL_LOCAL_STALL_MS;
            if (deadline <= now) {
                KL_WARN("Stream #%u: local write stalled", s->id);
                break;
            }
            timeout = (int)(deadline - now);
        } else {
            deadline = 0;
        }

        short events = (read_eof ? 0 : POLLIN) | (pending ? POLLOUT : 0);
        struct pollfd fds[] = {
            {.fd = events ? fd : -1, .events = events},
            {.fd = s->wake_pipe[0], .events = POLLIN}
        };
        if (poll(fds, 2, timeout) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (fds[1].revents & POLLIN) {
            uint8_t signals[256];
            (void)read(s->wake_pipe[0], signals, sizeof(signals));
        }
        if (s->closed || kl_stop_requested) return;
        if (fds[0].revents & (POLLNVAL | POLLERR)) break;
        if (pending && (fds[0].revents & (POLLOUT | POLLHUP))) {
            unsigned offset = tail % KL_LOCAL_BUFFER_SIZE;
            unsigned chunk = KL_LOCAL_BUFFER_SIZE - offset;
            if (chunk > pending) chunk = pending;
            ssize_t n = write(fd, s->local_buf + offset, chunk);
            if (n > 0) {
                tail += (unsigned)n;
                atomic_store_explicit(&s->consumed, tail, memory_order_release);
                deadline = (unsigned)n == pending ? 0 : kl_now_ms() + KL_LOCAL_STALL_MS;
            } else if (n == 0 || (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)) {
                break;
            }
        }
        if (!read_eof && (fds[0].revents & (POLLIN | POLLHUP))) {
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                break;
            }
            read_eof = n == 0;
            uint8_t cmd = read_eof ? KL_CMD_EOF : KL_CMD_DATA;
            if (agent_send_mux(ag, s, cmd, s->id, buf, (size_t)n) != 0) return;
        }
    }
    if (!s->closed && !kl_stop_requested)
        agent_send_mux(ag, s, KL_CMD_CLOSE, s->id, NULL, 0);
}

/* ---------------- Receiver local stream worker (permanent port-holder) ---------------- */
typedef struct {
    agent_t *ag;
    int local_fd;
    kl_stream_t *stream;
} worker_arg_t;

static void recv_stream(agent_t *ag, int lfd) {
    if (kl_set_nonblocking(lfd, true) != 0) {
        close(lfd);
        return;
    }
    kl_set_tcp_nodelay(lfd);

    /* Wait briefly if remote sender is temporarily reconnecting */
    pthread_mutex_lock(&ag->mu);
    if (!(ag->ws_connected && ag->peer_online) && ag->cfg->wait_peer_ms > 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        long add_ms = ag->cfg->wait_peer_ms;
        ts.tv_sec += add_ms / 1000;
        ts.tv_nsec += (add_ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }
        while (!(ag->ws_connected && ag->peer_online) && !kl_stop_requested) {
            int rc = pthread_cond_timedwait(&ag->peer_cv, &ag->mu, &ts);
            if (rc != 0) break;
        }
    }

    if (!(ag->ws_connected && ag->peer_online) || kl_stop_requested) {
        pthread_mutex_unlock(&ag->mu);
        KL_WARN("Local connection closed: remote sender is offline (local port stays held)");
        close(lfd);
        return;
    }

    pthread_mutex_unlock(&ag->mu);

    kl_stream_t *s = stream_create(ag, 0, lfd);
    if (!s) {
        close(lfd);
        return;
    }

    uint32_t sid = s->id;
    KL_DEBUG("Stream #%u: opening tunnel to remote sender", sid);
    if (agent_send_mux(ag, s, KL_CMD_OPEN, sid, NULL, 0) != 0) {
        stream_release(ag, s);
        return;
    }

    /* Wait for Sender's OPEN_OK / OPEN_FAIL */
    pthread_mutex_lock(&ag->mu);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 10;
    while (!s->open_done && !s->closed && !kl_stop_requested) {
        int rc = pthread_cond_timedwait(&s->open_cv, &ag->mu, &ts);
        if (rc != 0) break;
    }
    bool ok = s->open_ok && !s->closed;
    pthread_mutex_unlock(&ag->mu);

    if (!ok) {
        KL_WARN("Stream #%u: remote target open failed or timed out", sid);
        agent_send_mux(ag, s, KL_CMD_CLOSE, sid, NULL, 0);
        stream_release(ag, s);
        return;
    }

    KL_DEBUG("Stream #%u: established", sid);
    pump_stream(ag, s, lfd);
    stream_release(ag, s);
    KL_DEBUG("Stream #%u: closed", sid);
}

static void send_stream(agent_t *ag, kl_stream_t *s);

static void *run_worker(void *arg) {
    worker_arg_t *work = arg;
    agent_t *ag = work->ag;
    if (work->stream) send_stream(ag, work->stream);
    else recv_stream(ag, work->local_fd);
    free(work);
    return NULL;
}

static bool start_worker(agent_t *ag, int fd, kl_stream_t *s) {
    worker_arg_t *work = malloc(sizeof(*work));
    if (!work) return false;
    *work = (worker_arg_t){ .ag = ag, .local_fd = fd, .stream = s };
    if (kl_stop_requested || !kl_workers_start(&ag->workers, run_worker, work)) {
        free(work);
        return false;
    }
    return true;
}

/* Permanent port-holding accept thread (runs for the entire lifetime of Receiver) */
static void *recv_listen_thread(void *arg) {
    agent_t *ag = (agent_t *)arg;
    while (!kl_stop_requested) {
        int lfd = kl_tcp_accept(ag->listen_fd);
        if (lfd < 0) {
            if (!kl_stop_requested) {
                ag->listener_failed = true;
                kl_stop_requested = 1;
            }
            break;
        }
        if (!start_worker(ag, lfd, NULL)) close(lfd);
    }
    return NULL;
}

/* ---------------- Sender on-demand target dialer ---------------- */
static void send_stream(agent_t *ag, kl_stream_t *s) {
    uint32_t sid = s->id;
    char host[256];
    uint16_t port = 0;
    int tfd = -1;
    if (kl_parse_hostport(ag->cfg->target_addr, host, sizeof(host), &port) == 0) {
        tfd = kl_tcp_connect(host, port, 5000);
    }

    if (tfd >= 0 && kl_set_nonblocking(tfd, true) != 0) {
        close(tfd);
        tfd = -1;
    }
    if (tfd < 0) {
        KL_WARN("Stream #%u: failed to connect to target %s", sid, ag->cfg->target_addr);
        agent_send_mux(ag, s, KL_CMD_OPEN_FAIL, sid, NULL, 0);
        stream_release(ag, s);
        return;
    }

    pthread_mutex_lock(&ag->mu);
    bool aborted = s->closed;
    if (!aborted) {
        s->local_fd = tfd;
        s->open_done = true;
        s->open_ok = true;
    }
    pthread_mutex_unlock(&ag->mu);

    if (aborted) {
        close(tfd);
        stream_release(ag, s);
        return;
    }

    KL_DEBUG("Stream #%u: connected to target %s", sid, ag->cfg->target_addr);
    if (agent_send_mux(ag, s, KL_CMD_OPEN_OK, sid, NULL, 0) == 0)
        pump_stream(ag, s, tfd);
    stream_release(ag, s);
    KL_DEBUG("Stream #%u: target connection closed", sid);
}

/* ---------------- Dispatch decrypted binary mux frame ---------------- */
static int handle_mux_frame(agent_t *ag, const uint8_t *raw, size_t raw_len) {
    uint8_t cmd = 0;
    uint32_t sid = 0;
    uint8_t plain[KL_MAX_PAYLOAD];

    int dlen = kl_frame_open(&ag->crypto, raw, raw_len, &cmd, &sid, plain, sizeof(plain));
    if (dlen < 0) {
        KL_WARN("Closing session after frame authentication failure");
        return -1;
    }

    if (!sid || (cmd != KL_CMD_DATA && dlen != 0)) return -1;

    switch (cmd) {
        case KL_CMD_OPEN: {
            if (ag->cfg->mode != KL_MODE_SEND) return 0;
            kl_stream_t *s = stream_find_ref(ag, sid);
            if (s) {
                stream_unref(s);
                return 0;
            }
            s = stream_create(ag, sid, -1);
            if (!s) {
                agent_send_mux(ag, s, KL_CMD_OPEN_FAIL, sid, NULL, 0);
                return 0;
            }
            if (!start_worker(ag, -1, s)) {
                agent_send_mux(ag, s, KL_CMD_OPEN_FAIL, sid, NULL, 0);
                stream_release(ag, s);
            }
            break;
        }
        case KL_CMD_OPEN_OK:
        case KL_CMD_OPEN_FAIL: {
            kl_stream_t *s = stream_find_ref(ag, sid);
            if (!s) return 0;
            pthread_mutex_lock(&ag->mu);
            if (ag->cfg->mode == KL_MODE_RECV && !s->open_done) {
                s->open_done = true;
                s->open_ok = (cmd == KL_CMD_OPEN_OK);
            }
            pthread_cond_broadcast(&s->open_cv);
            pthread_mutex_unlock(&ag->mu);
            stream_unref(s);
            break;
        }
        case KL_CMD_DATA: {
            kl_stream_t *s = stream_find_ref(ag, sid);
            if (!s) return 0;
            pthread_mutex_lock(&ag->mu);
            bool deliver = s->open_ok && !s->closed && !s->remote_eof;
            pthread_mutex_unlock(&ag->mu);
            if (deliver && dlen > 0 && !queue_local_data(s, plain, (unsigned)dlen)) {
                KL_WARN("Stream #%u: local write buffer unavailable or full", sid);
                agent_send_mux(ag, s, KL_CMD_CLOSE, sid, NULL, 0);
            }
            stream_unref(s);
            break;
        }
        case KL_CMD_EOF: {
            kl_stream_t *s = stream_find_ref(ag, sid);
            if (!s) return 0;
            atomic_store_explicit(&s->remote_eof, true, memory_order_release);
            wake_fd(s->wake_pipe[1]);
            stream_unref(s);
            break;
        }
        case KL_CMD_CLOSE: {
            kl_stream_t *s = stream_find_ref(ag, sid);
            if (!s) return 0;
            pthread_mutex_lock(&ag->mu);
            stream_cancel_locked(ag, s, true);
            pthread_mutex_unlock(&ag->mu);
            stream_unref(s);
            break;
        }
        default:
            return -1;
    }
    return 0;
}

static int flush_agent_queue(agent_t *ag, kl_ws_conn_t *conn) {
    uint8_t drain[64];
    while (read(ag->wake_pipe[0], drain, sizeof(drain)) > 0) {}

    for (unsigned batch = 0; batch < 16; batch++) {
        pthread_mutex_lock(&ag->mu);
        if (ag->session_failed) {
            pthread_mutex_unlock(&ag->mu);
            return -1;
        }
        out_frame_t *f = ag->q_head;
        if (f) {
            ag->q_head = f->next;
            if (!ag->q_head) ag->q_tail = NULL;
            ag->q_count--;
            if (ag->q_count < KL_AGENT_QUEUE_MAX / 2) {
                pthread_cond_broadcast(&ag->q_cv);
            }
        }
        pthread_mutex_unlock(&ag->mu);

        if (!f) return 0;
        int rc = kl_ws_send_frame(conn, f->opcode, f->data, f->len);
        free(f);
        if (rc != 0) return -1;
    }
    wake_fd(ag->wake_pipe[1]); /* Continue draining after servicing incoming frames. */
    return 0;
}

static void clear_agent_queue(agent_t *ag) {
    pthread_mutex_lock(&ag->mu);
    out_frame_t *f = ag->q_head;
    while (f) {
        out_frame_t *nx = f->next;
        free(f);
        f = nx;
    }
    ag->q_head = ag->q_tail = NULL;
    ag->q_count = 0;
    pthread_cond_broadcast(&ag->q_cv);
    pthread_mutex_unlock(&ag->mu);
}

/* Exponential backoff sleep with +-20% jitter, interruptible every 100ms */
static void sleep_backoff_jitter(int base_sec) {
    int base_ms = base_sec * 1000;
    uint8_t r = 128;
    kl_random_bytes(&r, 1);
    /* Scale jitter to [-20%, +20%] */
    int jitter_ms = ((int)r - 128) * (base_ms / 5) / 128;
    int total_ms = base_ms + jitter_ms;
    if (total_ms < 200) total_ms = 200;

    int slices = total_ms / 100;
    for (int i = 0; i < slices && !kl_stop_requested; i++) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000000L };
        nanosleep(&ts, NULL);
    }
}

int kl_agent_run(const kl_config_t *cfg) {
    agent_t ag;
    memset(&ag, 0, sizeof(ag));
    ag.cfg = cfg;
    ag.listen_fd = -1;
    ag.wake_pipe[0] = ag.wake_pipe[1] = -1;
    int result = -1;
    if (pthread_mutex_init(&ag.mu, NULL) != 0) return -1;
    if (pthread_cond_init(&ag.peer_cv, NULL) != 0) goto destroy_mutex;
    if (pthread_cond_init(&ag.q_cv, NULL) != 0) goto destroy_peer_cv;

    if (kl_workers_init(&ag.workers) != 0) goto destroy_q_cv;
    uint8_t *rx_buf = malloc(KL_MAX_WS_FRAME + 1);
    if (!rx_buf) goto cleanup;
    if (kl_crypto_init(&ag.crypto, cfg->channel, cfg->padding_max) != 0) {
        KL_ERROR("Failed to initialize E2EE crypto context");
        goto cleanup;
    }
    if (pipe(ag.wake_pipe) != 0 || kl_set_nonblocking(ag.wake_pipe[0], true) != 0 ||
        kl_set_nonblocking(ag.wake_pipe[1], true) != 0) {
        KL_ERROR("Failed to create nonblocking wakeup pipe");
        goto cleanup;
    }

    /* CRITICAL: In RECV mode, bind and hold the local listening port IMMEDIATELY
     * and PERMANENTLY — regardless of whether Hub or remote Sender is online!
     * Local apps on the receiver machine can always point to this fixed port. */
    pthread_t listen_tid;
    bool has_listener = false;
    if (cfg->mode == KL_MODE_RECV) {
        ag.listen_fd = kl_tcp_listen(cfg->listen_addr);
        if (ag.listen_fd < 0) goto cleanup;
        KL_INFO("Receiver holding local port %s permanently (channel=%.12s..)",
                cfg->listen_addr, ag.crypto.channel_hash);
        if (pthread_create(&listen_tid, NULL, recv_listen_thread, &ag) != 0) {
            goto cleanup;
        }
        has_listener = true;
    } else {
        KL_INFO("Sender started: exposing target=%s (channel=%.12s..)",
                cfg->target_addr, ag.crypto.channel_hash);
    }


    int backoff = 1;
    unsigned long reconnect_attempts = 0;
    const int64_t hb_interval_ms = (int64_t)cfg->heartbeat_sec * 1000LL;
    const int64_t dead_timeout_ms = hb_interval_ms * 3; /* 3 missed heartbeats => force reconnect */

    while (!kl_stop_requested) {
        kl_ws_conn_t conn;
        reconnect_attempts++;
        KL_INFO("Connecting to Hub %s (attempt #%lu) ...", cfg->hub_url, reconnect_attempts);
        if (kl_ws_connect(&conn, cfg, 10000) != 0) {
            KL_WARN("Hub connection failed; retrying in ~%ds%s",
                    backoff, cfg->mode == KL_MODE_RECV ? " (local port still held)" : "");
            sleep_backoff_jitter(backoff);
            if (backoff < 30) backoff *= 2;
            continue;
        }

        /* Layer 2: Fake business subscribe handshake */
        char hs[512];
        snprintf(hs, sizeof(hs),
                 "{\"action\":\"subscribe\",\"topic\":\"market_ticker\","
                 "\"channel\":\"%s\",\"role\":\"%s\",\"ts\":%ld}",
                 ag.crypto.channel_hash,
                 cfg->mode == KL_MODE_SEND ? "send" : "recv",
                 (long)time(NULL));
        if (kl_ws_send_text(&conn, hs) != 0) {
            kl_ws_close(&conn);
            sleep_backoff_jitter(backoff);
            if (backoff < 30) backoff *= 2;
            continue;
        }

        uint8_t op = 0;
        int n = kl_ws_recv_msg(&conn, &op, rx_buf, KL_MAX_WS_FRAME);
        if (n <= 0 || op != WS_OP_TEXT) {
            KL_WARN("Hub handshake failed");
            kl_ws_close(&conn);
            sleep_backoff_jitter(backoff);
            if (backoff < 30) backoff *= 2;
            continue;
        }
        kl_control_t msg;
        if (!kl_control_parse((char *)rx_buf, (size_t)n, &msg) ||
            !msg.status || strcmp(msg.status, "ok") || msg.peer_online < 0) {
            KL_ERROR("Hub rejected registration or sent an invalid response");
            kl_ws_close(&conn);
            sleep_backoff_jitter(backoff);
            if (backoff < 30) backoff *= 2;
            continue;
        }

        bool peer_online = msg.peer_online == 1;
        backoff = 1;
        reconnect_attempts = 0;

        pthread_mutex_lock(&ag.mu);
        ag.session_failed = false;
        ag.ws_connected = true;
        ag.peer_online = peer_online;
        pthread_cond_broadcast(&ag.peer_cv);
        pthread_mutex_unlock(&ag.mu);

        KL_INFO("Connected to Hub (role=%s, peer_online=%s)",
                cfg->mode == KL_MODE_SEND ? "send" : "recv",
                peer_online ? "true" : "false");

        int64_t last_hb_ms = kl_now_ms();
        int64_t last_rx_ms = last_hb_ms;

        while (!kl_stop_requested) {
            bool wake = false;
            int pr = kl_ws_poll_read(&conn, ag.wake_pipe[0], 1000, &wake);
            if (pr < 0) break;

            if (wake) {
                if (flush_agent_queue(&ag, &conn) != 0) break;
            }

            if (pr > 0) {
                int mlen = kl_ws_recv_event(&conn, &op, rx_buf, KL_MAX_WS_FRAME);
                if (mlen < 0) break;
                last_rx_ms = kl_now_ms();

                if (op == WS_OP_TEXT) {
                    if (!kl_control_parse((char *)rx_buf, (size_t)mlen, &msg)) break;
                    if (msg.type && !strcmp(msg.type, "peer")) {
                        if (msg.online < 0) break;
                        bool now_online = msg.online == 1;
                        pthread_mutex_lock(&ag.mu);
                        ag.peer_online = now_online;
                        pthread_cond_broadcast(&ag.peer_cv);
                        pthread_mutex_unlock(&ag.mu);

                        KL_INFO("Remote peer is now %s", now_online ? "ONLINE (tunnel ready)" : "OFFLINE");
                        if (!now_online) {
                            stream_close_all(&ag);
                            clear_agent_queue(&ag);
                        }
                    }
                } else if (op == WS_OP_BINARY) {
                    if (handle_mux_frame(&ag, rx_buf, (size_t)mlen) != 0) break;
                }
            }

            int64_t now_ms = kl_now_ms();
            /* Silent blackhole / half-open TCP watchdog */
            if (now_ms - last_rx_ms >= dead_timeout_ms) {
                KL_WARN("Hub link silent for %lds (blackhole/NAT drop); forcing reconnect",
                        (long)((now_ms - last_rx_ms) / 1000));
                break;
            }
            if (now_ms - last_hb_ms >= hb_interval_ms) {
                char ping[128];
                snprintf(ping, sizeof(ping), "{\"type\":\"ping\",\"ts\":%ld}", (long)time(NULL));
                if (kl_ws_send_text(&conn, ping) != 0) break;
                last_hb_ms = now_ms;
            }
        }

        /* Connection lost: tear down active streams, NEVER release listening port */
        pthread_mutex_lock(&ag.mu);
        ag.ws_connected = false;
        ag.peer_online = false;
        pthread_cond_broadcast(&ag.peer_cv);
        pthread_cond_broadcast(&ag.q_cv);
        pthread_mutex_unlock(&ag.mu);

        clear_agent_queue(&ag);
        stream_close_all(&ag);
        kl_ws_close(&conn);

        if (!kl_stop_requested) {
            KL_WARN("Disconnected from Hub; reconnecting in ~%ds%s",
                    backoff, cfg->mode == KL_MODE_RECV ? " (local port still held)" : "");
            sleep_backoff_jitter(backoff);
            if (backoff < 30) backoff *= 2;
        }
    }

    if (has_listener) pthread_join(listen_tid, NULL);
    stream_close_all(&ag);
    pthread_mutex_lock(&ag.mu);
    pthread_cond_broadcast(&ag.peer_cv);
    pthread_mutex_unlock(&ag.mu);
    kl_workers_join(&ag.workers);
    result = ag.listener_failed ? -1 : 0;
    KL_INFO("kreamlink Agent stopped.");
cleanup:
    if (ag.listen_fd >= 0) close(ag.listen_fd);
    free(rx_buf);
    if (ag.wake_pipe[0] >= 0) close(ag.wake_pipe[0]);
    if (ag.wake_pipe[1] >= 0) close(ag.wake_pipe[1]);
    OPENSSL_cleanse(&ag.crypto, sizeof(ag.crypto));
    pthread_mutex_destroy(&ag.workers.mu);
destroy_q_cv:
    pthread_cond_destroy(&ag.q_cv);
destroy_peer_cv:
    pthread_cond_destroy(&ag.peer_cv);
destroy_mutex:
    pthread_mutex_destroy(&ag.mu);
    return result;
}
