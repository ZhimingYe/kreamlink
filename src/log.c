#include "kreamlink.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static kl_log_level_t g_log_level = KL_LOG_INFO;
static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;

void kl_log_set_level(kl_log_level_t lvl) {
    g_log_level = lvl;
}

static const char *level_str(kl_log_level_t lvl) {
    switch (lvl) {
        case KL_LOG_DEBUG: return "DEBUG";
        case KL_LOG_INFO:  return "INFO ";
        case KL_LOG_WARN:  return "WARN ";
        case KL_LOG_ERROR: return "ERROR";
        default:           return "INFO ";
    }
}

void kl_log(kl_log_level_t lvl, const char *fmt, ...) {
    if (lvl < g_log_level) {
        return;
    }

    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_now);

    pthread_mutex_lock(&g_log_mu);
    fprintf(stderr, "[%s] [%s] ", ts, level_str(lvl));
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
    pthread_mutex_unlock(&g_log_mu);
}
