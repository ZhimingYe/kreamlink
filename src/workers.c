#include "kreamlink.h"

#include <string.h>

int kl_workers_init(kl_workers_t *workers) {
    memset(workers, 0, sizeof(*workers));
    return pthread_mutex_init(&workers->mu, NULL);
}

static void *run_task(void *arg) {
    kl_worker_slot_t *slot = arg;
    slot->run(slot->arg);
    pthread_mutex_lock(slot->mu);
    slot->done = true;
    pthread_mutex_unlock(slot->mu);
    return NULL;
}

bool kl_workers_start(kl_workers_t *workers, void *(*run)(void *), void *arg) {
    bool started = false;
    pthread_mutex_lock(&workers->mu);
    for (size_t i = 0; i < KL_MAX_WORKERS; i++) {
        kl_worker_slot_t *slot = &workers->slots[i];
        if (slot->active && !slot->done) continue;
        /* A completed task has released mu for the last time. Join also waits
         * for thread-local destructors before recycling the slot. */
        if (slot->active) pthread_join(slot->tid, NULL);
        slot->mu = &workers->mu;
        slot->run = run;
        slot->arg = arg;
        slot->done = false;
        slot->active = pthread_create(&slot->tid, NULL, run_task, slot) == 0;
        started = slot->active;
        break;
    }
    pthread_mutex_unlock(&workers->mu);
    return started;
}

/* The caller must stop submitting tasks before joining the group. */
void kl_workers_join(kl_workers_t *workers) {
    for (size_t i = 0; i < KL_MAX_WORKERS; i++) {
        kl_worker_slot_t *slot = &workers->slots[i];
        if (slot->active) {
            pthread_join(slot->tid, NULL);
            slot->active = false;
        }
    }
}
