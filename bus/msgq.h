#pragma once

#include "config.h"
#include "lib/str.h"
#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdalign.h>

#ifndef _WIN32
#include <pthread.h>
#include <signal.h>
#define SIGMSGQ (SIGRTMIN)
#endif

#define INVALID_FILE ((intptr_t)-1)

struct msgq_entry {
	alignas(CACHE_LINE_SIZE) atomic_uint valid;
	uint16_t cmd;
	uint16_t time_ms;
	destructor_fn cleanup;

	// Message contents
	alignas(alignof(max_align_t)) char data[1];
};

static_assert(sizeof(struct msgq_entry) == CACHE_LINE_SIZE, "");

#define MSGQ_DATA_SIZE \
	(sizeof(struct msgq_entry) - offsetof(struct msgq_entry, data))

struct msgq_wakeup {
#ifdef _WIN32
	uintptr_t event;
#else
	pthread_t thread;
#endif
};

#define MSGQ_ALIGNED_T alignas(CACHE_LINE_SIZE) struct msgq

struct msgq {
	alignas(CACHE_LINE_SIZE) struct msgq_wakeup wakeup;
	alignas(CACHE_LINE_SIZE) atomic_flag awake;
	alignas(CACHE_LINE_SIZE) atomic_uint producer_next;
	alignas(CACHE_LINE_SIZE) unsigned consumer_next;
	alignas(CACHE_LINE_SIZE) struct msgq_entry entries[MSGQ_SIZE];
};

static_assert(alignof(struct msgq) == CACHE_LINE_SIZE, "");
static_assert(sizeof(struct msgq) == 260 * CACHE_LINE_SIZE, "");
static_assert(offsetof(struct msgq, awake) == CACHE_LINE_SIZE, "");
static_assert(offsetof(struct msgq, producer_next) == 2 * CACHE_LINE_SIZE, "");
static_assert(offsetof(struct msgq, consumer_next) == 3 * CACHE_LINE_SIZE, "");
static_assert(offsetof(struct msgq, entries) == 4 * CACHE_LINE_SIZE, "");

static inline struct msgq_entry *msgq_get(struct msgq *q, unsigned idx)
{
	return &q->entries[idx % MSGQ_SIZE];
}

// sets up the msgq
struct msgq *msgq_new();

// called to free up the memory
void msgq_free(struct msgq *q);

uintptr_t msgq_event(struct msgq *q);

// used by the producer to allocate entries within the queue
// returns non-zero on error
// pidx will hold index of first entry on success
int msgq_allocate(struct msgq *q, int num, unsigned *pidx);

// used by the producer to release entries to the consumer
// and wakes up the consumer if required
// returns non-zero if there was an error waking up the consumer
int msgq_release(struct msgq *q, unsigned idx, int num);

// used by the consumer to get the current queue head
// returns current entry in the queue
// return NULL if it's time to go to sleep
struct msgq_entry *msgq_acquire(struct msgq *q);

// used by the consumer when they are done with the current message
// the next call to msgq_acquire will get the next entry
void msgq_pop(struct msgq *q, struct msgq_entry *e);

// sends a single message. For multiple use msgq_allocate & msgq_release
// manually
int msgq_send(struct msgq *q, uint16_t cmd, const void *p, size_t sz,
	      destructor_fn cleanup);
