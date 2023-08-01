#pragma once

#include "config.h"
#include "lib/str.h"
#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdalign.h>

struct msg_type {
	int code;
	void (*destroy)(void *);
	void (*send)(void *);
};

typedef const struct msg_type msg_type_t;

struct msg_header {
	// set by msg_release and read by msg_acquire
	// don't read/write outside those functions
	_Atomic(void *) vt;
};

#define MSGQ_DATA_SIZE CACHE_LINE_SIZE
#define MSGQ_FLAG_FILE 0x8000U

struct msg_waiter {
	struct msg_waiter *next;
	uintptr_t wakeup;
	unsigned need;
};

struct msg_queue {
	// cache line #1 - write by both but rarely
	alignas(CACHE_LINE_SIZE) atomic_bool shutdown;
	_Atomic(struct msg_waiter *) waitlist;

	// cache line #2 - read and write by producers
	alignas(CACHE_LINE_SIZE) _Atomic(uint16_t) allocated;

	// cache line #3 - write by consumer, read by producers
	alignas(CACHE_LINE_SIZE) _Atomic(uint16_t) consumed;
	atomic_uintptr_t wakeup;

	// entry cache lines - go between the specific producer and the consumer
	alignas(CACHE_LINE_SIZE) char entries[MSGQ_SIZE * MSGQ_DATA_SIZE];
};

///////////////////////
// General data setup

// These must be called on the relevant threads
struct msg_queue *msg_new_queue();
void msg_free_queue(struct msg_queue *q);

void msg_start_producer(struct msg_waiter *w);
void msg_stop_producer(struct msg_waiter *w);

///////////////////////////////
// Producer functions

void msg_send_shutdown(struct msg_queue *q);

// Allocates a number of messages in the queue and returns the index of the
// first entry. Returns -ve on overrun. Use msg_get to get the queue
// entry.
int msg_allocate(struct msg_queue *q, struct msg_waiter *w, int num);
static void *msg_get(struct msg_queue *q, int idx);

// used by the producer to release entries to the consumer
// and wakes up the consumer if required
void msg_release(struct msg_queue *q, int idx, struct msg_type *type);

/////////////////////////
// Consumer functions

// returns non-zero if the thread should shutdown. Should be called before
// processing the queue on wakeup
static int msg_should_shutdown(struct msg_queue *q);

// used by the consumer to get the current queue head
// returns current entry in the queue
// return NULL if it's time to go to sleep
static msg_type_t *msg_acquire(struct msg_queue *q, int idx);

// used by the consumer when they are done with the current message
// the next call to msg_acquire will get the next entry
int msg_pop(struct msg_queue *q, int idx);

//////////////////////////////
// inline implementations

static inline void *msg_get(struct msg_queue *q, int idx)
{
	return &q->entries[(idx % MSGQ_SIZE) * CACHE_LINE_SIZE];
}

static inline int msg_should_shutdown(struct msg_queue *q)
{
	return atomic_load_explicit(&q->shutdown, memory_order_relaxed);
}

static inline msg_type_t *msg_acquire(struct msg_queue *q, int idx)
{
	struct msg_header *e = msg_get(q, idx);
	return atomic_load_explicit(&e->vt, memory_order_acquire);
}
