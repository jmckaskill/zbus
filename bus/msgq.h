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

#define MSGQ_SHORT_DATA_SIZE (CACHE_LINE_SIZE - alignof(max_align_t))

// top two bits of cmd are used as flags
#define MSGQ_TYPE_MASK 0xC000
#define MSGQ_TYPE_DATA 0x0000
#define MSGQ_TYPE_PTR 0x4000
#define MSGQ_TYPE_FILE 0x8000
#define MSGQ_TYPE_PAGED 0xC000

#define INVALID_FILE ((intptr_t)-1)

struct msgq_entry {
	atomic_uint valid;
	uint16_t cmd;
	uint16_t time_ms;

	alignas(alignof(max_align_t)) union {
		// other message types, see structures in messages.h
		char data[MSGQ_SHORT_DATA_SIZE];

		void *ptr;

		// Pointer to a ref counted page, the page will be deref when
		// the message is consumed. If the producer wants to keep a
		// copy, the paged data should be ref'd first.
		slice_t paged;

		// files: the file will be closed when the message is consumed.
		// If the producer wants to keep it's own copy, you should
		// duplicate the fd first.
		intptr_t file;
	} u;
};

static_assert(sizeof(((struct msgq_entry *)NULL)->u) >= 16,
	      "cache line too small");
static_assert(offsetof(struct msgq_entry, u) == alignof(max_align_t), "");
static_assert(sizeof(struct msgq_entry) == CACHE_LINE_SIZE, "");

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

#define MSGQ_ENTRY(Q, IDX) (&((Q)->entries[(IDX) % MSGQ_SIZE]))

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

int _msgq_send(struct msgq *q, uint16_t cmd, const void *p, size_t sz);

#define STATIC_ASSERT(TEST, STR, VAL)      \
	((void)sizeof(struct {             \
		 static_assert(TEST, STR); \
		 int d;                    \
	 }),                               \
	 (VAL))

#define MSGQ_DATA(PENTRY, CMD)                                  \
	STATIC_ASSERT((CMD & MSGQ_TYPE_MASK) == MSGQ_TYPE_DATA, \
		      "not a data cmd", (void *)((PENTRY)->u.data))

#define MSGQ_PTR(PENTRY, CMD)                                  \
	STATIC_ASSERT((CMD & MSGQ_TYPE_MASK) == MSGQ_TYPE_PTR, \
		      "not a ptr cmd", (PENTRY)->u.ptr)

#define MSGQ_FILE(PENTRY, CMD)                                  \
	STATIC_ASSERT((CMD & MSGQ_TYPE_MASK) == MSGQ_TYPE_FILE, \
		      "not a ptr cmd", (PENTRY)->u.file)

#define MSGQ_PAGED(PENTRY, CMD)                                  \
	STATIC_ASSERT((CMD & MSGQ_TYPE_MASK) == MSGQ_TYPE_PAGED, \
		      "not a paged cmd", (PENTRY)->u.paged)

#define MSGQ_SEND(PQ, CMD, PVAL)                                     \
	STATIC_ASSERT((CMD & MSGQ_TYPE_MASK) == MSGQ_TYPE_DATA &&    \
			      sizeof(*(PVAL)) <=                     \
				      sizeof((PQ)->entries->u.data), \
		      "not a data cmd",                              \
		      _msgq_send((PQ), CMD, (PVAL), sizeof(*(PVAL))))

#define MSGQ_SEND_PAGED(PQ, CMD, SLICE)                            \
	STATIC_ASSERT((CMD & MSGQ_TYPE_MASK) == MSGQ_TYPE_PAGED && \
			      sizeof(SLICE) == sizeof(slice_t),    \
		      "not a paged cmd",                           \
		      _msgq_send((PQ), CMD, &(SLICE), sizeof(slice_t)))

#define MSGQ_SEND_PTR(PQ, CMD, PTR)                              \
	STATIC_ASSERT((CMD & MSGQ_TYPE_MASK) == MSGQ_TYPE_PTR && \
			      sizeof(PTR) == sizeof(void *),     \
		      "not a ptr cmd",                           \
		      _msgq_send((PQ), CMD, &(PTR), sizeof(void *)))

#define MSGQ_SEND_FILE(PQ, CMD, FILE)                             \
	STATIC_ASSERT((CMD & MSGQ_TYPE_MASK) == MSGQ_TYPE_FILE && \
			      sizeof(PTR) == sizeof(intptr_t),    \
		      "not a file cmd",                           \
		      _msgq_send((PQ), CMD, &(FILE), sizeof(intptr_t)))
