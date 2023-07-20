#include "msgq.h"
#include "page.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <unistd.h>
#endif

struct msgq *msgq_new()
{
	struct msgq *q = aligned_alloc(CACHE_LINE_SIZE, sizeof(*q));

	// consumer thread should start by processing events (ie it's awake) and
	// only after failing to acquire will it go to sleep
	atomic_flag_test_and_set_explicit(&q->awake, memory_order_relaxed);
	q->producer_next = 0;
	q->consumer_next = 0;

	for (int i = 0; i < MSGQ_SIZE; i++) {
		q->entries[i].valid = 0;
	}

#ifdef _WIN32
	q->wakeup.event = CreateEvent();
#endif

	return q;
}

#ifdef _WIN32
uintptr_t msgq_event(struct msgq *q)
{
	return q->wakeup.event;
}
#endif

void msgq_free(struct msgq *q)
{
	if (q) {
		for (int i = 0; i < MSGQ_SIZE; i++) {
			struct msgq_entry *e = &q->entries[i];
			if (e->valid && e->cleanup) {
				e->cleanup(e->data);
			}
		}
#ifdef _WIN32
		CloseHandle(q->wakeup.event);
#endif
		free(q);
	}
}

int msgq_allocate(struct msgq *q, int num, unsigned *pidx)
{
	assert(num > 0);

	// we can use relaxed because we have no ordering requirements with
	// other producers
	unsigned idx = atomic_fetch_add_explicit(&q->producer_next, num,
						 memory_order_relaxed);
	// check if we have overrun the queue
	// by seeing if the last item we allocated is still valid
	struct msgq_entry *e = msgq_get(q, idx + num - 1);
	if (atomic_load_explicit(&e->valid, memory_order_acquire) == true) {
		// We've overrun the queue. Another thread may have tried to
		// allocate some more so we can't return them without having
		// fragmentation. We can't just use some of them as we'll end up
		// with an unused hole that will stall the consumer. We don't
		// want to block wait for the consumer as that would require
		// spin waiting. Realistically we want to kick the client as
		// it's not servicing messages quick enough. If it's still alive
		// it will reconnect.
		return 1;
	}

	// we have [idx,idx+end) available for the produce to fill out
	*pidx = idx;
	return 0;
}

int msgq_release(struct msgq *q, unsigned idx, int num)
{
	assert(num > 0);

	// set the valid flag for all but the first using relaxed
	for (int i = idx + num - 1; i > idx; i--) {
		struct msgq_entry *e = msgq_get(q, i);
		atomic_store_explicit(&e->valid, 1, memory_order_relaxed);
	}

	// and then finally use release ordering for the first item which
	// gives us a single write barrier for the whole lot
	struct msgq_entry *e = msgq_get(q, idx);
	atomic_store_explicit(&e->valid, 1, memory_order_release);

	if (atomic_flag_test_and_set_explicit(&q->awake,
					      memory_order_acq_rel) == false) {
#ifdef _WIN32
		return SetEvent(q->wakeup.handle) == FALSE;
#else
		return pthread_kill(q->wakeup.thread, SIGMSGQ);
#endif
	} else {
		return 0;
	}
}

struct msgq_entry *msgq_acquire(struct msgq *q)
{
	struct msgq_entry *e = msgq_get(q, q->consumer_next);
	if (atomic_load_explicit(&e->valid, memory_order_acquire)) {
		// this one is available
		return e;
	} else {
		// time to go to sleep
#ifndef _WIN32
		q->wakeup.thread = pthread_self();
#endif
		atomic_flag_clear_explicit(&q->awake, memory_order_release);
		return NULL;
	}
}

void msgq_pop(struct msgq *q, struct msgq_entry *e)
{
	if (e->cleanup) {
		e->cleanup(e->data);
	}
	q->consumer_next++;
}

int msgq_send(struct msgq *q, uint16_t cmd, const void *p, size_t sz,
	      destructor_fn cleanup)
{
	struct msgq_entry *e;
	unsigned idx;
	assert(sz <= MSGQ_DATA_SIZE);
	if (msgq_allocate(q, 1, &idx)) {
		return -1;
	}
	e = msgq_get(q, idx);
	e->cmd = cmd;
	e->time_ms = 0;
	e->cleanup = cleanup;
	memcpy(e->data, p, sz);
	return msgq_release(q, idx, 1);
}
