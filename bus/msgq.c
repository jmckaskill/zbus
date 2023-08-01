#include "msgq.h"
#include "page.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#endif

#ifdef _WIN32
static_assert(sizeof(HANDLE) == sizeof(uintptr_t), "");
#else
static_assert(sizeof(pthread_t) == sizeof(uintptr_t), "");
#endif

static_assert(alignof(struct msg_queue) == CACHE_LINE_SIZE, "");
static_assert(sizeof(struct msg_queue) == (3 + MSGQ_SIZE) * CACHE_LINE_SIZE,
	      "");

///////////////////////////
// General structure setup

struct msg_queue *msg_new_queue()
{
	struct msg_queue *q = aligned_alloc(CACHE_LINE_SIZE, sizeof(*q));

	atomic_store_explicit(&q->shutdown, false, memory_order_relaxed);
	atomic_store_explicit(&q->waitlist, NULL, memory_order_relaxed);
	atomic_store_explicit(&q->allocated, 0, memory_order_relaxed);
	atomic_store_explicit(&q->consumed, 0, memory_order_relaxed);

#ifdef _WIN32
	atomic_store_explicit(&q->wakeup, CreateEvent(), memory_order_relaxed);
#else
	atomic_store_explicit(&q->wakeup, pthread_self(), memory_order_relaxed);
#endif

	for (int i = 0; i < MSGQ_SIZE; i++) {
		struct msg_header *e = msg_get(q, i);
		atomic_store_explicit(&e->vt, NULL, memory_order_relaxed);
	}

	return q;
}

static void free_entry_data(struct msg_header *e)
{
	struct msg_type *vt =
		atomic_load_explicit(&e->vt, memory_order_relaxed);
	if (vt->destroy) {
		vt->destroy(e);
	}
}

void msg_free_queue(struct msg_queue *q)
{
	if (q) {
		for (int i = 0; i < MSGQ_SIZE; i++) {
			free_entry_data(&q->entries[i]);
		}
#ifdef _WIN32
		CloseHandle((HANDLE)q->wakeup.event);
#endif
		free(q);
	}
}

void msg_start_producer(struct msg_waiter *w)
{
	w->next = NULL;
	w->need = 0;
#ifdef _WIN32
	w->wakeup = INVALID_HANDLE_VALUE;
#else
	w->wakeup = pthread_self();
#endif
}

void msg_stop_producer(struct msg_waiter *w)
{
#ifdef _WIN32
	CloseHandle(w->wakeup);
#endif
}

////////////////////////////
// wakeup

static inline void wakeup_consumer(struct msg_queue *q)
{
#ifdef _WIN32
	SetEvent((HANDLE)q->wakeup);
#else
	pthread_kill((pthread_t)q->wakeup, MSGQ_SIG_CONSUMER);
#endif
}

static inline void wakeup_producer(struct msg_waiter *b)
{
#ifdef _WIN32
	SetEvent((HANDLE)b->wakeup);
#else
	pthread_kill((pthread_t)b->wakeup, MSGQ_SIG_PRODUCER);
#endif
}

//////////////////////////////////////
// overrun management

static void update_waitlist(struct msg_queue *q, struct msg_waiter *head,
			    struct msg_waiter *tail)
{
	tail->next = atomic_load(&q->waitlist);
	while (!atomic_compare_exchange_weak(&q->waitlist, &tail->next, head)) {
	}
}

static void wait_on_consumer(struct msg_queue *q, struct msg_waiter *w,
			     unsigned need)
{
#ifdef _WIN32
	if (w->wakeup == INVALID_HANDLE_VALUE) {
		w->wakeup = CreateEvent(NULL, FALSE, FALSE, NULL);
	}
#endif

	w->need = need;

	// add ourselves to the waitlist
	update_waitlist(q, w, w);

	// check to see if the consumer has consumed enough in the interim and
	// gone to sleep. If it has, we have to wake it up. We can't touch the
	// waitlist after we've added ourselves to it without screwing it up.
	if (atomic_load(&q->consumed) >= need) {
		wakeup_consumer(q);
	}

	int sig;
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, MSGQ_SIG_PRODUCER);
	sigwait(&set, &sig);
}

static void signal_waiters(struct msg_queue *q, unsigned consumed)
{
	// work through the waitlist, waking any that can now proceed, and put
	// any that can't proceed back on the waitlist

	struct msg_waiter *w = atomic_exchange_explicit(&q->waitlist, NULL,
							memory_order_acquire);

	struct msg_waiter *head = NULL;
	struct msg_waiter *tail = NULL;

	while (w) {
		struct msg_waiter *next = w->next;
		if (consumed >= w->need) {
			w->next = NULL;
			wakeup_producer(w);
		} else if (!head) {
			w->next = NULL;
			head = w;
			tail = w;
		} else {
			w->next = head;
			head = w;
		}
		w = next;
	}

	// add waiters we can't wake yet back on the waitlist for next time
	if (head != NULL) {
		update_waitlist(q, head, tail);
	}
}

///////////////////////////
// Producer functions

int msg_allocate(struct msg_queue *q, struct msg_waiter *wait, int num)
{
	assert(num > 0);

	// use relaxed as we aren't synchronizing other data with other
	// producers
	uint16_t first = atomic_fetch_add_explicit(&q->allocated, num,
						   memory_order_relaxed);
	uint16_t last = first + (uint16_t)(num - 1);
	uint16_t need = last - (uint16_t)MSGQ_SIZE;

	// use acquire so that the the previous use of the entry is sent through
	uint16_t consumed =
		atomic_load_explicit(&q->consumed, memory_order_acquire);

	if (consumed < need) {
		if (wait) {
			wait_on_consumer(q, wait, need);
		} else {
			// user doesn't want to block, the queue will stall out
			// as we've already allocated queue entries. We can't
			// return allocated entries as another thread may have
			// allocated in the interim. Only option is to kill the
			// consumer.
			msg_send_shutdown(q);
			return -1;
		}
	}
	return first;
}

void msg_release(struct msg_queue *q, int idx, struct msg_type *type)
{
	struct msg_header *e = msg_get(q, idx);
	if (type->send) {
		type->send(e);
	}

	// release this entry to the consumer
	atomic_store_explicit(&e->vt, type, memory_order_release);

	// use relaxed as we don't really care about any dependent data for
	// other entries. Just need to see if the consumer has only reached the
	// entry before ours and thus possibly gone to sleep.
	uint16_t consumed =
		atomic_load_explicit(&q->consumed, memory_order_relaxed);

	if (consumed == idx - 1) {
		wakeup_consumer(q);
	}
}

///////////////////////
// Consumer functions

int msg_pop(struct msg_queue *q, int idx)
{
	struct msg_header *e = msg_get(q, idx);
	free_entry_data(e);

	// Reset the flag so the consumer doesn't try and read it again.
	// Producers set this when the message is ready, but don't otherwise use
	// it.
	atomic_store_explicit(&e->vt, NULL, memory_order_relaxed);

	// release the entry back to the producers
	atomic_store_explicit(&q->consumed, idx, memory_order_release);
	return (uint16_t)(idx + 1);
}
