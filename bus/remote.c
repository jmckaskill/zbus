#define _GNU_SOURCE
#include "remote.h"
#include "page.h"
#include "messages.h"
#include "bus.h"
#include "rcu.h"
#include "unix.h"
#include "log.h"
#include "lib/str.h"
#include "lib/auth.h"
#include "lib/encode.h"
#include "lib/decode.h"
#include "dmem/vector.h"
#include <stdlib.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>

/////////////////////////////
// message reading

static int process_controlq(struct remote *r)
{
	struct msgq_entry *e;
	while ((e = msgq_acquire(r->qcontrol)) != NULL) {
		switch (e->cmd) {
		case MSG_SHUTDOWN:
			return -1;
		case REP_RELEASE_NAME:
		case REP_REQUEST_NAME: {
			struct rep_name *m = (void *)e->data;
			if (reply_request_name(r, m)) {
				return -1;
			}
			break;
		}
		}
		msgq_pop(r->qcontrol, e);
	}
	return 0;
}
static int run_remote(void *udata)
{
	struct remote *r = udata;
	pthread_setname_np(pthread_self(), r->addr_buf);

	if (authenticate(r)) {
		goto cleanup;
	}

	struct msg_remote ready = { .remote = r };
	msgq_send(r->busq, MSG_AUTHENTICATED, &ready, sizeof(ready), NULL);

	for (;;) {
		if (process_controlq(r)) {
			goto cleanup;
		}

		if (!r->send_stalled && process_dataq(r)) {
			goto cleanup;
		}

		if (read_socket(r)) {
			goto cleanup;
		}

		if (poll_remote(r) < 0) {
			goto cleanup;
		}
	}

cleanup:
	struct msg_remote closing = { .remote = r };
	msgq_send(r->busq, MSG_DISCONNECTED, &closing, sizeof(closing), NULL);
	return 0;
}

int start_remote(struct remote *r)
{
	r->qcontrol = msgq_new();
	r->qdata = msgq_new();
	r->in = new_page(1);
	init_unix_oob(&r->send_oob);
	init_unix_oob(&r->recv_oob);

	str_t s = MAKE_STR(r->addr_buf);
	id_to_string(&s, r->id);
	r->addr = to_slice(s);

	if (thrd_create(&r->thread, &run_remote, r)) {
		msgq_free(r->qcontrol);
		msgq_free(r->qdata);
		deref_page(r->in, 1);
		return -1;
	}

	return 0;
}

void join_remote(struct remote *r)
{
	// Clean up everything except what other threads use. That is
	// cleaned up gc_remote when the remote struct is garbage
	// collected.
	thrd_join(r->thread, NULL);
	deref_page(r->out.pg, 1);
	struct page *pg = r->in;
	while (pg) {
		struct page *next = pg->next;
		deref_page(pg, 1);
		pg = next;
	}
	close_fds(&r->send_oob, r->send_oob.fdn);
	close_fds(&r->recv_oob, r->recv_oob.fdn);
	close(r->sock);
}

void gc_remote(void *p)
{
	struct remote *r = p;
	msgq_free(r->qcontrol);
	msgq_free(r->qdata);
}
