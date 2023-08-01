#define _GNU_SOURCE
#include "remote.h"
#include "page.h"
#include "messages.h"
#include "bus.h"
#include "rcu.h"
#include "unix.h"
#include "lib/log.h"
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
	msg_type_t *e;
	while ((e = msg_acquire(r->qcontrol)) != NULL) {
		switch (e->code) {
		case REP_UPDATE_NAME:
		case REP_UPDATE_NAME_SUB:
		case REP_UPDATE_SUB: {
			struct rep_errcode *c = (void *)e->data;
			if (reply_errcode(r, c)) {
				return -1;
			}
			break;
		}
		case MSG_NAME: {
			struct msg_name *c = (void *)e->data;
			if (c->new_owner >= 0) {
				update_bus_matches(r, c->name);
			}
			break;
		}
		case CMD_UPDATE_SUB: {
		}
		}
		msg_pop(r->qcontrol, e);
	}
	return 0;
}
static int run_remote(void *udata)
{
	struct remote *r = udata;

	msg_start_producer(&r->waiter);
	r->qcontrol = msg_new_queue();
	r->qdata = msg_new_queue();
	r->icontrol = 0;
	r->idata = 0;
	r->in = new_page(1);
	init_unix_oob(&r->send_oob);
	init_unix_oob(&r->recv_oob);

	buf_t s = MAKE_BUF(r->addr_buf);
	id_to_string(&s, r->id);
	r->addr = to_slice(s);
	pthread_setname_np(pthread_self(), r->addr_buf);

	if (authenticate(r)) {
		goto cleanup;
	}

	r->can_write = true;

	while (!msg_should_shutdown(r->qcontrol) &&
	       !msg_should_shutdown(r->qdata)) {
		if (process_controlq(r)) {
			goto cleanup;
		}

		if (r->can_write && process_dataq(r)) {
			goto cleanup;
		}

		if (read_socket(r)) {
			goto cleanup;
		}

		if (poll_socket(r->sock, &r->can_write)) {
			goto cleanup;
		}
	}

cleanup:
	// remove references from other threads
	remove_all_matches(r);

	int idx = msg_allocate(r->busq, &r->waiter, 1);
	struct msg_disconnected *c = msg_get(r->busq, idx);
	c->remote = r;
	msg_release(r->busq, idx, &msg_disconnected_vt);

	// Clean up everything except what other threads use. That is
	// cleaned up gc_remote when the remote struct is garbage
	// collected.

	msg_stop_waiter(&r->waiter);
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
	return 0;
}

int start_remote(struct remote *r)
{
	return thrd_create(&r->thread, &run_remote, r);
}

void join_remote(struct remote *r)
{
	thrd_join(r->thread, NULL);
}

void gc_remote(void *p)
{
	struct remote *r = p;
	msg_free_queue(r->qcontrol);
	msg_free_queue(r->qdata);
}
