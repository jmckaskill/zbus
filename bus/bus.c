#define _GNU_SOURCE
#include "bus.h"
#include "lib/log.h"
#include "remote.h"
#include "messages.h"
#include "subs.h"
#include "rcu.h"
#include "lib/str.h"
#include "dmem/vector.h"
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <poll.h>
#include <errno.h>

static void signal_wakeup()
{
}

int setup_signals()
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &signal_wakeup;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGMSGQ);
	if (sigaction(SIGMSGQ, &sa, NULL)) {
		perror("sigaction");
		return -1;
	}
	if (sigprocmask(SIG_BLOCK, &sa.sa_mask, NULL)) {
		perror("sigprocmask");
		return -1;
	}
	if (signal(SIGPIPE, SIG_IGN)) {
		perror("ignore sigpipe");
		return -1;
	}
	return 0;
}

/////////////////////////
// Unique address parsing

void id_to_string(buf_t *s, int id)
{
	assert(s->cap - s->len > strlen(":1.") + (sizeof(int) * 4 + 2) / 3);
	int err = buf_addf(s, ":1.%o", (unsigned)id);
	assert(!err);
}

int id_from_string(slice_t s)
{
	const char *p = s.p + strlen(":1.");
	int len = s.len - strlen(":1.");
	if (len <= 0 || len > ((sizeof(int) * 4) - 1) / 3) {
		// make sure the number of octal bits wouldn't overflow an int
		return -1;
	}
	int id = 0;
	for (int i = 0; i < len; i++) {
		if (p[i] < (i ? '0' : '1') || p[i] > '7') {
			return -1;
		}
		id = (id << 3) | (p[i] - '0');
	}
	return id;
}

static int compare_bus_name(const void *key, const void *element)
{
	const slice_t *k = key;
	const struct bus_name *b = element;
	int dsz = k->len - b->name.len;
	return dsz ? dsz : memcmp(k->p, b->name.p, k->len);
}

static int compare_unique_name(const void *key, const void *element)
{
	unsigned k = (uintptr_t)key;
	const struct unique_name *name = element;
	return k - name->id;
}

struct bus_name *lookup_bus_name(struct rcu *d, slice_t name)
{
	return bsearch(&name, d->names_v, d->names_n, sizeof(*d->names_v),
		       &compare_bus_name);
}

struct remote *lookup_remote(struct rcu *d, int id)
{
	struct unique_name *n = bsearch((void *)(uintptr_t)id, d->remotes_v,
					d->remotes_n, sizeof(*d->remotes_v),
					&compare_unique_name);
	return n ? n->owner : NULL;
}

struct remote *lookup_unique_name(struct rcu *d, slice_t name)
{
	int id = id_from_string(name);
	return id >= 0 ? lookup_remote(d, id) : NULL;
}

struct remote *lookup_name(struct rcu *d, slice_t name)
{
	if (has_prefix(name, UNIQUE_ADDR_PREFIX)) {
		return lookup_unique_name(d, name);
	} else {
		struct bus_name *n = lookup_bus_name(d, name);
		return n ? n->owner : NULL;
	}
	return NULL;
}

#define BUSID_LENGTH 32
#define BUSID_BUFLEN 33
int generate_busid(char *busid)
{
	static const char hex_enc[] = "0123456789abcdef";
	uint8_t rand[16];
	if (getentropy(rand, sizeof(rand))) {
		perror("getentropy");
		return -1;
	}
	for (int i = 0; i < sizeof(rand); i++) {
		busid[2 * i] = hex_enc[rand[i] >> 4];
		busid[2 * i + 1] = hex_enc[rand[i] & 15];
	}
	busid[BUSID_LENGTH] = 0;
	return 0;
}

int bind_bus(const char *sockpn)
{
	int lfd = socket(AF_UNIX, SOCK_STREAM, PF_UNIX);
	if (lfd < 0 || fcntl(lfd, F_SETFD, FD_CLOEXEC) ||
	    fcntl(lfd, F_SETFL, O_NONBLOCK)) {
		perror("create socket");
		goto error;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	buf_t s = MAKE_BUF(addr.sun_path);
	if (buf_add_cstr(&s, sockpn)) {
		ELOG("socket pathname %s is too long", sockpn);
		goto error;
	}
	buf_addch(&s, '\0');

	socklen_t salen = s.p + s.len - (char *)&addr;
	if (bind(lfd, (struct sockaddr *)&addr, salen) ||
	    listen(lfd, SOMAXCONN)) {
		ELOG("failed to bind %s: %m", sockpn);
		goto error;
	}

	return lfd;
error:
	close(lfd);
	return -1;
}

DVECTOR_INIT(msgq, struct msgq *);

struct bus {
	struct msgq *q;
	int next_remote_id;
	struct gc *gc;
	struct rcu *rcu;
	struct page_buffer cfg;
	int cfg_used;
	d_vector(msgq) remotes;
	d_vector(msgq) on_name_changed;
	char busid[BUSID_BUFLEN];
};

static int init_bus(struct bus *b)
{
	if (generate_busid(b->busid)) {
		return -1;
	}

	b->q = msgq_new();
	b->gc = new_gc();
	b->next_remote_id = 1;
	dv_init(&b->remotes);
	dv_init(&b->on_name_changed);
	init_buffer(&b->cfg);

	// set an initial rcu data
	struct rcu *d = gc_alloc(1, sizeof(*d));
	memset(d, 0, sizeof(*d));

	struct bus_name *v = gc_alloc(2, sizeof(*v));
	v[0].owner = NULL;
	v[0].user = -1;
	v[0].group = -1;
	v[0].name = dup_in_buffer(&b->cfg, S("com.example.Bservice"));
	v[1].owner = NULL;
	v[1].user = -1;
	v[1].group = -1;
	v[1].name = dup_in_buffer(&b->cfg, S("com.example.Aservice"));

	d->names_n = 2;
	d->names_v = v;

	qsort(d->names_v, d->names_n, sizeof(*d->names_v), &compare_bus_name);

	gc_set_rcu(b->gc, d);
	b->rcu = d;

	return 0;
}

static void destroy_bus(struct bus *b)
{
	assert(b->remotes.size == 0);

	struct rcu *r = b->rcu;
	assert(r->remotes_n == 0);
	assert(r->remotes_v == NULL);
	for (int i = 0; i < r->names_n; i++) {
		gc_collect(b->gc, (char *)r->names_v[i].name.p, NULL);
	}
	gc_collect(b->gc, r->names_v, NULL);
	gc_collect(b->gc, r, NULL);
	free_gc(b->gc);

	dv_free(b->remotes);
	dv_free(b->on_name_changed);
	msgq_free(b->q);
}

static struct rcu *start_rcu(struct bus *b)
{
	struct rcu *d = gc_alloc(1, sizeof(struct rcu));
	*d = *b->rcu;
	return d;
}

static void finish_rcu(struct bus *b, struct rcu *d)
{
	gc_collect(b->gc, b->rcu, NULL);
	gc_set_rcu(b->gc, d);
	b->rcu = d;
	run_gc(b->gc);
}

///////////////////
// name handling

static void sub_name_changed(struct bus *b, struct msgq *q, bool add)
{
	if (add) {
		dv_append1(&b->on_name_changed, q);
	} else {
		dv_remove(&b->on_name_changed, q);
	}
}

static void on_name_changed(struct bus *b, slice_t name, int old_owner,
			    int new_owner)
{
	struct msg_name m;
	m.name = name;
	m.old_owner = old_owner;
	m.new_owner = new_owner;

	for (int i = 0; i < b->on_name_changed.size; i++) {
		struct msgq *q = b->on_name_changed.data[i];
		if (!msgq_send(q, MSG_NAME, &m, sizeof(m), &gc_name) &&
		    m.name.p) {
			ref_paged_data(m.name.p);
		}
	}
}

static void add_unique_name(struct gc *gc, struct unique_name **pv, int *pn,
			    struct remote *r)
{
	int n = *pn;
	struct unique_name *oldv = *pv;

	// most of the time we are inserting at the end
	int idx = *pn;

	if (n && oldv[n - 1].id >= r->id) {
		// slow path where we are not inserting at the end
		idx = lower_bound((void *)(uintptr_t)r->id, oldv, n,
				  sizeof(*oldv), &compare_unique_name);
		if (idx >= 0) {
			// the remote is already in the list
			return;
		}
		idx = -(idx + 1);
	}

	struct unique_name *v = gc_alloc(n + 1, sizeof(struct unique_name));
	memcpy(v, oldv, idx * sizeof(*v));
	v[idx].id = r->id;
	v[idx].owner = r;
	memcpy(v + 1, oldv + idx, (n - idx) * sizeof(*v));

	*pv = v;
	*pn = n + 1;
	gc_collect(gc, oldv, NULL);
}

static void remove_unique_name(struct gc *gc, struct unique_name **pv, int *pn,
			       int id)
{
	struct unique_name *oldv = *pv;
	int n = *pn;
	int idx = lower_bound((void *)(uintptr_t)id, oldv, n, sizeof(*oldv),
			      &compare_unique_name);

	if (idx < 0) {
		// remote was not in the list
		return;
	}

	struct unique_name *v = gc_alloc(n - 1, sizeof(struct unique_name));
	memcpy(v, oldv, idx * sizeof(*v));
	memcpy(v + idx, oldv + idx + 1, (n - 1 - idx) * sizeof(*v));
	*pv = v;
	*pn = n - 1;
	gc_collect(gc, oldv, NULL);
}

static void do_update_name(struct bus *b, struct bus_name *n, struct remote *r)
{
	int old_id = n->owner ? n->owner->id : -1;
	int new_id = r ? n->owner->id : -1;

	struct rcu *d = start_rcu(b);

	struct bus_name *oldv = d->names_v;
	d->names_v = gc_alloc(d->names_n, sizeof(struct bus_name));
	memcpy(d->names_v, oldv, d->names_n * sizeof(*oldv));
	d->names_v[n - oldv].owner = r;
	gc_collect(b->gc, oldv, NULL);
	finish_rcu(b, d);

	on_name_changed(b, n->name, old_id, new_id);
}

static int update_name(struct bus *b, struct remote *r, slice_t name, bool add)
{
	struct bus_name *n = lookup_bus_name(b->rcu, name);
	int success;

	if (add) {
		if (n == NULL) {
			return DBUS_REQUEST_NAME_NOT_ALLOWED;
		} else if (n->owner == r) {
			return DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
		} else if (n->owner) {
			return DBUS_REQUEST_NAME_REPLY_EXISTS;
		}
		success = DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
	} else {
		if (n == NULL || n->owner == NULL) {
			return DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
		} else if (n->owner != r) {
			return DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
		}
		success = DBUS_RELEASE_NAME_REPLY_RELEASED;
	}

	do_update_name(b, n, add ? r : NULL);
	return success;
}

static void release_all_names(struct bus *b, struct remote *r)
{
	// RCU may be updated during iteration. names_n should not change, but
	// need to be careful which rcu pointer we access data through.
	for (int i = 0, n = b->rcu->names_n; i < n; i++) {
		struct bus_name *n = &b->rcu->names_v[i];
		if (n->owner == r) {
			do_update_name(b, n, r);
		}
	}
}

/////////////////////////////////
// remote handling

static int add_remote(struct bus *b, int sock)
{
	struct remote *r = gc_alloc(1, sizeof(*r));
	r->id = b->next_remote_id++;
	r->handle = gc_register(b->gc);
	r->busid = make_slice(b->busid, BUSID_LENGTH);
	r->busq = b->q;
	r->sock = sock;

	if (start_remote(r)) {
		close(sock);
		gc_unregister(b->gc, r->handle);
		return -1;
	}

	dv_append1(&b->remotes, r->qcontrol);
	return 0;
}

static void activate_remote(struct bus *b, struct remote *r)
{
	DLOG("remote %d activated", r->id);

	struct rcu *d = start_rcu(b);
	add_unique_name(b->gc, &d->remotes_v, &d->remotes_n, r);

	// Make sure we're our reply is the first message the remote sees, but
	// it doesn't see it until after we publish the RCU data. This way no
	// other remote tries to send messages before the registration reply is
	// processed and this remote can't send any messages to anyone else
	// before it's been registered in the RCU data.
	unsigned ei;
	int err = msgq_allocate(r->qcontrol, 1, &ei);
	assert(!err); // this shouldn't fail as the queue should be empty
	finish_rcu(b, d);

	struct msgq_entry *e = msgq_get(r->qcontrol, ei);
	e->cmd = REP_REGISTER;
	msgq_release(r->qcontrol, ei, 1);

	on_name_changed(b, make_slice(NULL, 0), -1, r->id);
}

static void remove_remote(struct bus *b, struct remote *r)
{
	int id = r->id;
	DLOG("removing remote %u", r->id);

	// join and cleanup data used by the remote itself
	join_remote(r);
	dv_remove(&b->remotes, r->qcontrol);
	gc_unregister(b->gc, r->handle);

	// The remote will release subscriptions before sending the disconnect.
	// It will not release names, so we do that here.
	release_all_names(b, r);

	// We can then release the unique address.
	struct rcu *d = start_rcu(b);
	remove_unique_name(b->gc, &d->remotes_v, &d->remotes_n, r->id);
	gc_collect(b->gc, r, &gc_remote);
	finish_rcu(b, d);

	// can't use r as it's now been GC'd
	on_name_changed(b, make_slice(NULL, 0), id, -1);
}

//////////////////////////////////
// broadcast handling

static int update_broadcast(struct bus *b, struct subscription *s, bool add)
{
	int idx = find_sub(b->rcu->bcast_v, b->rcu->bcast_n, s);
	if ((add && idx >= 0) || (!add && idx < 0)) {
		// already added or removed
		return 0;
	}

	struct rcu *d = start_rcu(b);
	struct subscription *v = d->bcast_v;
	int n = d->bcast_n;
	if (add) {
		idx = -(idx + 1);
		struct subscription *subs = gc_alloc(n + 1, sizeof(*s));
		memcpy(subs, v, idx * sizeof(*s));
		memcpy(subs + idx, s, sizeof(*s));
		memcpy(subs + idx + 1, v + idx, (n - idx) * sizeof(*s));
		d->bcast_v = v;
		d->bcast_n = n + 1;
	} else {
		struct subscription *subs = gc_alloc(n - 1, sizeof(*s));
		memcpy(subs, v, idx * sizeof(*s));
		memcpy(subs + idx, v + idx + 1, (n - idx - 1) * sizeof(*s));
		d->bcast_v = v;
		d->bcast_n = n - 1;
	}
	finish_rcu(b, d);
	return 0;
}

/////////////////////////////////
// Main loop

static void _reply_errcode(struct msgq *q, uint16_t cmd, int errcode,
			   uint32_t serial)
{
	if (serial) {
		struct rep_errcode m;
		m.errcode = errcode;
		m.serial = serial;
		msgq_send(q, cmd, &m, sizeof(m), NULL);
	}
}

int run_bus(int lfd)
{
	struct bus b;
	if (init_bus(&b)) {
		return -1;
	}

	for (;;) {
		struct msgq_entry *e;
		while ((e = msgq_acquire(b.q)) != NULL) {
			switch (e->cmd) {
			case MSG_DISCONNECTED: {
				struct cmd_remote *c = (void *)e->data;
				remove_remote(&b, c->remote);
				break;
			}

			case CMD_REGISTER: {
				struct cmd_remote *c = (void *)e->data;
				activate_remote(&b, c->remote);
				break;
			}

			case CMD_UPDATE_NAME: {
				struct cmd_name *c = (void *)e->data;
				int err = update_name(&b, c->remote, c->name,
						      c->add);
				_reply_errcode(c->remote->qcontrol,
					       REP_UPDATE_NAME, err, c->serial);
				break;
			}

			case CMD_UPDATE_NAME_SUB: {
				struct cmd_name_sub *c = (void *)e->data;
				sub_name_changed(&b, c->q, c->add);
				_reply_errcode(c->q, REP_UPDATE_NAME_SUB, 0,
					       c->serial);
				break;
			}

			case CMD_UPDATE_SUB: {
				struct cmd_update_sub *c = (void *)e->data;
				int err = update_broadcast(&b, &c->s, c->add);
				_reply_errcode(c->remote->qcontrol,
					       REP_UPDATE_SUB, err, c->serial);
				break;
			}
			}
			msgq_pop(b.q, e);
		}

		if (poll_socket(lfd, NULL)) {
			break;
		}

		for (;;) {
			int cfd = accept4(lfd, NULL, NULL,
					  SOCK_NONBLOCK | SOCK_CLOEXEC);
			if (cfd < 0 && errno == EINTR) {
				continue;
			} else if (cfd < 0 && errno == EAGAIN) {
				break;
			} else if (cfd < 0) {
				perror("accept");
				break;
			}

			add_remote(&b, cfd);
		}
	}

	destroy_bus(&b);
	return 0;
}
