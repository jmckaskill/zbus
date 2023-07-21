#define _GNU_SOURCE
#include "bus.h"
#include "remote.h"
#include "messages.h"
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

int compare_bus_name(const void *a, const void *b)
{
	const struct bus_name *na = a;
	const struct bus_name *nb = b;
	return na->name.len == nb->name.len ?
		       memcmp(na->name.p, nb->name.p, na->name.len) :
		       na->name.len - nb->name.len;
}

int compare_unique_name(const void *a, const void *b)
{
	const struct unique_name *key = a;
	const struct unique_name *test = b;
	return key->id - test->id;
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

	str_t s = MAKE_STR(addr.sun_path);
	if (str_add1(&s, sockpn)) {
		fprintf(stderr, "socket pathname %s is too long\n", sockpn);
		goto error;
	}

	socklen_t salen = s.p + s.len + 1 - (char *)&addr;
	if (bind(lfd, (struct sockaddr *)&addr, salen) ||
	    listen(lfd, SOMAXCONN)) {
		fprintf(stderr, "failed to bind %s: %m\n", sockpn);
		goto error;
	}

	return lfd;
error:
	close(lfd);
	return -1;
}

DVECTOR_INIT(remote_ptr, struct remote *);

struct bus {
	struct msgq *q;
	int next_remote_id;
	struct gc *gc;
	struct rcu *rcu;
	d_vector(remote_ptr) remotes;
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

	// set an initial rcu data
	struct rcu *d = gc_alloc(1, sizeof(*d));
	memset(d, 0, sizeof(*d));

	struct bus_name *v = gc_alloc(2, sizeof(*v));
	v[0].owner = NULL;
	v[0].user = -1;
	v[0].group = -1;
	v[0].name = gc_dup(S("com.example.Bservice"));
	v[1].owner = NULL;
	v[1].user = -1;
	v[1].group = -1;
	v[1].name = gc_dup(S("com.example.Aservice"));

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
	msgq_free(b->q);
}

static int add_remote(struct bus *b, int sock)
{
	struct remote *r = gc_alloc(1, sizeof(*r));
	r->id = b->next_remote_id++;
	r->handle = gc_register(b->gc);
	r->bus = b;
	r->busid = make_slice2(b->busid, BUSID_LENGTH);
	r->busq = b->q;
	r->sock = sock;

	if (start_remote(r)) {
		close(sock);
		gc_unregister(b->gc, r->handle);
		return -1;
	}

	dv_append1(&b->remotes, r);
	return 0;
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

static struct unique_name *add_unique_name(struct gc *gc,
					   struct unique_name *oldv, int oldn,
					   struct remote *r)
{
	struct unique_name *v = gc_alloc(oldn + 1, sizeof(struct unique_name));

	// copy the remotes list over inserting the new remote in place
	int i = 0;
	while (i < oldn && oldv[i].id < r->id) {
		v[i] = oldv[i];
		i++;
	}
	v[i].id = r->id;
	v[i].owner = r;
	while (i < oldn) {
		v[i + 1] = oldv[i];
		i++;
	}

	gc_collect(gc, oldv, NULL);
	return v;
}

static struct unique_name *remove_unique_name(struct gc *gc,
					      struct unique_name *oldv,
					      int oldn, struct remote *r)
{
	struct unique_name *v = gc_alloc(oldn - 1, sizeof(struct unique_name));

	// copy the remotes list over removing the remote
	int i = 0;
	while (oldv[i].id != r->id) {
		v[i] = oldv[i];
		i++;
	}
	i++;
	while (i < oldn) {
		v[i - 1] = oldv[i];
		i++;
	}

	gc_collect(gc, oldv, NULL);
	return v;
}

static bool remote_owns_any_name(struct remote *r, struct bus_name *v, int n)
{
	for (int i = 0; i < n; i++) {
		if (v[i].owner == r) {
			return true;
		}
	}
	return false;
}

static struct bus_name *set_bus_name_owner(struct gc *gc, struct bus_name *old,
					   int n, struct bus_name *name,
					   struct remote *r)
{
	if (name == NULL && !remote_owns_any_name(r, old, n)) {
		return old;
	}
	struct bus_name *v = gc_alloc(n, sizeof(struct bus_name));
	memcpy(v, old, sizeof(*v) * n);
	if (name) {
		name = v + (name - old);
		name->owner = r;
	} else {
		for (int i = 0; i < n; i++) {
			if (v[i].owner == r) {
				v[i].owner = NULL;
			}
		}
	}
	gc_collect(gc, old, NULL);
	return v;
}

static void activate_remote(struct bus *b, struct remote *r)
{
	fprintf(stderr, "remote %d activated\n", r->id);
	struct rcu *d = start_rcu(b);
	d->remotes_v = add_unique_name(b->gc, d->remotes_v, d->remotes_n++, r);
	finish_rcu(b, d);
}

static void remove_remote(struct bus *b, struct remote *r)
{
	fprintf(stderr, "removing remote %u\n", r->id);

	// join and cleanup data used by the remote itself
	join_remote(r);
	dv_remove(&b->remotes, r);
	gc_unregister(b->gc, r->handle);

	// deregister it from the bus
	struct rcu *d = start_rcu(b);

	// remove it from the unique name list
	d->remotes_v =
		remove_unique_name(b->gc, d->remotes_v, d->remotes_n--, r);

	// release any named addresses
	d->names_v = set_bus_name_owner(b->gc, d->names_v, d->names_n, NULL, r);

	// cleanup the remote queues
	gc_collect(b->gc, r, &gc_remote);

	finish_rcu(b, d);
}

static int request_name(struct bus *b, struct remote *r, slice_t name)
{
	struct rcu *d = b->rcu;
	struct bus_name key = { .name = name };
	struct bus_name *n = bsearch(&key, d->names_v, d->names_n, sizeof(key),
				     &compare_bus_name);

	if (n == NULL) {
		return DBUS_REQUEST_NAME_NOT_ALLOWED;
	} else if (n->owner == r) {
		return DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
	} else if (n->owner) {
		return DBUS_REQUEST_NAME_REPLY_EXISTS;
	}

	d = start_rcu(b);
	d->names_v = set_bus_name_owner(b->gc, d->names_v, d->names_n, n, r);
	finish_rcu(b, d);

	return DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
}

static int release_name(struct bus *b, struct remote *r, slice_t name)
{
	struct rcu *d = b->rcu;
	struct bus_name key = { .name = name };
	struct bus_name *n = bsearch(&key, d->names_v, d->names_n, sizeof(key),
				     &compare_bus_name);

	if (n == NULL || n->owner == NULL) {
		return DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
	} else if (n->owner != r) {
		return DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
	}

	d = start_rcu(b);
	d->names_v = set_bus_name_owner(b->gc, d->names_v, d->names_n, n, NULL);
	finish_rcu(b, d);

	return DBUS_RELEASE_NAME_REPLY_RELEASED;
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
			case MSG_AUTHENTICATED: {
				struct msg_remote *m = (void *)e->data;
				activate_remote(m->remote->bus, m->remote);
				break;
			}
			case MSG_DISCONNECTED: {
				struct msg_remote *m = (void *)e->data;
				remove_remote(m->remote->bus, m->remote);
				break;
			}
			case CMD_REQUEST_NAME: {
				struct cmd_name *m = (void *)e->data;
				int res = request_name(m->remote->bus,
						       m->remote, m->name);

				struct rep_name r;
				r.errcode = res;
				r.reply_serial = m->reply_serial;
				msgq_send(m->remote->qcontrol, REP_REQUEST_NAME,
					  &r, sizeof(r), NULL);
				break;
			}

			case CMD_RELEASE_NAME: {
				struct cmd_name *m = (void *)e->data;
				int res = release_name(m->remote->bus,
						       m->remote, m->name);

				struct rep_name r;
				r.errcode = res;
				r.reply_serial = m->reply_serial;
				msgq_send(m->remote->qcontrol, REP_RELEASE_NAME,
					  &r, sizeof(r), NULL);
				break;
			}
			}
			msgq_pop(b.q, e);
		}

		struct pollfd pfd;
		pfd.fd = lfd;
		pfd.events = POLLIN;

		sigset_t sig;
		sigfillset(&sig);
		sigdelset(&sig, SIGMSGQ);

		int r = ppoll(&pfd, 1, NULL, &sig);
		if (r < 0 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		} else if (r < 0) {
			perror("poll");
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
