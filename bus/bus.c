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

#define BUS_DESTINATION "org.freedesktop.DBus"

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
	if (str_add(&s, sockpn)) {
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
	b->rcu = gc_alloc(1, sizeof(*b->rcu));
	memset(b->rcu, 0, sizeof(*b->rcu));
	update_rcu(b->gc, b->rcu);

	return 0;
}

static void destroy_bus(struct bus *b)
{
	assert(b->remotes.size == 0);

	for (int i = 0; i < b->rcu->names_n; i++) {
		gc_collect(b->gc, b->rcu->names_v[i], NULL);
	}
	gc_collect(b->gc, b->rcu->names_v, NULL);
	gc_collect(b->gc, b->rcu->remotes_v, NULL);
	gc_collect(b->gc, b->rcu, NULL);
	msgq_free(b->q);
	free_gc(b->gc);
	dv_free(b->remotes);
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

static void activate_remote(struct bus *b, struct remote *r)
{
	fprintf(stderr, "remote %d activated\n", r->id);
	struct rcu *d = gc_alloc(1, sizeof(struct rcu));
	struct rcu *old = b->rcu;
	*d = *old;

	struct unique_name *v =
		gc_alloc(d->remotes_n + 1, sizeof(struct unique_name));

	// copy the remotes list over inserting the new remote in place
	int i = 0;
	while (i < d->remotes_n && d->remotes_v[i].id < r->id) {
		v[i] = d->remotes_v[i];
		i++;
	}
	v[i].id = r->id;
	v[i].owner = r;
	while (i < d->remotes_n) {
		v[i + 1] = d->remotes_v[i];
		i++;
	}

	d->remotes_v = v;
	d->remotes_n++;

	// mark the old data for collection
	gc_collect(b->gc, old, NULL);
	gc_collect(b->gc, old->remotes_v, NULL);

	// update the other remotes
	update_rcu(b->gc, d);
	b->rcu = d;

	// and collect the garbage
	run_gc(b->gc);
}

static void remove_remote(struct bus *b, struct remote *r)
{
	fprintf(stderr, "removing remote %u\n", r->id);

	// deregister it from the bus first
	struct rcu *d = gc_alloc(1, sizeof(struct rcu));
	struct rcu *old = b->rcu;
	*d = *old;

	struct unique_name *v =
		gc_alloc(d->remotes_n - 1, sizeof(struct unique_name));

	// copy the remotes list over removing the remote
	int i = 0;
	while (d->remotes_v[i].id != r->id) {
		v[i] = d->remotes_v[i];
		i++;
	}
	while (i < d->remotes_n) {
		v[i - 1] = d->remotes_v[i];
		i++;
	}

	d->remotes_v = v;
	d->remotes_n--;

	// mark the old rcu data for collection
	gc_collect(b->gc, old, NULL);
	gc_collect(b->gc, old->remotes_v, NULL);
	gc_collect(b->gc, r, &gc_remote);

	// update the other remotes
	update_rcu(b->gc, d);
	b->rcu = d;

	// join the thread
	join_remote(r);

	// and then cleanup unneeded memory
	dv_remove(&b->remotes, r);
	gc_unregister(b->gc, r->handle);
	run_gc(b->gc);
}

static void request_name(struct bus *b, struct remote *r, slice_t name)
{
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
				struct msg_authenticated *m = (void *)e->data;
				activate_remote(m->remote->bus, m->remote);
				break;
			}
			case MSG_DISCONNECTED: {
				struct msg_disconnected *m = (void *)e->data;
				remove_remote(m->remote->bus, m->remote);
				break;
			}
			case CMD_REQUEST_NAME: {
				struct cmd_request_name *m = (void *)e->data;
				request_name(m->remote->bus, m->remote,
					     m->name);
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
