#define _GNU_SOURCE
#include "bus.h"
#include "remote.h"
#include "messages.h"
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

DVECTOR_INIT(remote_ptr, struct remote *);

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

int run_bus(int lfd)
{
	int next_remote = 1;
	d_vector(remote_ptr) remotes = DV_INIT;

	char busid_buf[BUSID_BUFLEN];
	if (generate_busid(busid_buf)) {
		return -1;
	}
	slice_t busid = make_slice2(busid_buf, BUSID_LENGTH);

	struct rcu *r = rcu_new();

	struct rcu_root *d = RCU_ALLOC(struct rcu_root, 1);
	d->data.test_string = rcu_strdup("test");
	rcu_update(r, d);

	struct msgq *q = msgq_new();

	for (;;) {
		struct msgq_entry *e;
		while ((e = msgq_acquire(q)) != NULL) {
			switch (e->cmd) {
			case MSG_AUTHENTICATED: {
				struct msg_authenticated *m =
					MSGQ_DATA(e, MSG_AUTHENTICATED);
				fprintf(stderr, "remote %u is ready\n", m->id);
				break;
			}
			case MSG_DISCONNECTED: {
				struct msg_disconnected *m =
					MSGQ_DATA(e, MSG_DISCONNECTED);
				fprintf(stderr, "remote %u is closing\n",
					m->r->id);
				join_remote(m->r);
				dv_remove(&remotes, m->r);
				break;
			}
			}
			msgq_pop(q, e);
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

			struct remote *r =
				start_remote(q, busid, next_remote++, cfd);
			if (r == NULL) {
				close(cfd);
				continue;
			}

			dv_append1(&remotes, r);
		}
	}

	msgq_free(q);
	rcu_free(r);
	dv_free(remotes);
	return 0;
}
