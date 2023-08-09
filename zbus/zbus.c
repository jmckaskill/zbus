#define _GNU_SOURCE
#include "sys.h"
#include "tx.h"
#include "rx.h"
#include "bus.h"
#include "config.h"
#include "lib/log.h"
#include <signal.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <threads.h>
#include <sys/socket.h>
#include <errno.h>

static int ready_indicator(void *udata)
{
	str8_t *fifopn = udata;

	set_thread_name("ready-fifo");

	for (;;) {
		// Wait for a client to open the fifo for read. We then
		// immediately close it to indicate that we are ready to go
		int fd = open(fifopn->p, O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			ERROR("open ready fifo,error:%m,path:%s", fifopn->p);
			free(fifopn);
			return -1;
		}
		DEBUG("open ready fifo");
		close(fd);
		usleep(1000);
	}
}

static int usage(void)
{
	fputs("usage: zbus [args]\n", stderr);
	fputs("\t-f config\tLoad config file\n", stderr);
	fputs("\t-c 'foo=bar'\tLoad config item\n", stderr);
	return 2;
}

int main(int argc, char *argv[])
{
	set_thread_name("main");

	struct config_loader ldr;
	init_config(&ldr);

	int i;
	while ((i = getopt(argc, argv, "hf:c:")) > 0) {
		switch (i) {
		case 'f':
			if (add_config_file(&ldr, optarg)) {
				return 1;
			}
			break;
		case 'c':
			if (add_config_cmdline(&ldr, optarg)) {
				return 1;
			}
			break;
		case 'h':
		case '?':
			return usage();
		}
	}

	if (argc - optind) {
		fputs("unexpected arguments\n", stderr);
		return usage();
	}

	struct bus b;
	if (setup_signals() || init_bus(&b)) {
		return 1;
	}
	load_config(&ldr, &b);

	const struct rcu_data *d = rcu_root(b.rcu);
	const struct config *c = d->config;

	if (!c->sockpn && c->sockfd < 0) {
		FATAL("no socket specified in config");
	}

	VERBOSE("startup,listen:%s,listenfd:%d,busid:%s", c->sockpn->p,
		c->sockfd, b.busid.p);

	int lfd = c->sockfd >= 0 ? c->sockfd : bind_bus(c->sockpn->p);
	if (lfd < 0) {
		return 1;
	}
	if (lfd > 0 && dup2(lfd, 0) != 0) {
		return 1;
	}
	close(lfd);
	lfd = 0;

	VERBOSE("ready");

	if (c->readypn) {
		VERBOSE("starting ready fifo thread,file:%s", c->readypn->p);
		thrd_t thrd;
		if (!thrd_create(&thrd, &ready_indicator,
				 str8dup(c->readypn))) {
			thrd_detach(thrd);
		}
	}

	int next_id = 1;

	for (;;) {
		int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
		if (cfd < 0) {
			ERROR("accept,errno:%m");
			break;
		}

		VERBOSE("new connection,fd:%d", cfd);

		struct tx *tx = new_tx(cfd, next_id++);
		if (!tx) {
			close(cfd);
			continue;
		}

		struct rx *rx = new_rx(&b, tx, cfd);
		deref_tx(tx);
		if (!rx) {
			continue;
		}

		thrd_t thrd;
		if (thrd_create(&thrd, &rx_thread, rx) == thrd_success) {
			thrd_detach(thrd);
		} else {
			free_rx(rx);
		}
	}

	destroy_bus(&b);
	return 0;
}
