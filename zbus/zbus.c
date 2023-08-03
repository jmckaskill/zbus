#define _GNU_SOURCE
#include "sys.h"
#include "tx.h"
#include "rx.h"
#include "bus.h"
#include "config.h"
#include "dmem/log.h"
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
	char *fifopn = (char *)udata;

	set_thread_name(S("ready-fifo"));

	for (;;) {
		// Wait for a client to open the fifo for read. We then
		// immediately close it to indicate that we are ready to go
		int fd = open(fifopn, O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			ERROR("open ready fifo,error:%m,path:%s", fifopn);
			return -1;
		}
		DEBUG("open ready fifo");
		close(fd);
		usleep(1000);
	}
}

static int usage(void)
{
	fputs("usage: zbus [args] socket\n", stderr);
	fputs("\t-j\tLog as JSON\n", stderr);
	fputs("\t-v\tEnable verbose (default:disabled)\n", stderr);
	fputs("\t-q\tEnable quiet (default:disabled)\n", stderr);
	fputs("\t-C dir\tSet config directory (default:$PWD)\n", stderr);
	fputs("\t-f file\tFIFO to use as a ready indicator\n", stderr);
	return 2;
}

int main(int argc, char *argv[])
{
	set_thread_name(S("main"));

	const char *configdir = ".";
	char *readypn = NULL;
	int i;
	while ((i = getopt(argc, argv, "Chqvjf:")) > 0) {
		switch (i) {
		case 'j':
			log_type = LOG_JSON;
			break;
		case 'q':
			log_quiet_flag = 1;
			break;
		case 'v':
			log_verbose_flag = 1;
			break;
		case 'f':
			readypn = optarg;
			break;
		case 'C':
			configdir = optarg;
			break;
		case 'h':
		case '?':
			return usage();
		}
	}

	(void)configdir;

	argc -= optind;
	argv += optind;
	if (argc != 1) {
		fputs("unexpected arguments\n", stderr);
		return usage();
	}

	if (setup_signals()) {
		return 1;
	}

	char *sockpn = argv[0];
	struct bus bus;
	if (init_bus(&bus) || add_name(&bus, S("com.example.Service"), false) ||
	    add_name(&bus, S("com.example.Autostart"), true)) {
		return 1;
	}

	NOTICE("startup,sockpn:%s,busid:%.*s,fifo:%s", sockpn, S_PRI(bus.busid),
	       readypn);

	int lfd = bind_bus(sockpn);
	if (lfd < 0) {
		return 1;
	}

	NOTICE("ready");

	thrd_t thrd;
	if (readypn && !thrd_create(&thrd, &ready_indicator, readypn)) {
		thrd_detach(thrd);
	}

	for (;;) {
		int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
		if (cfd < 0) {
			ERROR("accept,errno:%m");
			break;
		}

		VERBOSE("new connection,fd:%d", cfd);

		struct tx *tx = new_tx(cfd);
		if (!tx) {
			close(cfd);
			continue;
		}

		struct rx *rx = new_rx(&bus, tx, cfd);
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

	destroy_bus(&bus);
	return 0;
}
