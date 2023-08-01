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

	for (;;) {
		// Wait for a client to open the fifo for read. We then
		// immediately close it to indicate that we are ready to go
		int fd = open(fifopn, O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			start_log(LOG_ERROR, "open ready fifo", errno);
			log_cstring("path", fifopn);
			finish_log();
			return -1;
		}
		write_debug("open ready fifo");
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
	log_arg0 = "zbus";

	const char *configdir = ".";
	char *readypn = NULL;
	int i;
	while ((i = getopt(argc, argv, "Cshqvjf:")) > 0) {
		switch (i) {
		case 's':
			log_type = LOG_SYSLOG;
			break;
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

	if (setup_log() || setup_signals()) {
		return 1;
	}

	char *sockpn = argv[0];
	struct bus bus;
	if (init_bus(&bus) || add_name(&bus, S("com.example.Service"))) {
		return 1;
	}

	start_notice("startup");
	log_cstring("sockpn", sockpn);
	log_slice("busid", to_slice(bus.busid));
	log_cstring("fifo", readypn);
	finish_log();

	int lfd = bind_bus(sockpn);
	if (lfd < 0) {
		return 1;
	}

	write_notice("ready");

	thrd_t thrd;
	if (readypn && !thrd_create(&thrd, &ready_indicator, readypn)) {
		thrd_detach(thrd);
	}

	for (;;) {
		int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
		if (cfd < 0) {
			write_error("accept", errno);
			break;
		}

		start_notice("new connection");
		log_number("fd", cfd);
		finish_log();

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
