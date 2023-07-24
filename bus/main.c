#define _GNU_SOURCE
#include "bus.h"
#include "lib/log.h"
#include "lib/str.h"
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <threads.h>

#define ERR_FAILED 1
#define ERR_INVALID_ARG 2

static int ready_indicator(void *udata)
{
	char *fifopn = (char *)udata;

	for (;;) {
		// Wait for a client to open the fifo for read. We then
		// immediately close it to indicate that we are ready to go
		int fd = open(fifopn, O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			ELOG("open ready indicator: %m");
			return -1;
		}
		close(fd);
		usleep(1000);
	}
}

static int usage()
{
	fputs("usage: bus [args] socket\n", stderr);
	fputs("    -v     	Enable verbose (default:disabled)\n", stderr);
	fputs("    -f file    	FIFO to use as a ready indicator\n", stderr);
	return ERR_INVALID_ARG;
}

int main(int argc, char *argv[])
{
	char *readypn = NULL;
	int i;
	while ((i = getopt(argc, argv, "hqvf:")) > 0) {
		switch (i) {
		case 'f':
			readypn = optarg;
			break;
		case 'q':
			log_quiet = 1;
			break;
		case 'v':
			log_verbose = 1;
			break;
		case 'h':
		case '?':
			return usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc != 1) {
		fputs("unexpected arguments\n", stderr);
		return usage();
	}

	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	char *sockpn = argv[0];

	if (setup_signals()) {
		return ERR_FAILED;
	}

	unlink(sockpn);
	int lfd = bind_bus(sockpn);
	if (lfd < 0) {
		return ERR_FAILED;
	}

	thrd_t thrd;
	if (readypn && !thrd_create(&thrd, &ready_indicator, readypn)) {
		thrd_detach(thrd);
	}

	return run_bus(lfd);
}
