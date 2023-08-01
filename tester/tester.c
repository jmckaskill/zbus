#define _GNU_SOURCE
#include "client.h"
#include "lib/encode.h"
#include "lib/decode.h"
#include "lib/stream.h"
#include "dmem/log.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdalign.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <threads.h>

static inline void must(int iserr, const char *msg, int syserr)
{
	if (iserr) {
		write_abort(msg, syserr);
	}
}

static int run_client(void *udata)
{
	const char *sockpn = udata;

	struct client *c = open_client(sockpn);

	int serial = send_bus_method(c, S("ListNames"), "");
	must(serial < 0, "failed to send ListNames", 0);

	slice_t err;
	struct iterator ii;
	must(read_reply(c, serial, &ii, &err), "failed to get ListNames reply",
	     errno);
	if (err.len) {
		start_error("ListNames error", 0);
		log_slice("error", err);
		finish_log();
	} else if (start_verbose("ListNames reply")) {
		struct array_data ad = parse_array(&ii);
		while (array_has_more(&ii, &ad)) {
			slice_t str = parse_string(&ii);
			log_slice("name", str);
		}
		finish_log();
		must(iter_error(&ii), "ListNames reply parse error", 0);
	}

	close_client(c);
	return 0;
}

#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER 1
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE 2
#define DBUS_REQUEST_NAME_REPLY_EXISTS 3
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER 4

static struct client *start_server(const char *sockpn)
{
	struct client *c = open_client(sockpn);

	int serial = send_bus_method(c, S("RequestName"), "su",
				     S("com.example.Service"), (uint32_t)0);
	must(serial < 0, "call request name failed", 0);

	slice_t err;
	struct iterator ii;
	must(read_reply(c, serial, &ii, &err),
	     "failed to get request name reply", 0);

	if (err.len) {
		start_abort("request name failed", 0);
		log_slice("error", err);
		finish_log();
	} else {
		int errcode = parse_uint32(&ii);
		if (iter_error(&ii) ||
		    errcode != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
			start_abort("request name failed", 0);
			log_number("parse error", iter_error(&ii));
			log_number("errcode", errcode);
			finish_log();
		}
	}

	return c;
}

static int usage(void)
{
	fputs("usage: tester [args] socket\n", stderr);
	fputs("    -v     	Enable verbose (default:disabled)\n", stderr);
	fputs("    -f file    	FIFO to use as a ready indicator\n", stderr);
	return 2;
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
			log_quiet_flag = 1;
			break;
		case 'v':
			log_verbose_flag = 1;
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
	char *sockpn = argv[0];

	if (setup_log()) {
		return 1;
	}

	write_verbose("startup");

	if (readypn != NULL) {
		start_notice("waiting for server to be ready by opening FIFO");
		log_cstring("path", readypn);
		finish_log();
		int rfd = open(readypn, O_RDONLY);
		must(rfd < 0, "failed to open ready fifo", errno);
		close(rfd);
	}

	write_notice("opening dbus socket");
	log_cstring("path", sockpn);
	finish_log();

	struct client *c = start_server(sockpn);
	(void)c;

	thrd_t thrd;
	if (thrd_create(&thrd, &run_client, sockpn) != thrd_success) {
		write_error("failed to start client thread", errno);
		return 1;
	}
	thrd_detach(thrd);

	sleep(100000);

	return 0;
}
