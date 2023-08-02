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

static inline void must(int error, const char *cmd)
{
	if (error) {
		FATAL("command failed,cmd:%s,errno:%m", cmd);
	}
}

static int run_client(void *udata)
{
	const char *sockpn = udata;

	struct client *c = open_client(sockpn);

	int serial = call_bus_method(c, S("ListNames"), "");
	must(serial < 0, "send ListNames");

	slice_t error;
	struct iterator ii;
	int err = read_reply(c, serial, &ii, &error);
	must(err, "get ListNames reply");
	if (error.len) {
		ERROR("ListNames,error:%.*s", S_PRI(error));
	} else if (start_verbose("ListNames reply")) {
		struct array_data ad = parse_array(&ii);
		while (array_has_more(&ii, &ad)) {
			slice_t str = parse_string(&ii);
			log_nstring("name", S_PRI(str));
		}
		finish_log();
	}
	must(iter_error(&ii), "parse ListNames reply");

	serial = call_method(c, S("com.example.Service"), S("/"),
			     S("com.example.Service"), S("TestMethod"), "us", 0,
			     S("TestString"));
	must(serial < 0, "call TestMethod");

	err = read_reply(c, serial, &ii, &error);
	must(err, "get TestMethod reply");
	if (error.len) {
		ERROR("TestMethod,error:%.*s", S_PRI(error));
	} else {
		uint32_t u = parse_uint32(&ii);
		slice_t str = parse_string(&ii);
		int err = iter_error(&ii);
		NOTICE("TestMethod reply,number:%u,string:%.*s,parse:%d", u,
		       S_PRI(str), err);
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

	int serial = call_bus_method(c, S("RequestName"), "su",
				     S("com.example.Service"), (uint32_t)0);
	must(serial < 0, "call RequestName");

	slice_t err;
	struct iterator ii;
	must(read_reply(c, serial, &ii, &err), "get RequestName reply");

	if (err.len) {
		ERROR("RequestName failed,error:%.*s", S_PRI(err));
	} else {
		int errcode = parse_uint32(&ii);
		if (errcode != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
			ERROR("RequestName failed,errcode:%d", errcode);
		}
	}

	must(iter_error(&ii), "parse RequestName reply");
	return c;
}

static void server_message(struct client *c, const struct message *m,
			   struct iterator *ii)
{
	if (slice_eq(m->member, S("TestMethod"))) {
		uint32_t u = parse_uint32(ii);
		slice_t str = parse_string(ii);
		NOTICE("server TestMethod,number:%d,string:%.*s", u,
		       S_PRI(str));
		int err = send_reply(c, m, "us", u + 1, S("response"));
		must(err, "send TestMethod reply");
	}
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

	if (setup_log(LOG_TEXT, -1, "tester")) {
		return 1;
	}

	VERBOSE("startup");

	if (readypn != NULL) {
		NOTICE("waiting for server ready,fifopn:%s", readypn);
		int rfd = open(readypn, O_RDONLY);
		must(rfd < 0, "open ready fifo");
		close(rfd);
	}

	NOTICE("opening dbus socket,path:%s", sockpn);

	struct client *c = start_server(sockpn);
	(void)c;

	thrd_t thrd;
	if (thrd_create(&thrd, &run_client, sockpn) != thrd_success) {
		ERROR("failed to start client thread,errno:%m");
		return 1;
	}

	struct message m;
	struct iterator ii;
	while (!read_message(c, &m, &ii)) {
		if (m.type == MSG_METHOD &&
		    slice_eq(m.interface, S("com.example.Service"))) {
			server_message(c, &m, &ii);
		}
	}

	thrd_join(thrd, NULL);
	close_client(c);
	return 0;
}
