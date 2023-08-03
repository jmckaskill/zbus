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

static int on_list_names(void *udata, struct client *c, struct message *m,
			 struct iterator *ii)
{
	unregister_cb(c, m->reply_serial);

	if (m->error.len) {
		ERROR("ListNames,error:%.*s", S_PRI(m->error));
	} else if (start_verbose("ListNames reply")) {
		struct array_data ad = parse_array(ii);
		while (array_has_more(ii, &ad)) {
			slice_t str = parse_string(ii);
			log_nstring("name", S_PRI(str));
		}
		finish_log();
	}
	must(iter_error(ii), "parse ListNames reply");
	return 0;
}

static int on_test_signal(void *udata, struct client *c, struct message *m,
			  struct iterator *ii)
{
	const char *match = udata;
	switch (m->type) {
	case MSG_REPLY:
		NOTICE("TestSignal registered,match:%s", match);
		break;
	case MSG_ERROR:
		ERROR("failed to register TestSignal,error:%.*s,match:%s",
		      S_PRI(m->error), match);
		break;
	case MSG_SIGNAL: {
		uint32_t u = parse_uint32(ii);
		slice_t str = parse_string(ii);
		NOTICE("recv TestSignal,number:%u,string:%.*s,match:%s", u,
		       S_PRI(str), match);
		break;
	}
	}
	return 0;
}

static int on_test_method(void *, struct client *c, struct message *m,
			  struct iterator *ii)
{
	unregister_cb(c, m->reply_serial);

	if (m->error.len) {
		ERROR("TestMethod,error:%.*s", S_PRI(m->error));
	} else {
		uint32_t u = parse_uint32(ii);
		slice_t str = parse_string(ii);
		int err = iter_error(ii);
		NOTICE("TestMethod reply,number:%u,string:%.*s,parse:%d", u,
		       S_PRI(str), err);
	}

	return 0;
}

static int run_client(void *udata)
{
	const char *sockpn = udata;

	struct client *c = open_client(sockpn);

	uint32_t list_names = register_cb(c, &on_list_names, NULL);
	must(!list_names, "register ListNames");
	must(call_bus_method(c, list_names, S("ListNames"), ""),
	     "send ListNames");

	slice_t ucast = S("sender='com.example.Service',"
			  "interface='com.example.Service',"
			  "member='TestSignal'");
	uint32_t test_signal = register_cb(c, &on_test_signal, (void *)ucast.p);
	must(!test_signal, "register TestSignal");
	must(call_bus_method(c, test_signal, S("AddMatch"), "s", ucast),
	     "send AddMatch");

	slice_t bcast = S("interface='com.example.Service',"
			  "member='TestSignal2'");
	uint32_t test_signal2 =
		register_cb(c, &on_test_signal, (void *)bcast.p);
	must(!test_signal2, "register TestSignal");
	must(call_bus_method(c, test_signal2, S("AddMatch"), "s", bcast),
	     "send AddMatch");

	uint32_t test_method = register_cb(c, &on_test_method, NULL);
	must(!test_method, "register TestMethod");
	must(call_method(c, test_method, S("com.example.Service"), S("/"),
			 S("com.example.Service"), S("TestMethod"), "us", 0,
			 S("TestString")),
	     "send TestMethod");

	struct message m;
	struct iterator ii;
	while (!read_message(c, &m, &ii) && !distribute_message(c, &m, &ii)) {
	}

	close_client(c);
	return 0;
}

#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER 1
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE 2
#define DBUS_REQUEST_NAME_REPLY_EXISTS 3
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER 4

static int on_request_name(void *, struct client *c, struct message *m,
			   struct iterator *ii)
{
	unregister_cb(c, m->reply_serial);

	if (m->error.len) {
		FATAL("RequestName failed,error:%.*s", S_PRI(m->error));
	} else {
		int errcode = parse_uint32(ii);
		if (errcode != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
			FATAL("RequestName failed,errcode:%d", errcode);
		}
	}
	return 1;
}

static struct client *start_server(const char *sockpn)
{
	struct client *c = open_client(sockpn);

	uint32_t request_name = register_cb(c, &on_request_name, NULL);
	must(call_bus_method(c, request_name, S("RequestName"), "su",
			     S("com.example.Service"), (uint32_t)0),
	     "send RequestName");

	for (;;) {
		struct message m;
		struct iterator ii;
		if (read_message(c, &m, &ii)) {
			close_client(c);
			return NULL;
		}
		if (distribute_message(c, &m, &ii)) {
			return c;
		}
	}
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

		err = send_signal(c, S("/"), S("com.example.Service"),
				  S("TestSignal"), "su", S("TestString"), 14);
		must(err, "send TestSignal");

		err = send_signal(c, S("/path"), S("com.example.Service"),
				  S("TestSignal2"), "su", S("TestString2"), 15);
		must(err, "send TestSignal2");
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
