#include "client.h"
#include "dbus/encode.h"
#include "dbus/decode.h"
#include "dbus/stream.h"
#include "lib/log.h"
#include "lib/threads.h"
#include <stdio.h>
#include <stdalign.h>

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

	if (m->error) {
		ERROR("ListNames,error:%s", m->error->p);
	} else {
		struct array_data ad = parse_array(ii);
		while (array_has_more(ii, &ad)) {
			const str8_t *str = parse_string8(ii);
			VERBOSE("ListName,name:%s", str->p);
		}
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
		LOG("TestSignal registered,match:%s", match);
		break;
	case MSG_ERROR:
		ERROR("failed to register TestSignal,error:%s,match:%s",
		      m->error->p, match);
		break;
	case MSG_SIGNAL: {
		uint32_t u = parse_uint32(ii);
		size_t sz;
		const char *str = parse_string(ii, &sz);
		LOG("recv TestSignal,number:%u,string:%.*s,match:%s", u,
		    (int)sz, str, match);
		break;
	}
	}
	return 0;
}

static int on_test_method(void *udata, struct client *c, struct message *m,
			  struct iterator *ii)
{
	unregister_cb(c, m->reply_serial);

	if (m->error) {
		ERROR("TestMethod,error:%s", m->error->p);
	} else {
		uint32_t u = parse_uint32(ii);
		size_t sz;
		const char *str = parse_string(ii, &sz);
		int err = iter_error(ii);
		LOG("TestMethod reply,number:%u,string:%.*s,parse:%d", u,
		    (int)sz, str, err);
	}

	return 0;
}

static int on_autostart(void *udata, struct client *c, struct message *m,
			struct iterator *ii)
{
	unregister_cb(c, m->reply_serial);

	if (m->error) {
		ERROR("Autostart,error:%.*s", S_PRI(*m->error));
	} else {
		LOG("autostart hello");
	}

	return 0;
}

static int run_client(void *udata)
{
	const char *sockpn = udata;

	struct client *c = open_client(sockpn);

	uint32_t list_names = register_cb(c, &on_list_names, NULL);
	must(!list_names, "register ListNames");
	must(call_bus_method(c, list_names, S8("\011ListNames"), ""),
	     "send ListNames");

	const char *ucast = "sender='com.example.Service',"
			    "interface='com.example.Service',"
			    "member='TestSignal'";
	uint32_t test_signal = register_cb(c, &on_test_signal, (void *)ucast);
	must(!test_signal, "register TestSignal");
	must(call_bus_method(c, test_signal, S8("\010AddMatch"), "s", ucast),
	     "send AddMatch");

	const char *bcast = "interface='com.example.Service',"
			    "member='TestSignal2'";
	uint32_t test_signal2 = register_cb(c, &on_test_signal, (void *)bcast);
	must(!test_signal2, "register TestSignal");
	must(call_bus_method(c, test_signal2, S8("\010AddMatch"), "s", bcast),
	     "send AddMatch");

	uint32_t test_method = register_cb(c, &on_test_method, NULL);
	must(!test_method, "register TestMethod");
	must(call_method(c, test_method, S8("\023com.example.Service"),
			 S8("\001/"), S8("\023com.example.Service"),
			 S8("\012TestMethod"), "us", 0, "TestString"),
	     "send TestMethod");

	uint32_t test_autostart = register_cb(c, &on_autostart, NULL);
	must(!test_autostart, "register autostart");
	must(call_method(c, test_autostart, S8("\025com.example.Autostart"),
			 S8("\001/"), S8("\023com.example.Service"),
			 S8("\005Hello"), ""),
	     "send autostart");

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

static int on_request_name(void *udata, struct client *c, struct message *m,
			   struct iterator *ii)
{
	unregister_cb(c, m->reply_serial);

	if (m->error) {
		FATAL("RequestName failed,error:%.*s", S_PRI(*m->error));
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
	must(call_bus_method(c, request_name, S8("\013RequestName"), "su",
			     "com.example.Service", (uint32_t)0),
	     "send RequestName");

	if (read_auth(c)) {
		close_client(c);
		return NULL;
	}

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
	if (str8eq(m->member, S8("\012TestMethod"))) {
		uint32_t u = parse_uint32(ii);
		size_t sz;
		const char *str = parse_string(ii, &sz);
		LOG("server TestMethod,number:%d,string:%.*s", u, (int)sz, str);
		int err = send_reply(c, m, "us", u + 1, "response");
		must(err, "send TestMethod reply");

		err = send_signal(c, S8("\001/"), S8("\023com.example.Service"),
				  S8("\012TestSignal"), "su", "TestString", 14);
		must(err, "send TestSignal");

		err = send_signal(c, S8("\005/path"),
				  S8("\023com.example.Service"),
				  S8("\013TestSignal2"), "su", "TestString2",
				  15);
		must(err, "send TestSignal2");
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		return 2;
	}

	g_log_level = LOG_DEBUG;
	char *sockpn = argv[1];

	VERBOSE("startup");
	LOG("opening dbus socket,path:%s", sockpn);

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
		if (m.type == MSG_METHOD && m.interface &&
		    str8eq(m.interface, S8("\023com.example.Service"))) {
			server_message(c, &m, &ii);
		}
	}

	thrd_join(thrd, NULL);
	close_client(c);
	return 0;
}
