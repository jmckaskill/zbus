#include "client/client.h"
#include "lib/log.h"

static inline void must(int error, const char *cmd)
{
	if (error) {
		FATAL("command failed,cmd:%s,errno:%m", cmd);
	}
}

#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER 1
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE 2
#define DBUS_REQUEST_NAME_REPLY_EXISTS 3
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER 4

static int on_request_name(void *udata, struct client *c, struct zb_message *m,
			   struct zb_iterator *ii)
{
	unregister_cb(c, m->reply_serial);

	if (m->error) {
		FATAL("RequestName failed,error:%s", m->error->p);
	} else {
		int errcode = zb_parse_u32(ii);
		if (errcode == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
			LOG("RequestName OK");
		} else {
			FATAL("RequestName failed,errcode:%d", errcode);
		}
	}
	return 0;
}

static int server_message(struct client *c, const struct zb_message *m,
			  struct zb_iterator *ii)
{
	if (zb_eq_str8(m->member, ZB_S8("\012TestMethod"))) {
		uint32_t u = zb_parse_u32(ii);
		size_t sz;
		const char *str = zb_parse_string(ii, &sz);
		LOG("server TestMethod,number:%d,string:%.*s", u, (int)sz, str);
		int err = send_reply(c, m, "us", u + 1, "response");
		must(err, "send TestMethod reply");

		err = send_signal(c, ZB_S8("\001/"),
				  ZB_S8("\023com.example.Service"),
				  ZB_S8("\012TestSignal"), "su", "TestString",
				  14);
		must(err, "send TestSignal");

		err = send_signal(c, ZB_S8("\005/path"),
				  ZB_S8("\023com.example.Service"),
				  ZB_S8("\013TestSignal2"), "su", "TestString2",
				  15);
		must(err, "send TestSignal2");
		return 0;
	} else if (zb_eq_str8(m->member, ZB_S8("\010Shutdown"))) {
		LOG("shutdown");
		return 1;
	} else {
		FATAL("unexpected server message");
		return 1;
	}
}

int main(int argc, char *argv[])
{
	const char *sockpn = argv[1];
	if (argc != 2) {
		sockpn = getenv("DBUS_STARTER_ADDRESS");
		if (!sockpn) {
			ERROR("no address specified");
			return 2;
		}
	}

	g_log_level = LOG_DEBUG;

	LOG("opening dbus socket,path:%s", sockpn);

	struct client *c = open_client(sockpn);

	uint32_t request_name = register_cb(c, &on_request_name, NULL);
	must(call_bus_method(c, request_name, ZB_S8("\013RequestName"), "su",
			     "com.example.Service", (uint32_t)0),
	     "send RequestName");

	if (read_auth(c)) {
		close_client(c);
		return 2;
	}

	for (;;) {
		struct zb_message m;
		struct zb_iterator ii;
		if (read_message(c, &m, &ii)) {
			close_client(c);
			return 2;
		}
		if (m.type == ZB_METHOD && m.interface &&
		    zb_eq_str8(m.interface, ZB_S8("\023com.example.Service"))) {
			if (server_message(c, &m, &ii)) {
				break;
			}
		} else if (distribute_message(c, &m, &ii)) {
			break;
		}
	}

	close_client(c);
	return 0;
}
