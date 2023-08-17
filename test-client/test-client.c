#include "client/client.h"
#include "lib/log.h"

static inline void must(int error, const char *cmd)
{
	if (error) {
		FATAL("command failed,cmd:%s,errno:%m", cmd);
	}
}

static int remaining_client_replies;

static int on_list_names(void *udata, struct client *c, struct zb_message *m,
			 struct zb_iterator *ii)
{
	unregister_cb(c, m->reply_serial);
	remaining_client_replies--;

	if (m->error) {
		ERROR("ListNames,error:%s", m->error->p);
	} else {
		struct zb_scope array;
		zb_enter_array(ii, &array);
		while (zb_array_has_more(ii, &array)) {
			const zb_str8 *str = zb_parse_str8(ii);
			if (!str) {
				FATAL("failed to parse ListNames reply");
			}
			VERBOSE("ListName,name:%s", str->p);
		}
	}
	must(zb_get_iter_error(ii), "parse ListNames reply");
	return 0;
}

static int on_test_signal(void *udata, struct client *c, struct zb_message *m,
			  struct zb_iterator *ii)
{
	remaining_client_replies--;
	const char *match = udata;
	switch (m->type) {
	case ZB_REPLY:
		LOG("TestSignal registered,match:%s", match);
		break;
	case ZB_ERROR:
		ERROR("failed to register TestSignal,error:%s,match:%s",
		      m->error->p, match);
		break;
	case ZB_SIGNAL: {
		uint32_t u = zb_parse_u32(ii);
		size_t sz;
		const char *str = zb_parse_string(ii, &sz);
		LOG("recv TestSignal,number:%u,string:%.*s,match:%s", u,
		    (int)sz, str, match);
		break;
	}
	}
	return 0;
}

static int on_test_method(void *udata, struct client *c, struct zb_message *m,
			  struct zb_iterator *ii)
{
	unregister_cb(c, m->reply_serial);
	remaining_client_replies--;

	if (m->error) {
		ERROR("TestMethod,error:%s", m->error->p);
	} else {
		uint32_t u = zb_parse_u32(ii);
		size_t sz;
		const char *str = zb_parse_string(ii, &sz);
		int err = zb_get_iter_error(ii);
		LOG("TestMethod reply,number:%u,string:%.*s,parse:%d", u,
		    (int)sz, str, err);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		return 2;
	}

	g_log_level = LOG_DEBUG;

	struct client *c = open_client(argv[1]);

	uint32_t list_names = register_cb(c, &on_list_names, NULL);
	must(!list_names, "register ListNames");
	must(call_bus_method(c, list_names, ZB_S8("\011ListNames"), ""),
	     "send ListNames");
	remaining_client_replies++;

	const char *ucast = "sender='com.example.Service',"
			    "interface='com.example.Service',"
			    "member='TestSignal'";
	uint32_t test_signal = register_cb(c, &on_test_signal, (void *)ucast);
	must(!test_signal, "register TestSignal");
	must(call_bus_method(c, test_signal, ZB_S8("\010AddMatch"), "s", ucast),
	     "send AddMatch");
	remaining_client_replies += 2; // AddMatch response and signal

	const char *bcast = "interface='com.example.Service',"
			    "member='TestSignal2'";
	uint32_t test_signal2 = register_cb(c, &on_test_signal, (void *)bcast);
	must(!test_signal2, "register TestSignal");
	must(call_bus_method(c, test_signal2, ZB_S8("\010AddMatch"), "s",
			     bcast),
	     "send AddMatch");
	remaining_client_replies += 2; // AddMatch response and signal

	uint32_t test_method = register_cb(c, &on_test_method, NULL);
	must(!test_method, "register TestMethod");
	must(call_method(c, test_method, ZB_S8("\023com.example.Service"),
			 ZB_S8("\001/"), ZB_S8("\023com.example.Service"),
			 ZB_S8("\012TestMethod"), "us", 0, "TestString"),
	     "send TestMethod");
	remaining_client_replies++;

	if (read_auth(c)) {
		close_client(c);
		return 2;
	}

	struct zb_message m;
	struct zb_iterator ii;
	while (!read_message(c, &m, &ii) && !distribute_message(c, &m, &ii) &&
	       remaining_client_replies) {
	}

	must(call_method(c, 0, ZB_S8("\023com.example.Service"), ZB_S8("\001/"),
			 ZB_S8("\023com.example.Service"),
			 ZB_S8("\010Shutdown"), ""),
	     "send shutdown");

	close_client(c);
	return 0;
}
