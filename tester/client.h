#pragma once
#include "socket.h"
#include "dbus/types.h"
#include "dbus/stream.h"
#include "dbus/encode.h"
#include "dbus/decode.h"
#include "lib/log.h"

struct client;
typedef int (*message_fn)(void *, struct client *, struct zb_message *,
			  struct zb_iterator *);

struct zb_message_cb {
	message_fn fn;
	void *udata;
	uint16_t counter;
};

struct client {
	fd_t fd;
	uint16_t cb_available;
	struct zb_message_cb cbs[16];
	struct zb_stream in;
};

struct client *open_client(const char *sockpn);
void close_client(struct client *c);

uint32_t register_cb(struct client *c, message_fn fn, void *udata);
void unregister_cb(struct client *c, uint32_t serial);

int send_signal(struct client *c, const zb_str8 *path, const zb_str8 *iface,
		const zb_str8 *mbr, const char *sig, ...);
int vsend_signal(struct client *c, const zb_str8 *path, const zb_str8 *iface,
		 const zb_str8 *mbr, const char *sig, va_list ap);
int call_method(struct client *c, uint32_t serial, const zb_str8 *dst,
		const zb_str8 *path, const zb_str8 *iface, const zb_str8 *mbr,
		const char *sig, ...);
int vcall_method(struct client *c, uint32_t serial, const zb_str8 *dst,
		 const zb_str8 *path, const zb_str8 *iface, const zb_str8 *mbr,
		 const char *sig, va_list ap);
int call_bus_method(struct client *c, uint32_t serial, const zb_str8 *member,
		    const char *sig, ...);
int send_reply(struct client *c, const struct zb_message *req, const char *sig,
	       ...);
int vsend_reply(struct client *c, const struct zb_message *req, const char *sig,
		va_list ap);
int send_error(struct client *c, uint32_t request_serial, const zb_str8 *err);
int read_auth(struct client *c);
int read_message(struct client *c, struct zb_message *m, struct zb_iterator *body);
int distribute_message(struct client *c, struct zb_message *m,
		       struct zb_iterator *body);
