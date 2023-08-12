#pragma once
#include "socket.h"
#include "dbus/types.h"
#include "dbus/stream.h"
#include "dbus/encode.h"
#include "dbus/decode.h"
#include "lib/log.h"

struct client;
typedef int (*message_fn)(void *, struct client *, struct message *,
			  struct iterator *);

struct message_cb {
	message_fn fn;
	void *udata;
};

struct client {
	fd_t fd;
	uint16_t cb_available;
	struct message_cb cbs[16];
	struct msg_stream in;
	char buf[0];
};

struct client *open_client(const char *sockpn);
void close_client(struct client *c);

uint32_t register_cb(struct client *c, message_fn fn, void *udata);
void unregister_cb(struct client *c, uint32_t serial);

int send_signal(struct client *c, const str8_t *path, const str8_t *iface,
		const str8_t *mbr, const char *sig, ...);
int vsend_signal(struct client *c, const str8_t *path, const str8_t *iface,
		 const str8_t *mbr, const char *sig, va_list ap);
int call_method(struct client *c, uint32_t serial, const str8_t *dst,
		const str8_t *path, const str8_t *iface, const str8_t *mbr,
		const char *sig, ...);
int vcall_method(struct client *c, uint32_t serial, const str8_t *dst,
		 const str8_t *path, const str8_t *iface, const str8_t *mbr,
		 const char *sig, va_list ap);
int call_bus_method(struct client *c, uint32_t serial, const str8_t *member,
		    const char *sig, ...);
int send_reply(struct client *c, const struct message *req, const char *sig,
	       ...);
int vsend_reply(struct client *c, const struct message *req, const char *sig,
		va_list ap);
int send_error(struct client *c, uint32_t request_serial, const str8_t *err);
int read_message(struct client *c, struct message *m, struct iterator *body);
int distribute_message(struct client *c, struct message *m,
		       struct iterator *body);
