#pragma once
#include "lib/types.h"
#include "lib/stream.h"
#include "lib/encode.h"
#include "lib/decode.h"
#include "dmem/log.h"

struct client;
typedef int (*message_fn)(void *, struct client *, struct message *,
			  struct iterator *);

struct message_cb {
	message_fn fn;
	void *udata;
};

struct client {
	int fd;
	uint16_t cb_available;
	struct message_cb cbs[16];
	struct msg_stream in;
};

struct client *open_client(const char *sockpn);
void close_client(struct client *c);

uint32_t register_cb(struct client *c, message_fn fn, void *udata);
void unregister_cb(struct client *c, uint32_t serial);

int send_signal(struct client *c, slice_t path, slice_t iface, slice_t mbr,
		const char *sig, ...);
int vsend_signal(struct client *c, slice_t path, slice_t iface, slice_t mbr,
		 const char *sig, va_list ap);
int call_method(struct client *c, uint32_t serial, slice_t dst, slice_t path,
		slice_t iface, slice_t mbr, const char *sig, ...);
int vcall_method(struct client *c, uint32_t serial, slice_t dst, slice_t path,
		 slice_t iface, slice_t mbr, const char *sig, va_list ap);
int call_bus_method(struct client *c, uint32_t serial, slice_t member,
		    const char *sig, ...);
int send_reply(struct client *c, const struct message *req, const char *sig,
	       ...);
int vsend_reply(struct client *c, const struct message *req, const char *sig,
		va_list ap);
int send_error(struct client *c, uint32_t request_serial, slice_t err);
int read_message(struct client *c, struct message *m, struct iterator *body);
int distribute_message(struct client *c, struct message *m,
		       struct iterator *body);
