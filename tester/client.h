#pragma once
#include "lib/types.h"
#include "lib/stream.h"
#include "lib/encode.h"
#include "lib/decode.h"
#include "dmem/log.h"

struct client {
	int fd;
	int next_serial;
	struct msg_stream in;
};

struct client *open_client(const char *sockpn);
void close_client(struct client *c);

int send_signal(struct client *c, slice_t path, slice_t iface, slice_t mbr,
		const char *sig, ...);
int vsend_signal(struct client *c, slice_t path, slice_t iface, slice_t mbr,
		 const char *sig, va_list ap);
int call_method(struct client *c, slice_t dst, slice_t path, slice_t iface,
		slice_t mbr, const char *sig, ...);
int vcall_method(struct client *c, slice_t dst, slice_t path, slice_t iface,
		 slice_t mbr, const char *sig, va_list ap);
int call_bus_method(struct client *c, slice_t member, const char *sig, ...);
int send_reply(struct client *c, const struct message *reql, const char *sig,
	       ...);
int vsend_reply(struct client *c, const struct message *req, const char *sig,
		va_list ap);
int send_error(struct client *c, uint32_t request_serial, slice_t err);
int read_message(struct client *c, struct message *m, struct iterator *body);
int read_reply(struct client *c, int serial, struct iterator *body,
	       slice_t *perror);
