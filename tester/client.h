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
int send_bus_method(struct client *c, slice_t member, const char *sig, ...);
int read_message(struct client *c, struct message *m, struct iterator *body);
int read_reply(struct client *c, int serial, struct iterator *body,
	       slice_t *perror);

static inline void log_slice(const char *key, slice_t s)
{
	log_nstring(key, s.p, s.len);
}

static inline void opt_log_number(const char *key, int num)
{
	if (num) {
		log_number(key, num);
	}
}

static inline void opt_log_slice(const char *key, slice_t s)
{
	if (s.len) {
		log_nstring(key, s.p, s.len);
	}
}

void log_message(struct client *c, const struct message *m);
