#pragma once
#include "log.h"
#include "zbus/zbus.h"

void log_message(struct logbuf *b, const struct zb_message *m);

static inline void log_string8(struct logbuf *b, const char *key,
			       const zb_str8 *s)
{
	log_nstring(b, key, s->p, s->len);
}
