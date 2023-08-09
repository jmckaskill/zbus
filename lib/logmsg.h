#pragma once
#include "dbus/types.h"
#include "log.h"

void log_message(struct logbuf *b, const struct message *m);

static inline void log_string8(struct logbuf *b, const char *key,
			       const str8_t *s)
{
	log_nstring(b, key, s->p, s->len);
}
