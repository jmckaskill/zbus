#pragma once
#include "types.h"
#include "dmem/log.h"

static inline void log_slice(struct logbuf *b, const char *key, slice_t s)
{
	log_nstring(b, key, (int)s.len, s.p);
}

void log_message(struct logbuf *b, const struct message *m);
