#pragma once
#include "types.h"
#include "dmem/log.h"

static inline void log_slice(const char *key, slice_t s)
{
	log_nstring(key, (int)s.len, s.p);
}

void log_message(const struct message *m);
