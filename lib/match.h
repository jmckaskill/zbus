#pragma once
#include "types.h"

struct match {
	const char *base;
	uint16_t str_len;
	uint16_t sender_off;
	uint16_t interface_off;
	uint16_t member_off;
	uint16_t path_off;
	uint8_t sender_len;
	uint8_t interface_len;
	uint8_t member_len;
	uint8_t path_len;
	uint8_t include_children;
};

void init_match(struct match *m);
void gc_match(void *);

// decode_match parses a match string. This function is more strict than the
// standard requires. No backslashes or escaping is allowed. Type must be
// 'signal'. Destination, args, etc can not be filtered on. Returns non-zero on
// error, zero on success.
int decode_match(struct match *m, const char *p, size_t sz);

bool path_matches(const struct match *m, slice_t path);
bool member_matches(const struct match *m, slice_t member);

static inline slice_t match_sender(const struct match *m)
{
	return make_slice(m->base + m->sender_off, m->sender_len);
}

static inline slice_t match_interface(const struct match *m)
{
	return make_slice(m->base + m->interface_off, m->interface_len);
}
