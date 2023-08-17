#pragma once
#include "dbus/zbus.h"

struct match {
	uint16_t len;
	uint16_t sender_off;
	uint16_t interface_off;
	uint16_t member_off;
	uint16_t path_off;
};

// decode_match parses a match string. This function is more strict than the
// standard requires. No backslashes or escaping is allowed. Type must be
// 'signal'. Destination, args, etc can not be filtered on. Returns non-zero on
// error, zero on success.
int decode_match(struct match *m, char *s, size_t len);

bool path_matches(const char *base, const struct match m, const zb_str8 *path);

static inline const zb_str8 *_match_part(const char *p, uint16_t off)
{
	return off ? (const zb_str8 *)(p + off) : NULL;
}

static inline const zb_str8 *match_sender(const char *p, struct match m)
{
	return _match_part(p, m.sender_off);
}

static inline const zb_str8 *match_interface(const char *p, struct match m)
{
	return _match_part(p, m.interface_off);
}

static inline const zb_str8 *match_member(const char *p, struct match m)
{
	return _match_part(p, m.member_off);
}
