#pragma once
#include "types.h"

struct zb_matcher {
	uint16_t len;
	uint16_t sender_off;
	uint16_t interface_off;
	uint16_t member_off;
	uint16_t path_off;
};

// zb_decode_match parses a match string. This function is more strict than the
// standard requires. No backslashes or escaping is allowed. Type must be
// 'signal'. Destination, args, etc can not be filtered on. Returns non-zero on
// error, zero on success.
ZB_EXTERN int zb_decode_match(struct zb_matcher *m, char *s, size_t len);

ZB_EXTERN bool zb_path_matches(const char *base, const struct zb_matcher m,
			       const zb_str8 *path);

ZB_INLINE const zb_str8 *_zb_match_part(const char *p, uint16_t off)
{
	return off ? (const zb_str8 *)(p + off) : NULL;
}

ZB_INLINE const zb_str8 *zb_match_sender(const char *p, struct zb_matcher m)
{
	return _zb_match_part(p, m.sender_off);
}

ZB_INLINE const zb_str8 *zb_match_interface(const char *p, struct zb_matcher m)
{
	return _zb_match_part(p, m.interface_off);
}

ZB_INLINE const zb_str8 *zb_match_member(const char *p, struct zb_matcher m)
{
	return _zb_match_part(p, m.member_off);
}
