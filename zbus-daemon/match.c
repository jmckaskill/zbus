#include "match.h"
#include "zbus/zbus.h"
#include <assert.h>

#define INCLUDE_CHILDREN 0x8000
#define PATH_OFF_MASK 0x7FFF

static int add_match_field(struct match *m, char *base, char *key, size_t klen,
			   zb_str8 *val)
{
	switch (klen) {
	case 4:
		if (!memcmp(key, "type", 4)) {
			return !zb_eq_str8(val, ZB_S8("\006signal"));

		} else if (!memcmp(key, "path", 4)) {
			if (m->path_off) {
				return -1;
			}
			m->path_off = (uint16_t)((char *)val - base);
			return 0;
		} else {
			return 0;
		}
	case 6:
		if (!memcmp(key, "sender", 6)) {
			if (m->sender_off) {
				return -1;
			}
			m->sender_off = (uint16_t)((char *)val - base);
			return 0;
		} else if (!memcmp(key, "member", 6)) {
			if (m->member_off) {
				return -1;
			}
			m->member_off = (uint16_t)((char *)val - base);
			return 0;
		} else {
			return 0;
		}
	case 9:
		if (!memcmp(key, "interface", 9)) {
			if (m->interface_off) {
				return -1;
			}
			m->interface_off = (uint16_t)((char *)val - base);
			return 0;
		} else if (!memcmp(key, "eavesdrop", 9)) {
			// eavesdrop through matches is not supported.
			// Use the monitoring interface instead.
			return -1;
		} else {
			return 0;
		}
	case 11:
		// filtering for a message bound for a different
		// destination is not supported. And you don't
		// need a match if it's for you.
		if (!memcmp(key, "destination", 11)) {
			return -1;
		} else {
			return 0;
		}
	case 14:
		if (!memcmp(key, "path_namespace", 14)) {
			if (m->path_off) {
				return -1;
			}
			// remove trailing slashes, including if
			// this is a root path update "/" to "".
			// This simplifies the match logic.
			if (val->len && val->p[val->len - 1] == '/') {
				val->len--;
				val->p[val->len] = 0;
			}
			m->path_off = INCLUDE_CHILDREN |
				      (uint16_t)((char *)val - base);
			return 0;
		} else {
			return 0;
		}
	default:
		return 0;
	}
}

int decode_match(struct match *m, char *s, size_t len)
{
	if (len > PATH_OFF_MASK) {
		return -1;
	}

	memset(m, 0, sizeof(*m));
	m->len = (uint16_t)len;
	char *base = s;
	const char *end = s + len;
	while (s < end) {
		// check for a range that does not include backslashes or
		// spaces, terminating at an equals sign
		char *key = s;
		for (;;) {
			if (s == end || *s == '\\' || *s == ' ' || *s == '\0') {
				return -1;
			} else if (*s == '=') {
				break;
			}
			s++;
		}
		size_t klen = s++ - key;

		// check that next we have an apostrophe
		if (s == end || *s != '\'') {
			return -1;
		}

		// check for a range that does not include backslashes finishing
		// at another apostrophe
		char *val = ++s;
		for (;;) {
			if (s == end || *s == '\\' || *s == '\0') {
				return -1;
			} else if (*s == '\'') {
				break;
			}
			s++;
		}
		size_t vlen = s++ - val;
		if (vlen > UINT8_MAX) {
			return -1;
		}
		// replace the beginning apostrophe with the string size and the
		// end apostrophe with a nul to create a zb_str8
		zb_str8 *str = (zb_str8 *)(val - 1);
		str->len = (uint8_t)vlen;
		str->p[vlen] = 0;

		if (add_match_field(m, base, key, klen, str)) {
			return -1;
		}

		// check for a comma
		if (s == end) {
			break;
		} else if (*s != ',') {
			return -1;
		}
		s++;
	}

	return 0;
}

bool path_matches(const char *base, const struct match m, const zb_str8 *path)
{
	if (!m.path_off) {
		return true;
	}
	const zb_str8 *mp = _match_part(base, m.path_off & PATH_OFF_MASK);
	if (m.path_off & INCLUDE_CHILDREN) {
		return path->len >= mp->len &&
		       !memcmp(mp->p, path->p, mp->len) &&
		       (path->len == mp->len || path->p[mp->len] == '/');
	} else {
		return zb_eq_str8(mp, path);
	}
}
