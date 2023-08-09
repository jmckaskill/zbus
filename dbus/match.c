#include "match.h"
#include "decode.h"
#include <assert.h>

#define INCLUDE_CHILDREN 0x8000
#define PATH_OFF_MASK 0x7FFF

static int add_match_field(struct match *m, char *base, char *key, size_t klen,
			   str8_t *val)
{
	switch (klen) {
	case 4:
		if (!memcmp(key, "type", 4)) {
			return !str8eq(val, S8("\006signal"));

		} else if (!memcmp(key, "path", 4)) {
			if (m->path_off) {
				return -1;
			}
			m->path_off = (char *)val - base;
			return 0;
		} else {
			return 0;
		}
	case 6:
		if (!memcmp(key, "sender", 6)) {
			if (m->sender_off) {
				return -1;
			}
			m->sender_off = (char *)val - base;
			return 0;
		} else if (!memcmp(key, "member", 6)) {
			if (m->member_off) {
				return -1;
			}
			m->member_off = (char *)val - base;
			return 0;
		} else {
			return 0;
		}
	case 9:
		if (!memcmp(key, "interface", 9)) {
			if (m->interface_off) {
				return -1;
			}
			m->interface_off = (char *)val - base;
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
			m->path_off = INCLUDE_CHILDREN | ((char *)val - base);
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
	m->len = len;
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
		// end apostrophe with a nul to create a str8_t
		str8_t *str = (str8_t *)(val - 1);
		str->len = vlen;
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

bool path_matches(const char *base, struct match m, const str8_t *path)
{
	if (!m.path_off) {
		return true;
	}
	const str8_t *mp = match_part(base, m.path_off & PATH_OFF_MASK);
	if (m.path_off & INCLUDE_CHILDREN) {
		return path->len >= mp->len &&
		       !memcmp(mp->p, path->p, mp->len) &&
		       (path->len == mp->len || path->p[mp->len] == '/');
	} else {
		return str8eq(mp, path);
	}
}
