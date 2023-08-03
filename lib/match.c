#include "match.h"
#include "decode.h"
#include <assert.h>

static int add_match_field(struct match *m, slice_t key, slice_t val)
{
	switch (key.len) {
	case 4:
		if (slice_eq(key, S("type"))) {
			return !slice_eq(val, S("signal"));

		} else if (slice_eq(key, S("path"))) {
			if (m->path_len) {
				return -1;
			}
			assert(!check_path(val));
			m->path_len = (uint8_t)val.len;
			m->path_off = (uint16_t)(val.p - m->base);
			m->include_children = false;
			return 0;
		} else {
			return 0;
		}
	case 6:
		if (slice_eq(key, S("sender"))) {
			if (m->sender_len) {
				return -1;
			}
			assert(!check_address(val));
			m->sender_len = (uint8_t)val.len;
			m->sender_off = (uint16_t)(val.p - m->base);
			return 0;
		} else if (slice_eq(key, S("member"))) {
			if (m->member_len) {
				return -1;
			}
			assert(!check_member(val));
			m->member_len = (uint8_t)val.len;
			m->member_off = (uint16_t)(val.p - m->base);
			return 0;
		} else {
			return 0;
		}
	case 9:
		if (slice_eq(key, S("interface"))) {
			if (m->interface_len) {
				return -1;
			}
			assert(!check_interface(val));
			m->interface_len = (uint8_t)val.len;
			m->interface_off = (uint16_t)(val.p - m->base);
			return 0;
		} else {
			// eavesdrop through matches is not supported.
			// Use the monitoring interface instead.
			return slice_eq(key, S("eavesdrop"));
		}
	case 11:
		// filtering for a message bound for a different
		// destination is not supported. And you don't
		// need a match if it's for you.
		return slice_eq(key, S("destination"));
	case 14:
		if (slice_eq(key, S("path_namespace"))) {
			if (m->path_len) {
				return -1;
			}
			assert(!check_path(val));
			if (val.len && val.p[val.len - 1] == '/') {
				// remove trailing slashes, including if
				// this is a root path update "/" to "".
				// This simplifies the match logic.
				val.len--;
			}
			m->path_len = (uint8_t)val.len;
			m->path_off = (uint16_t)(val.p - m->base);
			m->include_children = true;
			return 0;
		} else {
			return 0;
		}
	default:
		return 0;
	}
}

int decode_match(struct match *m, const char *s, size_t len)
{
	if (len > UINT16_MAX) {
		return -1;
	}

	m->base = s;
	const char *end = s + len;
	while (s < end) {
		// check for a range that does not include backslashes or
		// spaces, terminating at an equals sign
		slice_t key;
		key.p = s;
		for (;;) {
			if (s == end || *s == '\\' || *s == ' ') {
				return -1;
			} else if (*s == '=') {
				break;
			}
			s++;
		}
		key.len = s++ - key.p;

		// check that next we have an apostrophe
		if (s == end || *s != '\'') {
			return -1;
		}
		s++;

		// check for a range that does not include backslashes finishing
		// at another apostrophe
		slice_t val;
		val.p = s;
		for (;;) {
			if (s == end || *s == '\\') {
				return -1;
			} else if (*s == '\'') {
				break;
			}
			s++;
		}
		val.len = s++ - val.p;
		if (val.len > UINT8_MAX) {
			return -1;
		}

		if (add_match_field(m, key, val)) {
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

bool path_matches(const struct match *m, slice_t path)
{
	if (!m->path_len) {
		return true;
	}
	if (m->include_children ? (path.len < m->path_len) :
				  (path.len != m->path_len)) {
		return false;
	}
	if (memcmp(m->base + m->path_len, path.p, path.len)) {
		return false;
	}
	return path.len == m->path_len ||
	       (m->include_children && path.p[m->path_len] == '/');
}

bool member_matches(const struct match *m, slice_t member)
{
	return !m->member_len ||
	       (m->member_len == member.len &&
		!memcmp(m->base + m->member_off, member.p, member.len));
}
