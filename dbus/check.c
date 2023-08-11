#include "check.h"

int check_path(const char *s, size_t len)
{
	if (!len || len > 255 || *s != '/') {
		// path must begin with / and can not be the empty string
		return -1;
	}
	if (len == 1) {
		// trailing / only allowed if the path is "/"
		return 0;
	}
	const char *p = s + 1;
	const char *end = s + len;
	const char *segment = p;
	while (p < end) {
		// only [A-Z][a-z][0-9]_ are allowed
		// / and \0 are not allowed as the first char of a segment
		// this rejects multiple / in sequence and a trailing /
		// respectively
		if (('A' <= *p && *p <= 'Z') || ('a' <= *p && *p <= 'z') ||
		    ('0' <= *p && *p <= '9') || *p == '_') {
			p++;
		} else if (p > segment && *p == '/') {
			segment = ++p;
		} else {
			return -1;
		}
	}

	// trailing / not allowed
	return p == segment;
}

int check_member(const char *s, size_t len)
{
	if (!len || len > 255) {
		return -1;
	}
	const char *p = p;
	const char *begin = p;
	const char *end = p + len;
	while (p < end) {
		// must be composed of [A-Z][a-z][0-9]_ and must not start with
		// a digit
		if (('A' <= *p && *p <= 'Z') || ('a' <= *p && *p <= 'z') ||
		    *p == '_' || (p > begin && '0' <= *p && *p <= '9')) {
			p++;
		} else {
			return -1;
		}
	}
	return 0;
}

int check_interface(const char *s, size_t len)
{
	if (len > 255) {
		return -1;
	}
	int have_dot = 0;
	const char *p = s;
	const char *segment = s;
	const char *end = s + len;
	while (p < end) {
		// must be composed of [A-Z][a-z][0-9]_ and must not start with
		// a digit segments can not be zero length ie no two dots in a
		// row nor a leading dot the name as a whole must comprise at
		// least two segments ie have a dot and must not be longer than
		// the requested size
		if (('A' <= *p && *p <= 'Z') || ('a' <= *p && *p <= 'z') ||
		    *p == '_' || (p > segment && '0' <= *p && *p <= '9')) {
			p++;
		} else if (p > segment && *p == '.') {
			segment = ++p;
			have_dot = 1;
		} else {
			return -1;
		}
	}

	return p == segment || !have_dot;
}

int check_unique_address(const char *s, size_t len)
{
	if (!len || *s != ':' || len > 255) {
		return -1;
	}
	const char *p = s + 1;
	const char *end = s + len;
	int have_dot = 0;
	const char *segment = p;
	while (p < end) {
		// must start with a :
		// must be composed of at least two segments separated by a dot
		// segments must be composed of [A-Z][a-z][0-9]_
		// segments can not be zero length
		if (('A' <= *p && *p <= 'Z') || ('a' <= *p && *p <= 'z') ||
		    *p == '_' || ('0' <= *p && *p <= '9')) {
			p++;
		} else if (p > segment && *p == '.') {
			segment = ++p;
			have_dot = 1;
		} else {
			return -1;
		}
	}

	return p == segment || !have_dot;
}

int check_address(const char *s, size_t len)
{
	return check_unique_address(s, len) && check_known_address(s, len);
}