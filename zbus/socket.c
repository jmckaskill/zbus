#include "socket.h"

static inline char *x_strchrnul(const char *s, char ch)
{
	while (*s && *s != ch) {
		s++;
	}
	return (char *)s;
}

int zb_parse_address(char *address, const char **ptype, const char **phost,
		     const char **pport)
{
	char *end = x_strchrnul(address, ';');
	int ret = *end ? (end + 1 - address) : (end - address);
	*end = 0;

	char *colon = strchr(address, ':');
	if (!colon) {
		return -1;
	}
	*colon = 0;

	*ptype = address;
	*phost = "";
	*pport = "";

	char *next = colon + 1;
	for (;;) {
		char *key = next;
		char *comma = x_strchrnul(key, ',');
		next = *comma ? (comma + 1) : comma;
		*comma = 0;

		char *eq = memchr(key, comma - key, '=');
		if (!eq) {
			return -1;
		}
		char *value = eq + 1;
		*eq = 0;

		// Ignore unknown keys. These may be present for dbus-daemon
		if (!strcmp(address, "unix")) {
			if (!strcmp(key, "path")) {
				*ptype = "unix";
				*phost = value;
			} else if (!strcmp(key, "abstract")) {
				*ptype = "abstract";
				*phost = value;
			}
		} else if (!strcmp(address, "tcp")) {
			if (!strcmp(key, "host")) {
				*phost = value;
			} else if (!strcmp(key, "port")) {
				*pport = value;
			} else if (!strcmp(key, "family")) {
				if (!strcmp(value, "ipv4")) {
					*ptype = "tcp4";
				} else if (!strcmp(value, "ipv6")) {
					*ptype = "tcp6";
				} else {
					return -1;
				}
			}
		}
	}

	return ret;
}
