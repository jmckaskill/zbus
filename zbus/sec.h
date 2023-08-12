#pragma once
#include "config.h"
#include "lib/socket.h"
#include "dbus/str8.h"
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define GROUP_UNKNOWN 0
#define GROUP_ANY -1
#define GROUP_NOBODY -2

struct security {
	uint32_t pid;

#if HAVE_UID
	uint32_t uid;
#endif

#if HAVE_SID
	char *sid;
#elif defined HAVE_GID
	struct {
		int n;
		int v[0];
	} groups;
#endif
};

extern bool g_enable_security;

int load_security(struct txconn *c, struct security **pp);
void free_security(struct security *p);

int getentropy(void *buf, size_t sz);

#if HAVE_GID
bool has_group(const struct security *p, int group);
int lookup_group(const char *name);
#else
#define has_group(P, GRP) (true)
#endif
