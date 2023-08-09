#pragma once

#include <stdlib.h>
#include <stdbool.h>

struct pidinfo {
	int pid;
	int uid;
	struct {
		int n;
		int v[0];
	} groups;
};

int new_socket_pidinfo(int fd, struct pidinfo **pp);
bool has_group(const struct pidinfo *p, int group);
int lookup_group(const char *name);
static inline void free_pidinfo(struct pidinfo *p)
{
	free(p);
}
