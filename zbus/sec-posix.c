#define _POSIX_C_SOURCE
#include "sec.h"

#ifdef HAVE_GID
#include <stdlib.h>
#include <grp.h>
#include <sys/types.h>

bool g_enable_security;

static int compare_gid(const void *key, const void *element)
{
	int k = (uintptr_t)key;
	int e = *(int *)element;
	return k - e;
}

bool has_group(const struct security *p, int group)
{
	if (!g_enable_security || group < 0) {
		// anyone can access this resource
		return true;
	}
	if (p == NULL) {
		// we failed to lookup info for this remote
		return false;
	}
	return bsearch((void *)(uintptr_t)group, p->groups.v, p->groups.n,
		       sizeof(p->groups.v[0]), &compare_gid) != NULL;
}

int lookup_group(const char *name)
{
	struct group *g = getgrnam(name);
	return g ? g->gr_gid : -1;
}

void free_security(struct security *p)
{
	free(p);
}

#endif
