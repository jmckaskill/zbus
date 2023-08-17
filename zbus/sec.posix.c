#include "sec.h"

#if HAVE_UNIX_GROUPS
#include <stdlib.h>
#include <grp.h>
#include <sys/types.h>

static int compare_gid(const void *key, const void *element)
{
	int k = (int)(uintptr_t)key;
	int e = *(int *)element;
	return k - e;
}

bool has_group(const struct security *p, int group)
{
	if (group == GROUP_ANY) {
		// anyone can access this resource
		return true;
	}
	if (p == NULL || group == GROUP_NOBODY) {
		// we failed to lookup info for this remote
		return false;
	}
	return bsearch((void *)(uintptr_t)group, p->groups.v, p->groups.n,
		       sizeof(p->groups.v[0]), &compare_gid) != NULL;
}

int lookup_group(const char *name)
{
	if (!strcmp(name, "any")) {
		return GROUP_ANY;
	} else if (!strcmp(name, "nobody")) {
		return GROUP_NOBODY;
	}

	struct group *g = getgrnam(name);
	return g ? g->gr_gid : GROUP_UNKNOWN;
}

void free_security(struct security *p)
{
	free(p);
}

#endif
