#define _GNU_SOURCE
#include "pid-unix.h"
#include "lib/log.h"
#include "lib/print.h"
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <grp.h>
#include <fcntl.h>
#include <stdio.h>

static void parse_proc_groups(struct pidinfo *c, int max_groups, pid_t pid,
			      FILE *f)
{
	char buf[256];
	while (fgets(buf, sizeof(buf), f)) {
		if (strncmp(buf, "Groups:\t", strlen("Groups:\t"))) {
			continue;
		}
		char *p = &buf[strlen("Groups:\t")];
		for (;;) {
			if (c->groups.n == max_groups) {
				WARN("too many supplementary groups,pid:%d",
				     (int)pid);
				break;
			}
			char *e;
			gid_t id = strtoul(p, &e, 10);
			if (p == e) {
				break;
			}
			c->groups.v[c->groups.n++] = id;
			p = e;
		}
		return;
	}

	if (ferror(f)) {
		WARN("error reading proc file,errno:%m,pid:%d", (int)pid);
	}
}

int new_socket_pidinfo(int fd, struct pidinfo **pp)
{
	struct ucred uc;
	socklen_t sz = sizeof(uc);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &sz)) {
		ERROR("failed to get peer credentials for fd,fd:%d,errno:%m",
		      fd);
		return -1;
	}
	int max_groups = sysconf(_SC_NGROUPS_MAX);
	struct pidinfo *c =
		fmalloc(sizeof(*c) + (max_groups * sizeof(c->groups.v[0])));
	c->pid = uc.pid;
	c->uid = uc.uid;

	// now try to get the full group list
	char path[32 + PRINT_UINT32_LEN];
	size_t n = strlen("/proc/");
	memcpy(&path[0], "/proc/", n);
	n += print_uint32(&path[n], uc.pid);
	memcpy(&path[n], "/status", strlen("/status"));
	n += strlen("/status");
	path[n] = 0;

	FILE *f = fopen(path, "r");
	if (f) {
		parse_proc_groups(c, max_groups, uc.pid, f);
		fclose(f);
	} else {
		c->groups.v[0] = uc.gid;
		c->groups.n = 1;
		WARN("unable to get supplementary groups,errno:%m,pid:%d",
		     (int)uc.pid);
	}
	*pp = c;
	return 0;
}

static int compare_gid(const void *key, const void *element)
{
	int k = (uintptr_t)key;
	int e = *(int *)element;
	return k - e;
}

bool has_group(const struct pidinfo *p, int group)
{
	if (group < 0) {
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
