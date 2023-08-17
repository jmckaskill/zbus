#define _GNU_SOURCE
#include "sec.h"

#if HAVE_PROC_GROUPS
#include "lib/log.h"
#include "lib/print.h"
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>

static void parse_proc_groups(struct security *c, int max_groups, int pid,
			      FILE *f)
{
	char buf[256];
	while (fgets(buf, sizeof(buf), f)) {
		if (strncmp(buf, "Groups:\t", strlen("Groups:\t"))) {
			continue;
		}
		char *p = &buf[strlen("Groups:\t")];
		while (*p && *p != '\n') {
			if (c->groups.n == max_groups) {
				WARN("too many supplementary groups,pid:%d",
				     pid);
				break;
			}
			int id;
			int n = parse_pos_int(p, &id);
			if (n <= 0) {
				WARN("failed to parse group,val:%s,pid:%d", p,
				     pid);
				break;
			}
			c->groups.v[c->groups.n++] = (int)id;
			p += n;
			if (*p == ' ') {
				p++;
			}
		}
		return;
	}

#ifndef NDEBUG
	// has_group relies on the group list being sorted
	for (int i = 0; i < c->groups.n - 1; i++) {
		assert(c->groups.v[i] < c->groups.v[i + 1]);
	}
#endif

	if (ferror(f)) {
		WARN("error reading proc file,errno:%m,pid:%d", (int)pid);
	}
}

int load_security(struct txconn *c, struct security **pp)
{
	struct ucred uc;
	socklen_t sz = sizeof(uc);
	if (getsockopt(c->fd, SOL_SOCKET, SO_PEERCRED, &uc, &sz)) {
		ERROR("failed to get peer credentials for fd,fd:%d,errno:%m",
		      c->fd);
		return -1;
	}
	int max_groups = sysconf(_SC_NGROUPS_MAX);
	struct security *p =
		fmalloc(sizeof(*p) + (max_groups * sizeof(p->groups.v[0])));
	p->pid = uc.pid;
	p->uid = uc.uid;
	p->groups.n = 0;

	// now try to get the full group list
	char path[32 + PRINT_UINT32_LEN];
	size_t n = strlen("/proc/");
	memcpy(&path[0], "/proc/", n);
	n += print_uint32(&path[n], uc.pid);
	memcpy(&path[n], "/status", strlen("/status"));
	n += strlen("/status");
	path[n] = 0;

	FILE *f = fopen(path, "r");
	if (!f) {
		ERROR("unable to get supplementary groups,errno:%m,pid:%d",
		      (int)uc.pid);
		free(p);
		return -1;
	}
	parse_proc_groups(p, max_groups, uc.pid, f);
	fclose(f);
	*pp = p;
	return 0;
}

#endif
