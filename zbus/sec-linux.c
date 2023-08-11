#define _GNU_SOURCE
#include "sec.h"

#ifdef HAVE_PROC_GROUPS
#include "lib/log.h"
#include "lib/print.h"
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>

static void parse_proc_groups(struct security *c, int max_groups, pid_t pid,
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

int load_security(struct txconn *c, struct security **pp)
{
	if (!g_enable_security) {
		*pp = NULL;
		return 0;
	}

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
		parse_proc_groups(p, max_groups, uc.pid, f);
		fclose(f);
	} else {
		p->groups.v[0] = uc.gid;
		p->groups.n = 1;
		WARN("unable to get supplementary groups,errno:%m,pid:%d",
		     (int)uc.pid);
	}
	*pp = p;
	return 0;
}

#endif
