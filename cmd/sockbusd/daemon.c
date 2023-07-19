#define _GNU_SOURCE
#include "lib/str.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>

#define ERR_FAILED 1
#define ERR_INVALID_ARG 5
#define MAX_CHILDREN 64

static char busid[33];
static char *busdir;
static const char *sockbusp = "sockbusp";
static int verbose = 0;
static int childpipe[2];
static int termpipe[2];
static int childn;
static pid_t childv[MAX_CHILDREN];
static int opened;

static int usage()
{
	fputs("usage: sockbusd [args] [--] dbus-socket sockdir\n", stderr);
	fputs("  -p path    sockbusp binary (default:sockbusp)\n", stderr);
	fputs("  -v         Enable verbose (default:disabled)\n", stderr);
	return ERR_INVALID_ARG;
}

static void sigchild(int)
{
	char buf[1] = { 0 };
	write(childpipe[1], buf, 1);
}

static void sigterm(int)
{
	char buf[1] = { 0 };
	write(termpipe[1], buf, 1);
}

static void make_pipe(int *p)
{
	if (pipe(p) || fcntl(p[0], F_SETFD, FD_CLOEXEC) ||
	    fcntl(p[1], F_SETFD, FD_CLOEXEC) ||
	    fcntl(p[0], F_SETFL, O_NONBLOCK) ||
	    fcntl(p[1], F_SETFL, O_NONBLOCK)) {
		perror("childpipe");
		exit(ERR_FAILED);
	}
}

static void child_process(int sock)
{
	struct ucred cred;
	socklen_t credlen = sizeof(cred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &credlen)) {
		perror("failed to get peer credentials");
		exit(ERR_FAILED);
	}

	// set our uid, gid, pgid to match the peer
	// TODO set the cgroups to match
	pid_t pgid = getpgid(cred.pid);
	if (pgid < 0) {
		fprintf(stderr,
			"WARN failed to get process group id for %d: %s\n",
			cred.pid, strerror(errno));
	} else if (setpgid(0, pgid)) {
		fprintf(stderr, "WARN failed to set process group to %d: %s\n",
			pgid, strerror(errno));
	}
	if (setuid(cred.uid) || setgid(cred.gid)) {
		fprintf(stderr, "WARN failed to set uid/gid to %d/%d: %s\n",
			cred.uid, cred.gid, strerror(errno));
	}

	char fdstr[32];
	sprintf(fdstr, "%d", sock);

	int argn = 0;
	char *argv[8];

	argv[argn++] = "sockbusp";
	if (verbose) {
		argv[argn++] = "-v";
	}
	argv[argn++] = "-f";
	argv[argn++] = fdstr;
	argv[argn++] = "-d";
	argv[argn++] = busdir;
	argv[argn++] = busid;
	argv[argn] = NULL;

	execvp(sockbusp, argv);
	fprintf(stderr, "failed to execute %s: %s\n", sockbusp,
		strerror(errno));
	exit(ERR_FAILED);
}

static void spawn_children(int sock)
{
	while (childn < MAX_CHILDREN) {
		int client = accept(sock, NULL, NULL);
		if (client < 0 && errno == EINTR) {
			continue;
		} else if (client < 0 &&
			   (errno == EAGAIN || errno == EWOULDBLOCK)) {
			break;
		}

		int pid = fork();
		if (pid < 0) {
			perror("fork failed");
			exit(ERR_FAILED);
		} else if (!pid) {
			child_process(client);
		}

		childv[childn++] = pid;
		close(client);
	}
}

static void consume_selfpipe(int fd)
{
	for (;;) {
		// consume whatever is in the buffer
		char buf[128];
		int r = read(fd, buf, sizeof(buf));
		if (r < 0 && errno == EINTR) {
			continue;
		} else if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			break;
		} else if (r <= 0) {
			perror("childpipe read");
			exit(ERR_FAILED);
		}
	}
}

static void kill_children()
{
	for (int i = 0; i < childn; i++) {
		if (verbose) {
			fprintf(stderr, "terminating child %d\n", childv[i]);
		}
		kill(childv[i], SIGTERM);
	}
}

static void reap_children()
{
	for (;;) {
		int sts;
		pid_t pid = waitpid(-1, &sts, WNOHANG);
		if (pid <= 0) {
			break;
		}
		if (WIFSIGNALED(sts)) {
			if (verbose || opened) {
				fprintf(stderr, "child %d terminated with %d\n",
					pid, WTERMSIG(sts));
			}
		} else if (WIFEXITED(sts)) {
			if (verbose || WEXITSTATUS(sts)) {
				fprintf(stderr, "child %d exited with %d\n",
					pid, WEXITSTATUS(sts));
			}
		}

		// remove the child from our list
		int o = 0;
		for (int i = 0; i < childn; i++) {
			if (childv[i] != pid) {
				childv[o++] = childv[i];
			}
		}
		childn = o;

		// clean up the socket our children left behind
		// char buf[256];
		// str_t s = MAKE_STR(buf);
		// if (!str_addf(&s, "%s/:%d.0", busdir, pid)) {
		// 	unlink(s.p);
		// }
	}
}

int main(int argc, char *argv[])
{
	for (;;) {
		int i = getopt(argc, argv, "hzvp:");
		if (i < 0) {
			break;
		}
		switch (i) {
		case 'v':
			verbose = 1;
			break;
		case 'p':
			sockbusp = optarg;
			break;
		case 'h':
		case '?':
			return usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		fprintf(stderr, "missing arguments\n");
		return usage();
	}

	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	make_pipe(childpipe);
	make_pipe(termpipe);

	signal(SIGCHLD, &sigchild);
	signal(SIGINT, &sigterm);
	signal(SIGTERM, &sigterm);

	char *sockpath = argv[0];
	busdir = argv[1];

	static const char hex_enc[] = "0123456789abcdef";
	uint8_t rand[16];
	if (getentropy(rand, sizeof(rand))) {
		perror("getentropy");
		return ERR_FAILED;
	}
	for (int i = 0; i < sizeof(rand); i++) {
		busid[2 * i] = hex_enc[rand[i] >> 4];
		busid[2 * i + 1] = hex_enc[rand[i] & 15];
	}
	busid[sizeof(busid) - 1] = 0;

	if (verbose) {
		fprintf(stderr,
			"launching daemon with busdir %s and busid %s\n",
			busdir, busid);
		fprintf(stderr, "creating dbus-1 socket at %s\n", sockpath);
	}

	int sock = socket(AF_UNIX, SOCK_STREAM, PF_UNIX);
	if (!sock || fcntl(sock, F_SETFD, FD_CLOEXEC) ||
	    fcntl(sock, F_SETFL, O_NONBLOCK)) {
		perror("failed to create unix socket");
		return ERR_FAILED;
	}

	unlink(sockpath);

	union {
		struct sockaddr_un sun;
		struct sockaddr sa;
	} a;
	size_t pathlen = strlen(sockpath);
	if (pathlen + 1 > sizeof(a.sun.sun_path)) {
		fprintf(stderr, "socket pathname %s is too long\n", sockpath);
		return usage();
	}
	a.sun.sun_family = AF_UNIX;
	memcpy(a.sun.sun_path, sockpath, pathlen + 1);

	socklen_t salen = offsetof(struct sockaddr_un, sun_path) + pathlen + 1;
	if (bind(sock, &a.sa, salen) || listen(sock, SOMAXCONN)) {
		fprintf(stderr, "failed to bind socket %s: %s\n", sockpath,
			strerror(errno));
		return ERR_FAILED;
	}

	struct pollfd pfd[3];
	pfd[0].fd = childpipe[0];
	pfd[0].events = POLLIN;
	pfd[0].revents = 0;
	pfd[1].fd = termpipe[0];
	pfd[1].events = POLLIN;
	pfd[1].revents = 0;
	pfd[2].fd = sock;
	pfd[2].events = POLLIN;
	pfd[2].revents = POLLIN;

	opened = 1;

	for (;;) {
		if (pfd[0].revents) {
			consume_selfpipe(childpipe[0]);
			reap_children();
		}
		if (opened && pfd[1].revents) {
			consume_selfpipe(termpipe[0]);
			kill_children();
			close(sock);
			opened = 0;
		}
		if (opened && pfd[2].revents) {
			spawn_children(sock);
		}
		pfd[2].events = childn < MAX_CHILDREN ? POLLIN : 0;

		if (!childn && !opened) {
			break;
		}

		int r = poll(pfd, opened ? 3 : 1, -1);
		if (r < 0 && errno != EINTR) {
			perror("poll");
			return ERR_FAILED;
		}
	}

	if (verbose) {
		fprintf(stderr, "exiting\n");
	}

	close(termpipe[0]);
	close(termpipe[1]);
	close(childpipe[0]);
	close(childpipe[1]);
	return 0;
}
