#define _GNU_SOURCE
#include <uuid/uuid.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <fcntl.h>

#define ERR_FAILED 1
#define ERR_INVALID_ARG 5

static int usage(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	fprintf(stderr, format, ap);
	va_end(ap);
	fputs("usage: sockbusd [args] [--] dbus-socket sockdir busid\n",
	      stderr);
	fputs("  -p path    sockbusp binary (default:sockbusp)\n", stderr);
	fputs("  -v         Enable verbose (default:disabled)\n", stderr);
	return ERR_INVALID_ARG;
}

static int child_process(int sock, const char *sockbusp, char *busdir,
			 char *busid)
{
	struct ucred cred;
	socklen_t credlen = sizeof(cred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &credlen)) {
		perror("failed to get peer credentials");
		return ERR_FAILED;
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

	// Set up the unix client socket as stdin and stdout
	// As these are duplicates they do not have cloexec.
	dup2(sock, 1);
	dup2(sock, 0);
	close(sock);

	char *argv[] = {
		"sockbusp", "-v", busdir, busid, NULL,
	};

	execvp(sockbusp, argv);
	fprintf(stderr, "failed to execute %s: %s\n", sockbusp,
		strerror(errno));
	return -1;
}

static const char hex_bytes[] = "0123456789abcdef";

int main(int argc, char *argv[])
{
	long verbose = 0;
	const char *sockbusp = "/bin/sockbusp";
	for (;;) {
		int i = getopt(argc, argv, "zvp:");
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
		case '?':
			return usage("");
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 3) {
		return usage("missing arguments\n");
	}

	uuid_t uuid;
	char busid[sizeof(uuid) * 2 + 1];
	uuid_generate(uuid);
	for (int i = 0; i < sizeof(uuid); i++) {
		busid[2 * i] = hex_bytes[uuid[i] >> 4];
		busid[2 * i + 1] = hex_bytes[uuid[i] & 15];
	}
	busid[sizeof(busid) - 1] = 0;

	char *sockpath = argv[0];
	char *busdir = argv[1];

	if (verbose) {
		fprintf(stderr,
			"launching daemon with busdir %s and busid %s\n",
			busdir, busid);
		fprintf(stderr, "creating dbus-1 socket at %s\n", sockpath);
	}

	union {
		struct sockaddr_un sun;
		struct sockaddr sa;
	} addr;
	addr.sun.sun_family = AF_UNIX;
	size_t pathlen = strlen(sockpath);
	if (pathlen + 1 > sizeof(addr.sun.sun_path)) {
		return usage("socket pathname %s is too long\n", sockpath);
	}
	memcpy(addr.sun.sun_path, sockpath, pathlen);
	memset(addr.sun.sun_path + pathlen, 0,
	       sizeof(addr.sun.sun_path) - pathlen);

	int sock = socket(AF_UNIX, SOCK_STREAM, PF_UNIX);
	if (!sock || fcntl(sock, F_SETFD, (int)FD_CLOEXEC)) {
		perror("failed to create unix socket");
		return ERR_FAILED;
	}

	unlink(sockpath);

	if (bind(sock, &addr.sa,
		 offsetof(struct sockaddr_un, sun_path) + pathlen + 1) ||
	    listen(sock, SOMAXCONN)) {
		fprintf(stderr, "failed to bind socket %s: %s\n", sockpath,
			strerror(errno));
		return ERR_FAILED;
	}

	for (;;) {
		// Set cloexec as we open it. We then reenable after forking
		// so that we don't leak sockets across children.
#ifdef SOCK_CLOEXEC
		int client = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
#else
		int client = accept(sock, NULL, NULL);
		fcntl(sock, F_SETFD, (int)FD_CLOEXEC);
#endif

		int pid = fork();
		switch (pid) {
		case -1:
			perror("fork failed");
			return ERR_FAILED;
		case 0:
			return child_process(client, sockbusp, busdir, busid);
		default:
			// in parent
			break;
		}
	}
	return 0;
}
