#define _GNU_SOURCE
#include "parse.h"
#include "message.h"
#include "stream.h"
#include "auth.h"
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#define ERR_FAILED 1
#define ERR_INVALID_ARG 5
#define MAX_CONTROL_SIZE 256
#define MAX_DGRAM_MESSAGES 8

static int verbose;
static char *busdir;
static char *busid;
static union {
	struct sockaddr sa;
	struct sockaddr_un sun;
} sockaddr;

void log_message(const struct msg_header *h, const struct msg_fields *f,
		 const char *src)
{
	fprintf(stderr,
		"have message source %s from %s to %s obj %s iface %s member %s sig %s\n",
		src, f->sender.p, f->destination.p, f->path.p, f->interface.p,
		f->member.p, f->signature.p);
}

static int usage(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	fprintf(stderr, format, ap);
	va_end(ap);
	fputs("usage: sockbus-dbus-proxy [args] sockdir busid\n", stderr);
	fputs("  -v      Enable verbose\n", stderr);
	fputs("  -i fd   Input file descriptor (default:0)\n", stderr);
	fputs("  -o fd   Output file descriptor (default:1)\n", stderr);
	return ERR_INVALID_ARG;
}

static int process_stream_message(struct msg_header *h, struct msg_fields *f)
{
	if (verbose) {
		log_message(h, f, "stdin");
	}
	if (is_string(f->destination, "org.freedesktop.DBus") &&
	    is_string(f->interface, "org.freedesktop.DBus") &&
	    is_string(f->path, "/org/freedesktop/DBus")) {
		switch (f->member.len) {
		case sizeof("Hello") - 1:
			if (is_string(f->member, "Hello")) {
				fprintf(stderr, "have hello\n");
			}
			break;
		}
	}
	return 0;
}

static int process_busdir_message(struct msg_header *h, struct msg_fields *f)
{
	if (verbose) {
		log_message(h, f, "busdir");
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int infd = STDIN_FILENO;
	int outfd = STDOUT_FILENO;
	for (;;) {
		int i = getopt(argc, argv, "z:vi:o:");
		if (i < 0) {
			break;
		}
		switch (i) {
		case 'v':
			verbose = 1;
			break;
		case 'i':
			infd = atoi(optarg);
			break;
		case 'o':
			outfd = atoi(optarg);
			break;
		case 'z':
#ifndef NDEBUG
			freopen(optarg, "w", stderr);
			TEST_parse();
			return 0;
#endif
		case '?':
			return usage("");
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		return usage("missing arguments\n");
	}

	// make sure they are different so we can have different blocking
	if (infd == outfd) {
		outfd = dup(outfd);
	}

	busdir = argv[0];
	busid = argv[1];

	// buffer used for read call from stdin
	struct stream_buffer inbuf = INIT_STREAM_BUFFER;

	// enable SIGPIPE, and blocking on stdin/out for the auth call
	signal(SIGPIPE, SIG_DFL);
	fcntl(infd, F_SETFL, 0);
	fcntl(outfd, F_SETFL, 0);

	if (perform_auth(infd, outfd, &inbuf, busid)) {
		return ERR_FAILED;
	}

	realign_buffer(&inbuf);

	// set stdin to non block and ignore SIGPIPE
	// we'll deal with these synchronously in the write calls
	signal(SIGPIPE, SIG_IGN);
	fcntl(infd, F_SETFL, (int)O_NONBLOCK);
	fcntl(outfd, F_SETFL, 0);

	// we may have to auto-launch daemons. Don't want our stdin/out to leak
	fcntl(infd, F_SETFD, FD_CLOEXEC);
	fcntl(outfd, F_SETFD, FD_CLOEXEC);

	// lets setup and bind our unique address
	int bus = socket(AF_UNIX, SOCK_DGRAM, PF_UNIX);
	fcntl(bus, F_SETFL, (int)O_NONBLOCK);
	fcntl(bus, F_SETFD, (int)FD_CLOEXEC);

	srand(time(NULL));

	struct sockaddr_un *a = &sockaddr.sun;
	a->sun_family = AF_UNIX;

	// try a few times until we get an address
	for (int tries = 0;; tries++) {
		int n = snprintf(a->sun_path, sizeof(a->sun_path) - 1,
				 "%s/:%d.%d", busdir, getpid(), rand());
		if (n < 0 || n >= sizeof(a->sun_path) - 1) {
			fprintf(stderr,
				"bus directory pathname %s is too long\n",
				busdir);
			return ERR_FAILED;
		}
		unlink(a->sun_path);
		if (!bind(bus, &sockaddr.sa,
			  offsetof(struct sockaddr_un, sun_path) + n + 1)) {
			break;
		}
		if (tries >= 10) {
			fprintf(stderr,
				"failed to bind unique address %s: %s\n",
				a->sun_path, strerror(errno));
			return ERR_FAILED;
		}
	}

	// buffers used for recvmmsg call from busdir
	struct iovec datav[MAX_DGRAM_MESSAGES];
	struct mmsghdr msgv[MAX_DGRAM_MESSAGES];
	char *controlv[MAX_DGRAM_MESSAGES];
	for (int i = 0; i < MAX_DGRAM_MESSAGES; i++) {
		datav[i].iov_len = MAX_MESSAGE_SIZE;
		datav[i].iov_base = malloc(MAX_MESSAGE_SIZE);
		controlv[i] = malloc(MAX_CONTROL_SIZE);
		if (!datav[i].iov_base || !controlv[i]) {
			perror("malloc failed");
			return ERR_FAILED;
		}
		struct msghdr *h = &msgv[i].msg_hdr;
		h->msg_iov = &datav[i];
		h->msg_iovlen = 1;
		h->msg_control = controlv[i];
		h->msg_controllen = MAX_CONTROL_SIZE;
		h->msg_flags = MSG_CMSG_CLOEXEC;
		h->msg_name = NULL;
		h->msg_namelen = 0;
	}

	struct pollfd pfd[2];
	pfd[0].fd = infd;
	pfd[0].events = POLLIN;
	pfd[0].revents = POLLIN;
	pfd[1].fd = bus;
	pfd[1].events = POLLIN;
	pfd[1].revents = POLLIN;

	for (;;) {
		if (pfd[0].revents) {
			for (;;) {
				struct msg_header *h;
				int sts = read_message(infd, &inbuf, &h);
				if (sts == READ_ERROR) {
					return ERR_FAILED;
				} else if (sts == READ_MORE) {
					break;
				}
				struct msg_fields f;
				if (parse_header_fields(&f, h)) {
					return ERR_FAILED;
				}

				if (process_stream_message(h, &f)) {
					return ERR_FAILED;
				}

				drop_message(&inbuf);
			}
		}
		if (pfd[1].revents) {
			for (;;) {
				int msgnum = recvmmsg(
					bus, msgv, MAX_DGRAM_MESSAGES, 0, NULL);
				if (msgnum < 0 &&
				    (errno == EINTR || errno == EAGAIN)) {
					break;
				} else if (msgnum < 0) {
					// how does a unix datagram socket fail?
					perror("recvmmsg");
					return ERR_FAILED;
				}
				for (int i = 0; i < msgnum; i++) {
					struct msg_header *h =
						datav[i].iov_base;
					int len = raw_message_length(h);
					if (len < 0 || len > msgv[i].msg_len) {
						// drop malformed messages
						// TODO deal with unix fds
						continue;
					}
					struct msg_fields f;
					if (parse_header_fields(&f, h)) {
						continue;
					}
					if (process_busdir_message(h, &f)) {
						continue;
					}
				}
			}
		}

		if (poll(pfd, 2, -1) <= 0) {
			perror("poll");
			return ERR_FAILED;
		}
	}
}
