#define _GNU_SOURCE
#include "parse.h"
#include "message.h"
#include "stream.h"
#include "auth.h"
#include "marshal.h"
#include "unix.h"
#include "log.h"
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>

#define ERR_FAILED 1
#define ERR_INVALID_ARG 5

static uint32_t next_serial = 1;
static char *busid;
static char unique_addr[128];

void log_message(const struct message *m, const char *src)
{
	fprintf(stderr,
		"have message source %s from %s to %s obj %s iface %s member %s sig %s\n",
		src, m->sender.p, m->destination.p, m->path.p, m->interface.p,
		m->member.p, m->signature);
}

static int usage(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	fprintf(stderr, format, ap);
	va_end(ap);
	fputs("usage: sockbus-dbus-proxy [args] busid\n", stderr);
	fputs("  -v      Enable verbose\n", stderr);
	fputs("  -f fd   Stream file descriptor (default:0)\n", stderr);
	fputs("  -d dir  Bus directory\n", stderr);
	return ERR_INVALID_ARG;
}

static int blocking_write(int fd, const char *p, unsigned len)
{
	log_data("write stream", p, len);
	while (len) {
		int r = write(fd, p, len);
		if (r < 0 && errno == EINTR) {
			continue;
		} else if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			struct pollfd pfd;
			pfd.fd = fd;
			pfd.events = POLLOUT;
			r = poll(&pfd, 1, -1);
			if (r > 0 || (r < 0 && errno == EINTR)) {
				continue;
			} else {
				perror("poll");
				return -1;
			}
		} else if (r <= 0 || r > len) {
			perror("write");
			return -1;
		}
		p += r;
		len -= r;
	}
	return 0;
}

static int send_hello_reply(int out, uint32_t reply_serial)
{
	struct message m;
	init_message(&m);
	m.hdr.type = MSG_REPLY;
	m.hdr.serial = next_serial++;
	m.reply_serial = reply_serial;
	m.signature = "s";

	char vbuf[256];
	struct buffer b;
	init_buffer(&b, vbuf, sizeof(vbuf));

	struct message_data md;
	start_message(&b, &m, &md);
	append_string(&b, to_string(unique_addr));
	end_message(&b, &md);

	return b.error || blocking_write(out, vbuf, b.off);
}

static int send_list_names_reply(int out, uint32_t reply_serial)
{
	fprintf(stderr, "send_list_names_reply\n");
	char vbuf[4096];
	struct buffer b;
	init_buffer(&b, vbuf, sizeof(vbuf));

	struct message m;
	init_message(&m);
	m.hdr.type = MSG_REPLY;
	m.hdr.serial = next_serial++;
	m.reply_serial = reply_serial;
	m.signature = "as";

	struct message_data md;
	start_message(&b, &m, &md);
	struct array_data ad;
	start_array(&b, &ad);

	DIR *d = opendir(".");
	if (d == NULL) {
		perror("failed to open bus dir");
		return -1;
	}
	struct dirent *e;
	while ((e = readdir(d)) != NULL) {
		if (e->d_type != DT_SOCK) {
			// folder, file or something else incl. . and ..
			continue;
		}
		if (strchr(e->d_name, '.') == NULL) {
			// other socket e.g. session_bus_socket
			continue;
		}
		next_in_array(&b, &ad);
		append_string(&b, to_string(e->d_name));
	}
	closedir(d);

	end_array(&b, &ad);
	end_message(&b, &md);

	return b.error || blocking_write(out, vbuf, b.off);
}

#define PATH_BUS "/org/freedesktop/DBus"
#define DESTINATION_BUS "org.freedesktop.DBus"
#define INTERFACE_BUS "org.freedesktop.DBus"
#define METHOD_HELLO "Hello"
#define METHOD_LIST_NAMES "ListNames"

static int process_stream(int out, const struct message *m,
			  struct iterator *body)
{
	if (verbose) {
		log_message(m, "stdin");
	}
	if (is_string(m->destination, DESTINATION_BUS) &&
	    is_string(m->interface, INTERFACE_BUS) &&
	    is_string(m->path, PATH_BUS)) {
		switch (m->member.len) {
		case STRLEN(METHOD_HELLO):
			if (is_string(m->member, METHOD_HELLO)) {
				return send_hello_reply(out, m->hdr.serial);
			}
			break;
		case STRLEN(METHOD_LIST_NAMES):
			if (is_string(m->member, METHOD_LIST_NAMES)) {
				return send_list_names_reply(out,
							     m->hdr.serial);
			}
			break;
		}
	}
	return 0;
}

static int verify_sender(const struct message *m, const struct unix_oob *u)
{
	if (!m->sender.len || m->sender.p[0] != ':') {
		return -1;
	}
	if (u->pid < 0) {
		return -1;
	}
	char *p;
	unsigned long m_pid = strtoul(m->sender.p + 1, &p, 10);
	return m_pid != u->pid || *p != '.';
}

static int process_dgram(int fd, void *buf, size_t have, struct unix_oob *u)
{
	if (have < MIN_MESSAGE_SIZE) {
		return -1;
	}
	int len = raw_message_len(buf);
	if (len < 0 || (size_t)len != have) {
		return -1;
	}

	struct message msg;
	struct iterator body;
	if (parse_message(buf, &msg, &body)) {
		return -1;
	}

	if (verify_sender(&msg, u)) {
		// we don't have an authenticated reply destination
		msg.sender.len = 0;
		msg.hdr.flags |= FLAG_NO_REPLY_EXPECTED;
	}

	if (verbose) {
		log_message(&msg, "busdir");
	}
	return 0;
}

static int recv_dgram(int fd)
{
	for (;;) {
		static char sdata[MAX_MESSAGE_SIZE];
		static union {
			char buf[CONTROL_BUFFER_SIZE];
			struct cmsghdr align;
		} scontrol;

		struct iovec iov;
		iov.iov_base = sdata;
		iov.iov_len = sizeof(sdata);

		struct msghdr msg;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = scontrol.buf;
		msg.msg_controllen = sizeof(scontrol);
		msg.msg_flags = 0;

		ssize_t n = recvmsg(fd, &msg, 0);
		if (n < 0 && errno == EINTR) {
			continue;
		} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return 0;
		} else if (n < 0) {
			// how does a unix datagram socket fail?
			perror("recvmmsg");
			return -1;
		}

		struct unix_oob oob;
		parse_cmsg(&oob, &msg);
		process_dgram(fd, sdata, n, &oob);
		close_fds(&oob, oob.fdn);
	}
}

int main(int argc, char *argv[])
{
	int fd = 0;
	for (;;) {
		int i = getopt(argc, argv, "hz:vf:d:");
		if (i < 0) {
			break;
		}
		switch (i) {
		case 'v':
			verbose = 1;
			break;
		case 'f':
			fd = atoi(optarg);
			break;
		case 'd':
			if (chdir(optarg)) {
				perror("chdir busdir");
				return ERR_INVALID_ARG;
			}
			break;
		case 'z':
#ifndef NDEBUG
			freopen(optarg, "w", stderr);
			TEST_parse();
			return 0;
#endif
		case 'h':
		case '?':
			return usage("");
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		return usage("missing arguments\n");
	}

	busid = argv[0];

	// buffer used for read call from stdin
	struct stream stream;
	static char sbuf[MAX_MESSAGE_SIZE];
	init_stream(&stream, fd, sbuf, sizeof(sbuf));

	// enable SIGPIPE, and blocking on stdin/out for the auth call
	signal(SIGPIPE, SIG_DFL);
	fcntl(fd, F_SETFL, 0);

	if (perform_auth(&stream, fd, busid)) {
		return ERR_FAILED;
	}

	reset_stream_alignment(&stream);

	// set stdin to non block and ignore SIGPIPE
	// we'll deal with these synchronously in the write calls
	signal(SIGPIPE, SIG_IGN);
	fcntl(fd, F_SETFL, O_NONBLOCK);

	// lets setup and bind our unique address
	int bus = socket(AF_UNIX, SOCK_DGRAM, PF_UNIX);
	fcntl(bus, F_SETFL, O_NONBLOCK);
	int enable = 1;
	if (setsockopt(bus, SOL_SOCKET, SO_PASSCRED, &enable, sizeof(int))) {
		perror("SO_PASSCRED");
		return ERR_FAILED;
	}

	// we may have to auto-launch daemons. Don't want our fd to leak
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	fcntl(bus, F_SETFD, FD_CLOEXEC);

	// bind first to a temporary name
	// and then rename to our actual unique address
	// this removes the race between unlink and bind
	union {
		struct sockaddr sa;
		struct sockaddr_un sun;
	} sockaddr;

	struct sockaddr_un *a = &sockaddr.sun;
	a->sun_family = AF_UNIX;
	strcpy(a->sun_path, "./sock-XXXXXX");
	if (mkdtemp(a->sun_path) == NULL) {
		perror("mktemp");
		return ERR_FAILED;
	}
	strcat(a->sun_path, "/sock");

	socklen_t sunlen = offsetof(struct sockaddr_un, sun_path) +
			   strlen(a->sun_path) + 1;
	if (bind(bus, &sockaddr.sa, sunlen)) {
		perror("bind");
		return ERR_FAILED;
	}

	if (chmod(a->sun_path, 0700)) {
		perror("chmod");
		return ERR_FAILED;
	}

	sprintf(unique_addr, ":%d.1", getpid());
	if (rename(a->sun_path, unique_addr)) {
		perror("rename");
		return ERR_FAILED;
	}
	a->sun_path[strlen(a->sun_path) - strlen("/sock")] = 0;
	rmdir(a->sun_path);

	struct pollfd pfd[2];
	pfd[0].fd = fd;
	pfd[0].events = POLLIN;
	pfd[0].revents = POLLIN;
	pfd[1].fd = bus;
	pfd[1].events = POLLIN;
	pfd[1].revents = POLLIN;

	for (;;) {
		if (pfd[0].revents) {
			for (;;) {
				struct message msg;
				struct iterator body;
				int r = read_message(&stream, &msg, &body);
				if (r == READ_ERROR) {
					return ERR_FAILED;
				} else if (r == READ_MORE) {
					break;
				}

				if (process_stream(fd, &msg, &body)) {
					return ERR_FAILED;
				}

				drop_message(&stream, &msg);
			}
		}
		if (pfd[1].revents) {
			if (recv_dgram(fd)) {
				return ERR_FAILED;
			}
		}

		if (poll(pfd, 2, -1) <= 0) {
			perror("poll");
			return ERR_FAILED;
		}
	}
}
