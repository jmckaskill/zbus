#define _GNU_SOURCE
#include "lib/parse.h"
#include "lib/message.h"
#include "lib/stream.h"
#include "lib/auth.h"
#include "lib/marshal.h"
#include "lib/unix.h"
#include "lib/log.h"
#include "lib/bus.h"
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

static uint32_t last_serial;
static const char *busid;
static const char *busdir = ".";
static int busfd;
static int streamfd;
static char unique_addr[256];

void log_message(const struct message *m, const char *src)
{
	dlog("have message source %s from %s to %s obj %s iface %s member %s sig %s\n",
	     src, m->sender.p, m->destination.p, m->path.p, m->interface.p,
	     m->member.p, m->signature);
}

static int blocking_write(int fd, const char *p, int len,
			  const struct unix_oob *oob)
{
	log_data(p, len, "writing");
	while (len) {
		struct iovec iov;
		iov.iov_base = (void *)p;
		iov.iov_len = len;

		struct msghdr m;
		m.msg_name = NULL;
		m.msg_namelen = 0;
		m.msg_iov = &iov;
		m.msg_iovlen = 1;
		m.msg_flags = 0;

		control_buf_t control;
		if (write_cmsg(&m, &control, oob)) {
			return -1;
		}

		int r = write(fd, p, len);
		if (r < 0 && errno == EINTR) {
			continue;
		} else if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			if (blocking_poll(fd, POLLOUT)) {
				return -1;
			}
			continue;
		} else if (r <= 0 || r > len) {
			perror("write");
			return -1;
		}

		// a chunk and any fds were sent, loop around to send some more
		oob = NULL;
		p += r;
		len -= r;
	}
	return 0;
}

#define BUS_PATH "/org/freedesktop/DBus"
#define BUS_DESTINATION "org.freedesktop.DBus"
#define BUS_INTERFACE "org.freedesktop.DBus"
#define MONITORING_INTERFACE "org.freedesktop.DBus.Monitoring"
#define PEER_INTERFACE "org.freedesktop.DBus.Peer"
#define METHOD_HELLO "Hello"
#define METHOD_LIST_NAMES "ListNames"
#define METHOD_BECOME_MONITOR "BecomeMonitor"
#define METHOD_PING "Ping"

static int create_empty_reply(uint32_t reply_serial, void *buf, size_t bufsz)
{
	struct message m;
	init_message(&m, MSG_REPLY, ++last_serial);
	m.reply_serial = reply_serial;
	return end_message(start_message(&m, buf, bufsz));
}

static int send_empty_ok(slice_t destination, uint32_t reply_serial)
{
	char buf[256];
	int sz = create_empty_reply(reply_serial, buf, sizeof(buf));
	return sz < 0 ||
	       blocking_send(busfd, busdir, destination, buf, sz, NULL);
}

static int write_empty_ok(uint32_t reply_serial)
{
	char buf[256];
	int sz = create_empty_reply(reply_serial, buf, sizeof(buf));
	return sz < 0 || blocking_write(streamfd, buf, sz, NULL);
}

static int write_hello_reply(uint32_t reply_serial)
{
	struct message m;
	init_message(&m, MSG_REPLY, ++last_serial);
	m.reply_serial = reply_serial;
	m.signature = "s";

	char vbuf[256];
	struct buffer b = start_message(&m, vbuf, sizeof(vbuf));
	append_string(&b, make_slice(unique_addr));
	int sz = end_message(b);
	return sz < 0 || blocking_write(streamfd, vbuf, sz, NULL);
}

static int write_list_names_reply(uint32_t reply_serial)
{
	fprintf(stderr, "write_list_names_reply\n");
	char vbuf[4096];

	struct message m;
	init_message(&m, MSG_REPLY, ++last_serial);
	m.reply_serial = reply_serial;
	m.signature = "as";

	struct buffer b = start_message(&m, vbuf, sizeof(vbuf));
	struct array_data ad = start_array(&b);

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
		append_string(&b, make_slice(e->d_name));
	}
	closedir(d);

	end_array(&b, ad);
	int sz = end_message(b);
	return sz < 0 || blocking_write(streamfd, vbuf, sz, NULL);
}

static int process_stream(const struct message *m, struct iterator *body)
{
	log_message(m, "stdin");
	if (slice_eq(m->destination, BUS_DESTINATION) &&
	    slice_eq(m->interface, BUS_INTERFACE) &&
	    slice_eq(m->path, BUS_PATH)) {
		switch (m->member.len) {
		case STRLEN(METHOD_HELLO):
			if (slice_eq(m->member, METHOD_HELLO)) {
				return write_hello_reply(m->serial);
			}
			break;
		case STRLEN(METHOD_LIST_NAMES):
			if (slice_eq(m->member, METHOD_LIST_NAMES)) {
				return write_list_names_reply(m->serial);
			}
			break;
		}
	}
	if (slice_eq(m->interface, MONITORING_INTERFACE) &&
	    slice_eq(m->member, METHOD_BECOME_MONITOR)) {
		return write_empty_ok(m->serial);
	}
	return 0;
}

static int process_dgram(const struct message *m, struct iterator *body,
			 struct unix_oob *oob)
{
	log_message(m, "busdir");

	if (slice_eq(m->interface, PEER_INTERFACE) &&
	    slice_eq(m->member, METHOD_PING)) {
		return send_empty_ok(m->sender, m->serial);
	}
	return 0;
}

static int usage()
{
	fputs("usage: sockbus-dbus-proxy [args] busid\n", stderr);
	fputs("  -v      Enable verbose\n", stderr);
	fputs("  -f fd   Stream file descriptor (default:0)\n", stderr);
	fputs("  -d dir  Bus directory\n", stderr);
	return ERR_INVALID_ARG;
}

int main(int argc, char *argv[])
{
	streamfd = 0;
	for (;;) {
		int i = getopt(argc, argv, "hvf:d:z:");
		if (i < 0) {
			break;
		}
		switch (i) {
		case 'v':
			verbose = 1;
			break;
		case 'f':
			streamfd = atoi(optarg);
			break;
		case 'd':
			busdir = optarg;
			break;
		case 'z':
#ifndef NDEBUG
			freopen(optarg, "w", stderr);
			TEST_parse();
			return 0;
#endif
		case 'h':
		case '?':
			return usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		fprintf(stderr, "missing arguments\n");
		return usage();
	}

	busid = argv[0];

	// buffer used for read call from stdin
	struct stream stream;
	static char sbuf[MAX_MESSAGE_SIZE];

	// enable SIGPIPE, and blocking on stdin/out for the auth call
	signal(SIGPIPE, SIG_DFL);
	fcntl(streamfd, F_SETFL, 0);

	str_t strbuf = MAKE_STR(sbuf);
	if (perform_auth(streamfd, busid, &strbuf)) {
		return ERR_FAILED;
	}

	init_stream(&stream, streamfd, sbuf, sizeof(sbuf));
	stream.end = strbuf.len;

	// set stdin to non block and ignore SIGPIPE
	// we'll deal with these synchronously in the write calls
	signal(SIGPIPE, SIG_IGN);
	fcntl(streamfd, F_SETFL, O_NONBLOCK);
	fcntl(streamfd, F_SETFD, FD_CLOEXEC);

	busfd = bind_unique_address(busdir, -1, -1, 0700, unique_addr,
				    sizeof(unique_addr));
	if (busfd < 0) {
		return ERR_FAILED;
	}

	struct pollfd pfd[2];
	pfd[0].fd = streamfd;
	pfd[0].events = POLLIN;
	pfd[0].revents = POLLIN;
	pfd[1].fd = busfd;
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

				if (process_stream(&msg, &body)) {
					return ERR_FAILED;
				}

				drop_message(&stream, &msg);
			}
		}
		if (pfd[1].revents) {
			for (;;) {
				static char buf[MAX_MESSAGE_SIZE];
				struct message msg;
				struct iterator body;
				struct unix_oob oob;
				int r = recv_message(busfd, buf, sizeof(buf),
						     &msg, &body, &oob);
				if (r == RECV_MORE) {
					break;
				} else if (r == RECV_ERROR) {
					return ERR_FAILED;
				}

				process_dgram(&msg, &body, &oob);
				close_fds(&oob, oob.fdn);
			}
		}

		if (poll(pfd, 2, -1) <= 0) {
			perror("poll");
			return ERR_FAILED;
		}
	}
}
