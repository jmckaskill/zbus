#define _GNU_SOURCE
#include "lib/encode.h"
#include "lib/decode.h"
#include "lib/log.h"
#include "lib/str.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdalign.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>

static int last_serial;

static void init_bus_call(struct message *m, slice_t member, const char *sig)
{
	init_message(m, MSG_METHOD, ++last_serial);
	m->member = member;
	m->destination = S("org.freedesktop.DBus");
	m->path = S("/org/freedesktop/DBus");
	m->interface = S("org.freedesktop.DBus");
	m->signature = sig;
}

static int connect_unix(const char *sockpn)
{
	int lfd = socket(AF_UNIX, SOCK_STREAM, PF_UNIX);
	if (lfd < 0 || fcntl(lfd, F_SETFD, FD_CLOEXEC)) {
		goto error;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	buf_t s = MAKE_BUF(addr.sun_path);
	if (buf_add_cstr(&s, sockpn)) {
		goto error;
	}
	buf_addch(&s, '\0');

	socklen_t salen = s.p + s.len - (char *)&addr;
	if (connect(lfd, (struct sockaddr *)&addr, salen)) {
		goto error;
	}

	return lfd;
error:
	close(lfd);
	return -1;
}

static void add_auth_external(buf_t *b)
{
	char uid_buf[10];
	buf_t uid = MAKE_BUF(uid_buf);
	buf_addf(&uid, "%u", getuid());

	buf_addf(b, "AUTH EXTERNAL ");
	for (int i = 0; i < uid.len; i++) {
		buf_addf(b, "%02x", uid.p[i]);
	}
	buf_add(b, S("\r\n"));
}

static int read_all(buf_t *b, int fd)
{
try_again:
	int n = read(fd, b->p + b->len, b->cap - b->len);
	if (n < 0 && errno == EINTR) {
		goto try_again;
	} else if (n <= 0) {
		return -1;
	}
	b->len += n;
	return 0;
}

static int read_len(buf_t *b, int fd, int len)
{
	if (b->len + len > b->cap) {
		return -1;
	}
	while (len) {
		int r = read(fd, b->p + b->len, len);
		if (r < 0 && errno == EINTR) {
			continue;
		} else if (r <= 0) {
			return -1;
		}
		len -= r;
		b->len += r;
	}
	return 0;
}

static int read_message(buf_t *b, int fd, struct message *msg,
			struct iterator *body)
{
	if (read_len(b, fd, 16)) {
		return -1;
	}
	int sz = parse_message_size(to_right_slice(*b, 16));
	if (sz <= 0) {
		return -1;
	}
	if (read_len(b, fd, sz - 16)) {
		return -1;
	}
	LOG_DATA(to_right_slice(*b, sz), "read message");
	if (parse_header(msg, to_right_slice(*b, sz))) {
		return -1;
	}
	init_iterator(body, msg->signature, to_right_slice(*b, msg->body_len));
	return 0;
}

static void flush(int fd, buf_t *s, const char *msg)
{
	LOG_DATA(*s, "write %s", msg);
	write(fd, s->p, s->len);
	s->len = 0;
}

static void must(int iserr, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void must(int iserr, const char *fmt, ...)
{
	if (iserr) {
		va_list ap;
		va_start(ap, fmt);
		log_vfmt(log_error, fmt, ap);
		va_end(ap);
		abort();
	}
}

static int usage()
{
	fputs("usage: tester [args] socket\n", stderr);
	fputs("    -v     	Enable verbose (default:disabled)\n", stderr);
	fputs("    -f file    	FIFO to use as a ready indicator\n", stderr);
	return 2;
}

int main(int argc, char *argv[])
{
	char *readypn = NULL;
	int i;
	while ((i = getopt(argc, argv, "hqvf:")) > 0) {
		switch (i) {
		case 'f':
			readypn = optarg;
			break;
		case 'q':
			log_quiet = 1;
			break;
		case 'v':
			log_verbose = 1;
			break;
		case 'h':
		case '?':
			return usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc != 1) {
		fputs("unexpected arguments\n", stderr);
		return usage();
	}
	char *sockpn = argv[0];

	DLOG("startup");

	if (readypn != NULL) {
		ILOG("waiting for server to be ready by opening FIFO %s",
		     readypn);
		int rfd = open(readypn, O_RDONLY);
		must(rfd < 0, "failed to open ready fifo %s: %m", readypn);
		close(rfd);
	}

	DLOG("opening dbus socket %s", sockpn);
	int fd = connect_unix(sockpn);
	must(fd < 0, "failed to open dbus socket '%s': %m", sockpn);

	alignas(8) char buf[256];

	buf_t b = MAKE_BUF(buf);

	buf_addch(&b, '\0');
	add_auth_external(&b);
	flush(fd, &b, "nul + auth external");

	must(read_all(&b, fd), "read auth reply: %m");
	LOG_DATA(b, "read auth reply");
	b.len = 0;

	buf_add(&b, S("BEGIN\r\n"));
	flush(fd, &b, "begin");

	struct message m, r;
	struct iterator ii;

	init_bus_call(&m, S("Hello"), "");
	must(end_message(&b, start_message(&b, &m)), "encode Hello");
	flush(fd, &b, "Hello");

	must(read_message(&b, fd, &r, &ii), "read hello reply");
	slice_t addr = parse_string(&ii);
	must(iter_error(&ii), "Hello reply parse error");
	DLOG("Hello reply %.*s", addr.len, addr.p);
	b.len = 0;

	init_bus_call(&m, S("ListNames"), "");
	must(end_message(&b, start_message(&b, &m)), "encode ListNames");
	flush(fd, &b, "ListNames");

	must(read_message(&b, fd, &r, &ii), "read ListNames");
	DLOG("ListNames reply %d", r.type);
	struct array_data ad = parse_array(&ii);
	while (array_has_more(&ii, &ad)) {
		slice_t str = parse_string(&ii);
		DLOG("name %.*s", str.len, str.p);
	}
	must(iter_error(&ii), "ListNames reply parse error");
	b.len = 0;

	close(fd);
	return 0;
}
