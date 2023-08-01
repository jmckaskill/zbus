#include "client.h"
#include "lib/auth.h"
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>

static int write_all(int fd, char *b, size_t sz, const char *msg)
{
	if (start_verbose(msg)) {
		log_data("data", b, sz);
		finish_log();
	}
	while (sz) {
		int w = write(fd, b, sz);
		if (w <= 0) {
			write_error(msg, errno);
			return -1;
		}
		b += w;
		sz -= w;
	}
	return 0;
}

static int read_one(int fd, char *buf, size_t cap, const char *msg)
{
try_again:
	int r = read(fd, buf, cap);
	if (r < 0 && errno == EINTR) {
		goto try_again;
	} else if (r <= 0) {
		return -1;
	}
	if (start_verbose(msg)) {
		log_data("data", buf, r);
		finish_log();
	}
	return r;
}

static int connect_unix(const char *sockpn)
{
	int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNIX);
	if (lfd < 0) {
		goto error;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	size_t len = strlen(sockpn);
	if (len + 1 > sizeof(addr.sun_path)) {
		goto error;
	}
	memcpy(addr.sun_path, sockpn, len + 1);

	socklen_t salen = &addr.sun_path[len + 1] - (char *)&addr;
	if (connect(lfd, (struct sockaddr *)&addr, salen)) {
		goto error;
	}

	return lfd;
error:
	close(lfd);
	return -1;
}

static slice_t get_user_id(char *buf, size_t sz)
{
	char *puid = buf + sz;
	int id = getuid();
	if (id < 0) {
		return make_slice(NULL, 0);
	}
	do {
		*(--puid) = (id % 10) + '0';
		id /= 10;
	} while (id);
	return make_slice(puid, buf + sz - puid);
}

struct client *open_client(const char *sockpn)
{
	struct client *c = NULL;
	int fd = connect_unix(sockpn);
	if (fd < 0) {
		write_error("failed to open dbus socket", errno);
		goto error;
	}

	char uidbuf[16];
	slice_t uid = get_user_id(uidbuf, sizeof(uidbuf));

	char inbuf[256], outbuf[256];
	size_t insz = 0;
	int state = 0;
	uint32_t serial;

	for (;;) {
		size_t outsz = sizeof(outbuf);
		slice_t in = make_slice(inbuf, insz);
		int err = step_client_auth(&state, &in, outbuf, &outsz, uid,
					   &serial);

		if (write_all(fd, outbuf, outsz, "auth")) {
			goto error;
		}
		if (err == AUTH_OK) {
			break;
		} else if (err != AUTH_READ_MORE) {
			goto error;
		}

		memmove(inbuf, in.p, in.len);
		insz = in.len;

		int n = read_one(fd, inbuf + insz, sizeof(inbuf) - insz,
				 "auth");
		if (n < 0) {
			goto error;
		}
		insz += n;
	}

	size_t msgsz = 4096;
	size_t defrag = 1024;
	c = malloc(sizeof(*c) + msgsz + defrag);
	if (!c) {
		goto error;
	}
	c->fd = fd;
	c->next_serial = 1;
	init_msg_stream(&c->in, msgsz, defrag);

	struct message m;
	struct iterator ii;
	if (read_message(c, &m, &ii) || m.type != MSG_REPLY ||
	    m.reply_serial != serial) {
		goto error;
	}
	slice_t addr = parse_string(&ii);
	if (iter_error(&ii)) {
		goto error;
	}
	if (start_verbose("connected")) {
		log_slice("address", addr);
		finish_log();
	}
	return c;

error:
	free(c);
	close(fd);
	return NULL;
}

void close_client(struct client *c)
{
	if (c) {
		close(c->fd);
		free(c);
	}
}

int send_bus_method(struct client *c, slice_t member, const char *sig, ...)
{
	int serial = c->next_serial++;
	struct message m;
	init_message(&m, MSG_METHOD, serial);
	m.member = member;
	m.destination = S("org.freedesktop.DBus");
	m.path = S("/org/freedesktop/DBus");
	m.interface = S("org.freedesktop.DBus");
	m.signature = sig;

	char buf[256];
	struct builder b = start_message(buf, sizeof(buf), &m);

	va_list ap;
	va_start(ap, sig);
	append_multiv(&b, sig, ap);
	va_end(ap);

	int sz = end_message(b);
	if (sz < 0 || write_all(c->fd, buf, sz, "call bus method")) {
		return -1;
	}
	return serial;
}

int read_message(struct client *c, struct message *msg, struct iterator *body)
{
	for (;;) {
		slice_t b1, b2;
		int err = stream_next(&c->in, msg, &b1, &b2);

		if (err == STREAM_MORE) {
			char *p1, *p2;
			size_t n1, n2;
			stream_buffers(&c->in, &p1, &n1, &p2, &n2);
			int n = read_one(c->fd, p1, n1, "read message");
			if (n < 0) {
				return -1;
			}
			c->in.have += n;
			continue;
		} else if (err == STREAM_OK) {
			if (defragment_body(&c->in, &b1, &b2)) {
				return -1;
			}
			init_iterator(body, msg->signature, b1.p, b1.len);
			return 0;
		} else {
			return -1;
		}
	}
}

int read_reply(struct client *c, int serial, struct iterator *reply,
	       slice_t *perror)
{
	for (;;) {
		struct message msg;
		if (read_message(c, &msg, reply)) {
			perror->p = strerror(errno);
			perror->len = strlen(perror->p);
			return -1;
		}
		if (msg.type != MSG_REPLY && msg.type != MSG_ERROR) {
			continue;
		}
		if (msg.reply_serial != serial) {
			continue;
		}
		*perror = msg.error;
		return 0;
	}
}

void log_message(struct client *c, const struct message *m)
{
	start_verbose("rx message");
	log_number("client", c->fd);
	log_number("type", m->type);
	log_number("serial", m->serial);
	opt_log_number("reply", m->reply_serial);
	opt_log_number("flags", m->flags);
	opt_log_slice("dst", m->destination);
	opt_log_slice("iface", m->interface);
	opt_log_slice("member", m->member);
	opt_log_slice("path", m->path);
	opt_log_slice("error", m->error);
	finish_log();
}
