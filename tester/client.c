#include "client.h"
#include "lib/auth.h"
#include "lib/log.h"
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>

static int write_all(int fd, char *b, size_t sz, const char *args, ...)
	__attribute__((format(printf, 4, 5)));

static int write_all(int fd, char *b, size_t sz, const char *args, ...)
{
	if (start_debug("write")) {
		va_list ap;
		va_start(ap, args);
		log_vargs(args, ap);
		log_int("fd", fd);
		log_bytes("data", b, sz);
		finish_log();
	}
	while (sz) {
		int w = write(fd, b, sz);
		if (w <= 0) {
			start_log(LOG_ERROR, "write");
			va_list ap;
			va_start(ap, args);
			log_vargs(args, ap);
			log_errno("errno");
			log_int("fd", fd);
			finish_log();
			return -1;
		}
		b += w;
		sz -= w;
	}
	return 0;
}

static int read_one(int fd, char *buf, size_t cap)
{
try_again:
	int r = read(fd, buf, cap);
	if (r < 0 && errno == EINTR) {
		goto try_again;
	} else if (r < 0) {
		ERROR("read,errno:%m,fd:%d", fd);
		return -1;
	} else if (r == 0) {
		ERROR("recv early EOF,fd:%d", fd);
		return -1;
	}
	if (start_debug("read")) {
		log_int("fd", fd);
		log_bytes("data", buf, r);
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
		ERROR("failed to open dbus socket,errno:%m");
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

		if (write_all(fd, outbuf, outsz, "auth,state:%d", state)) {
			goto error;
		}
		if (err == AUTH_OK) {
			break;
		} else if (err != AUTH_READ_MORE) {
			goto error;
		}

		memmove(inbuf, in.p, in.len);
		insz = in.len;

		int n = read_one(fd, inbuf + insz, sizeof(inbuf) - insz);
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
	c->cb_available = UINT16_MAX;
	memset(&c->cbs, 0, sizeof(c->cbs));
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
	NOTICE("connected,address:%.*s", S_PRI(addr));
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

uint32_t register_cb(struct client *c, message_fn fn, void *udata)
{
	int idx = ffs(c->cb_available);
	if (!idx) {
		return 0;
	}
	c->cbs[idx - 1].fn = fn;
	c->cbs[idx - 1].udata = udata;
	c->cb_available &= ~(1U << (idx - 1));
	return idx;
}

void unregister_cb(struct client *c, uint32_t serial)
{
	assert(0 < serial && serial <= sizeof(c->cbs) / sizeof(c->cbs[0]));
	c->cb_available |= 1U << (serial - 1);
	c->cbs[serial - 1].fn = NULL;
	c->cbs[serial - 1].udata = NULL;
}

int vsend_signal(struct client *c, slice_t path, slice_t iface, slice_t mbr,
		 const char *sig, va_list ap)
{
	struct message m;
	init_message(&m, MSG_SIGNAL, UINT32_MAX);
	m.member = mbr;
	m.path = path;
	m.interface = iface;
	m.signature = sig;

	char buf[256];
	struct builder b = start_message(buf, sizeof(buf), &m);

	append_multiv(&b, sig, ap);

	int sz = end_message(b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz,
		      "send_signal,path:%.*s,iface:%.*s,mbr:%.*s", S_PRI(path),
		      S_PRI(iface), S_PRI(mbr))) {
		return -1;
	}
	return 0;
}

int vcall_method(struct client *c, uint32_t serial, slice_t dst, slice_t path,
		 slice_t iface, slice_t mbr, const char *sig, va_list ap)
{
	struct message m;
	init_message(&m, MSG_METHOD, serial ? serial : UINT32_MAX);
	m.flags = serial ? 0 : FLAG_NO_REPLY_EXPECTED;
	m.member = mbr;
	m.destination = dst;
	m.path = path;
	m.interface = iface;
	m.signature = sig;

	char buf[256];
	struct builder b = start_message(buf, sizeof(buf), &m);

	append_multiv(&b, sig, ap);

	int sz = end_message(b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz, "dst:%.*s,path:%.*s,iface:%.*s,mbr:%.*s",
		      S_PRI(dst), S_PRI(path), S_PRI(iface), S_PRI(mbr))) {
		return -1;
	}
	return 0;
}

int vsend_reply(struct client *c, const struct message *req, const char *sig,
		va_list ap)
{
	struct message m;
	init_message(&m, MSG_REPLY, UINT32_MAX);
	m.signature = sig;
	m.reply_serial = req->serial;
	m.destination = req->sender;

	char buf[256];
	struct builder b = start_message(buf, sizeof(buf), &m);

	append_multiv(&b, sig, ap);

	int sz = end_message(b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz, "type:%s,request:%x,dst:%.*s", "reply(2)",
		      req->serial, S_PRI(req->sender))) {
		return -1;
	}
	return 0;
}

int send_error(struct client *c, uint32_t request_serial, slice_t error)
{
	struct message m;
	init_message(&m, MSG_ERROR, UINT32_MAX);
	m.error = error;
	m.reply_serial = request_serial;

	char buf[256];
	struct builder b = start_message(buf, sizeof(buf), &m);

	int sz = end_message(b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz, "send_error,request:%u,error:%.*s",
		      request_serial, S_PRI(error))) {
		return -1;
	}
	return 0;
}

int send_signal(struct client *c, slice_t path, slice_t iface, slice_t mbr,
		const char *sig, ...)
{
	va_list ap;
	va_start(ap, sig);
	return vsend_signal(c, path, iface, mbr, sig, ap);
}

int call_method(struct client *c, uint32_t serial, slice_t dst, slice_t path,
		slice_t iface, slice_t mbr, const char *sig, ...)
{
	va_list ap;
	va_start(ap, sig);
	return vcall_method(c, serial, dst, path, iface, mbr, sig, ap);
}

int send_reply(struct client *c, const struct message *req, const char *sig,
	       ...)
{
	va_list ap;
	va_start(ap, sig);
	return vsend_reply(c, req, sig, ap);
}

int call_bus_method(struct client *c, uint32_t serial, slice_t member,
		    const char *sig, ...)
{
	va_list ap;
	va_start(ap, sig);
	return vcall_method(c, serial, S("org.freedesktop.DBus"),
			    S("/org/freedesktop/DBus"),
			    S("org.freedesktop.DBus"), member, sig, ap);
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
			int n = read_one(c->fd, p1, n1);
			if (n < 0) {
				return -1;
			}
			c->in.have += n;
			continue;
		} else if (err == STREAM_OK) {
			if (start_debug("read message")) {
				log_int("fd", c->fd);
				log_message(msg);
				finish_log();
			}
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

int distribute_message(struct client *c, struct message *m,
		       struct iterator *body)
{
	if (!(0 < m->reply_serial &&
	      m->reply_serial <= sizeof(c->cbs) / sizeof(c->cbs[0]))) {
		return 0;
	}
	int idx = m->reply_serial - 1;
	if (c->cb_available & (1U << idx)) {
		return 0;
	} else {
		return c->cbs[idx].fn(c->cbs[idx].udata, c, m, body);
	}
}
