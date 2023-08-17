#include "config.h"
#include "auth.h"

#define BUS_DESTINATION ZB_S8("\024org.freedesktop.DBus")
#define BUS_INTERFACE ZB_S8("\024org.freedesktop.DBus")
#define BUS_PATH ZB_S8("\025/org/freedesktop/DBus")
#define HELLO ZB_S8("\005Hello")

static int split_line(char **pin, char *end, char **pstart, char **pend)
{
	char *start = *pin;
	char *nl = memchr(start, '\n', end - start);
	if (!nl) {
		return ZB_STREAM_READ_MORE;
	}
	if (nl == start || nl[-1] != '\r' || memchr(start, 0, nl - start)) {
		return ZB_STREAM_ERROR;
	}
	*pin = nl + 1;
	*pstart = start;
	*pend = nl;
	nl[-1] = ' ';
	nl[0] = '\0';
	return 0;
}

static bool equals(char *line, char *end, const char *test)
{
	size_t len = strlen(test);
	return (end - line) == len && !memcmp(line, test, len);
}

static bool begins_with(char *line, char *end, const char *test)
{
	size_t len = strlen(test);
	return (size_t)(end - line) >= len && !memcmp(line, test, len);
}

static char *append(char *out, char *end, const zb_str8 *s)
{
	if (out + s->len > end) {
		return end + 1;
	}
	memcpy(out, s->p, s->len);
	return out + s->len;
}

enum auth_state {
	AUTH_INIT = 0,
	AUTH_WAIT_FOR_AUTH,
	AUTH_WAIT_FOR_BEGIN,
	AUTH_WAIT_FOR_HELLO,
};

static int step_server_auth(enum auth_state *pstate, char **pin, char *ie,
			    char **pout, char *oe, const zb_str8 *busid,
			    uint32_t *pserial)
{
	char *in = *pin;
	char *out = *pout;

	switch (*pstate) {
	case AUTH_INIT:
		if (in == ie) {
			return ZB_STREAM_READ_MORE;
		}
		if (*in) {
			return ZB_STREAM_ERROR;
		}
		in++;
		goto wait_for_auth;

	wait_for_auth:
		*pin = in;
		*pout = out;
		*pstate = AUTH_WAIT_FOR_AUTH;
	case AUTH_WAIT_FOR_AUTH: {
		char *line, *nl;
		int err = split_line(&in, ie, &line, &nl);
		if (err) {
			return err;
		}

		if (!begins_with(line, nl, "AUTH ")) {
			// unexpected command
			out = append(out, oe, ZB_S8("\007ERROR\r\n"));
			if (out > oe) {
				return ZB_STREAM_WRITE_MORE;
			}
			goto wait_for_auth;
		}

		if (!begins_with(line, nl, "AUTH EXTERNAL ")) {
			// unsupported auth type
			out = append(out, oe,
				     ZB_S8("\023REJECTED EXTERNAL\r\n"));
			if (out > oe) {
				return ZB_STREAM_WRITE_MORE;
			}
			goto wait_for_auth;
		}

		// for now ignore the argument
		out = append(out, oe, ZB_S8("\003OK "));
		out = append(out, oe, busid);
		out = append(out, oe, ZB_S8("\002\r\n"));
		if (out > oe) {
			return ZB_STREAM_WRITE_MORE;
		}
		goto wait_for_begin;
	}

	wait_for_begin:
		*pin = in;
		*pout = out;
		*pstate = AUTH_WAIT_FOR_BEGIN;
	case AUTH_WAIT_FOR_BEGIN: {
		char *line, *nl;
		int err = split_line(&in, ie, &line, &nl);
		if (err) {
			return err;
		}
		if (equals(line, nl, "BEGIN ")) {
			goto wait_for_hello;

#ifdef CAN_SEND_UNIX_FDS
		} else if (equals(line, nl, "NEGOTIATE_UNIX_FD ")) {
			out = append(out, oe, ZB_S8("\017AGREE_UNIX_FD\r\n"));
			if (out > oe) {
				return ZB_STREAM_WRITE_MORE;
			}
			goto wait_for_begin;
#endif

		} else {
			out = append(out, oe, ZB_S8("\007ERROR\r\n"));
			if (out > oe) {
				return ZB_STREAM_WRITE_MORE;
			}
			goto wait_for_begin;
		}
	}

	wait_for_hello:
		*pin = in;
		*pout = out;
		*pstate = AUTH_WAIT_FOR_HELLO;
	case AUTH_WAIT_FOR_HELLO: {
		// process the Hello header

		size_t hsz, bsz;
		if (in + ZB_MIN_MSG_SIZE > ie) {
			return ZB_STREAM_READ_MORE;
		} else if (zb_parse_size(in, &hsz, &bsz)) {
			return ZB_STREAM_ERROR;
		} else if (in + hsz + bsz > ie) {
			return ZB_STREAM_READ_MORE;
		}

		// verify the fields
		// method fields always have serial, path & member
		struct zb_message m;
		if (zb_parse_header(&m, in) || m.type != ZB_METHOD ||
		    !m.destination ||
		    !zb_eq_str8(m.destination, BUS_DESTINATION) ||
		    !zb_eq_str8(m.path, BUS_PATH) || !m.interface ||
		    !zb_eq_str8(m.interface, BUS_INTERFACE) ||
		    !zb_eq_str8(m.member, HELLO)) {
			return ZB_STREAM_ERROR;
		}

		*pserial = m.serial;
		*pin = in + hsz + bsz;
		return ZB_STREAM_OK;
	}
	default:
		return ZB_STREAM_ERROR;
	}
}

static int send_auth(struct txconn *c, char *p, size_t sz)
{
	while (sz) {
		int n = start_send1(c, p, sz);
		if (n <= 0) {
			// we shouldn't have sent enough to consume the tx
			// buffer so consider async sends as errors
			ERROR("send,errno:%m");
			return -1;
		}
		p += n;
		sz -= n;
	}
	return 0;
}

struct zb_stream *authenticate(struct rx *r)
{
	uint32_t serial;
	enum auth_state state = AUTH_INIT;
	size_t inhave = 0;
	char in[256];
	char out[64];
	char *innext = in;
	char *ie = in + sizeof(in);
	char *oe = out + sizeof(out);

	for (;;) {
		// compact any remaining input data
		inhave = in + inhave - innext;
		memmove(in, innext, inhave);

		int n = block_recv1(&r->conn, in + inhave, ie - in - inhave);
		if (n < 0) {
			return NULL;
		}
		inhave += n;

		char *op = out;
		int err = step_server_auth(&state, &innext, in + inhave, &op,
					   oe, &r->bus->busid, &serial);

		if (send_auth(&r->tx->conn, out, op - out)) {
			return NULL;
		}

		if (err == ZB_STREAM_OK) {
			break;
		} else if (err != ZB_STREAM_READ_MORE) {
			return NULL;
		}
	}

	if (load_security(&r->tx->conn, &r->tx->sec)) {
		return NULL;
	}

	// auth successful, setup the full size receive and transmit buffers
	char *buf = malloc(sizeof(struct zb_stream) + RX_BUFSZ + RX_HDRSZ +
			   TX_BUFSZ);
	if (!buf) {
		return NULL;
	}
	r->txbuf = buf;

	struct zb_stream *s = (void *)(buf + TX_BUFSZ);
	zb_init_stream(s, RX_BUFSZ, RX_HDRSZ);

	// copy the remaining data into the msg receive buffer
	size_t sz = in + inhave - innext;
	if (sz) {
		char *p1, *p2;
		size_t n1, n2;
		zb_get_stream_recvbuf(s, &p1, &n1, &p2, &n2);
		assert(n1 > sizeof(in));
		memcpy(p1, innext, sz);
		s->have = sz;
	}

	// register_remote will send the Hello reply
	mtx_lock(&r->bus->lk);
	int err = register_remote(r->bus, r, &r->addr, serial, &r->reader);
	mtx_unlock(&r->bus->lk);
	return err ? NULL : s;
}
