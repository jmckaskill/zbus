#define _GNU_SOURCE
#include "stream.h"
#include "message.h"
#include "unix.h"
#include "log.h"
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

void init_stream(struct stream *s, int fd, char *p, unsigned cap)
{
	s->base = p;
	s->cap = cap;
	s->off = 0;
	s->end = 0;
	s->fd = fd;
	init_unix_oob(&s->oob);
}

void close_stream(struct stream *s)
{
	close_fds(&s->oob, s->oob.fdn);
}

static void debug_fill_stream(struct stream *s)
{
#ifndef NDEBUG
	memset(s->base + s->end, 0xDE, s->cap - s->end);
#endif
}

void reset_stream_alignment(struct stream *s)
{
	memmove(s->base, s->base + s->off, s->end - s->off);
	s->end -= s->off;
	s->off = 0;
	debug_fill_stream(s);
}

static int compact_stream(struct stream *s, unsigned need)
{
	if (s->off + need > s->cap) {
		// compact the existing buffer maintaining 8 byte alignment
		unsigned off = ALIGN_UINT_DOWN(s->off, 8);
		memmove(s->base, s->base + off, s->end - off);
		s->off -= off;
		s->end -= off;
		debug_fill_stream(s);
	}
	return 0;
}

static int do_read(struct stream *s, unsigned need)
{
	if (compact_stream(s, need)) {
		return READ_ERROR;
	}

	unsigned newend = s->off + need;
	while (s->end < newend) {
		union {
			char buf[CONTROL_BUFFER_SIZE];
			struct cmsghdr align;
		} control;

		struct iovec iov;
		iov.iov_base = s->base + s->end;
		iov.iov_len = s->cap - s->off;

		struct msghdr msg;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.buf;
		msg.msg_controllen = sizeof(control);
		msg.msg_flags = 0;

		int n = recvmsg(s->fd, &msg, 0);
		if (n < 0 && errno == EINTR) {
			continue;
		} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return READ_MORE;
		} else if (n <= 0) {
			perror("recvmsg");
			return READ_ERROR;
		}

		log_data(s->base + s->end, n, "read");

		if (parse_cmsg(&s->oob, &msg)) {
			fprintf(stderr, "too many file descriptors\n");
			return READ_ERROR;
		}

		s->end += n;
	}
	return READ_OK;
}

int read_message(struct stream *s, struct message *msg, struct iterator *body)
{
	// NOTE - do_read may compact the buffer after every call
	// We may still have a few bytes need to be read to align the message

	unsigned pad = ALIGN_UINT_UP(s->off, 8) - s->off;
	unsigned need = pad + MIN_MESSAGE_SIZE;
	int sts = do_read(s, need);
	if (sts != READ_OK) {
		return sts;
	}

	int len = parse_header(msg, s->base + s->off + pad);
	if (len < 0) {
		return READ_ERROR;
	}

	// now that we've read the padding, we can remove it
	s->off += pad;

	sts = do_read(s, len);
	if (sts != READ_OK) {
		return sts;
	}
	str_t p;
	p.p = s->base + s->off;
	p.len = len;
	p.cap = len;
	if (parse_message(msg, &p)) {
		return READ_ERROR;
	}
	init_iterator(body, msg->signature, p.p, 0, p.len);
	if (msg->fdnum > s->oob.fdn) {
		fprintf(stderr, "message asks for more fds than sent\n");
		return READ_ERROR;
	}
	return READ_OK;
}

void drop_message(struct stream *s, const struct message *msg)
{
	int len = ALIGN_UINT_UP(MIN_MESSAGE_SIZE + msg->field_len, 8) +
		  msg->body_len;
	s->off += len;
	close_fds(&s->oob, msg->fdnum);
}

static int peek_char(struct stream *s, unsigned idx)
{
	if (s->off + idx == s->end && do_read(s, idx + 1) != READ_OK) {
		return -1;
	}
	return ((unsigned char *)s->base)[s->off + idx];
}

int read_char(struct stream *s)
{
	int ch = peek_char(s, 0);
	if (ch < 0) {
		return -1;
	}
	s->off++;
	return ch;
}

char *read_crlf_line(struct stream *s)
{
	unsigned n = 0;

	for (;;) {
		int ch = peek_char(s, n);
		// look for a terminating \r\n
		if (ch == '\r') {
			if (peek_char(s, n + 1) != '\n') {
				return NULL;
			}
			// return the line, removing the \r\n
			char *line = s->base + s->off;
			line[n] = 0;
			s->off += n + 2;
			return line;
		}
		// only ASCII non control characters are allowed
		if (ch < 0 || ch < ' ' || ch > '~') {
			return NULL;
		}
		n++;
	}
}
