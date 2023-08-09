#include "stream.h"
#include <assert.h>

void init_msg_stream(struct msg_stream *s, size_t msgsz, size_t defragsz)
{
	assert((msgsz & (msgsz - 1)) == 0);
	assert(defragsz >= DBUS_MIN_MSG_SIZE);
	s->cap = msgsz;
	s->defrag = defragsz;
	s->have = 0;
	s->used = 0;
}

void stream_buffers(struct msg_stream *s, char **p1, size_t *n1, char **p2,
		    size_t *n2)
{
	// shouldn't be possible to overflow the buffer
	assert(s->have <= s->used + s->cap);

	if (s->have < s->used) {
		// skipping data
		*p1 = s->buf;
		*n1 = s->used - s->have;
		if (*n1 > s->cap) {
			*n1 = s->cap;
		}
		*n2 = 0;
	} else if (s->have == s->used) {
		// empty buffer
		s->used = 0;
		s->have = 0;
		*p1 = s->buf;
		*n1 = s->cap;
		*n2 = 0;
	} else if (s->have < s->used + s->cap) {
		// normal buffer use
		size_t begin = s->used & (s->cap - 1);
		size_t end = s->have & (s->cap - 1);
		*p1 = s->buf + begin;
		if (begin < end) {
			// begin < end:  |  B+++E  | want +s
			*n1 = end - begin;
			*n2 = 0;
		} else {
			// want +s
			// !end: |E   B++++|
			// end < begin: |++E   B++|
			// end == begin: |++++EB+++|
			*n1 = s->cap - begin;
			*p2 = s->buf;
			*n2 = end;
		}
	} else {
		// full buffer
		*n1 = 0;
		*n2 = 0;
	}
}

int stream_next(struct msg_stream *s, struct message *msg)
{
	for (;;) {
		size_t used = s->used;
		size_t have = s->have;

		if (used + DBUS_MIN_MSG_SIZE > have) {
			return STREAM_MORE;
		}

		size_t cap = s->cap;
		size_t mask = s->cap - 1;
		size_t begin = s->used & mask;
		size_t end = s->have & mask;

		// defragment the fixed header
		char *buf = s->buf;
		char *hdr = buf + begin;
		if (begin + DBUS_MIN_MSG_SIZE > cap) {
			size_t n = (begin + DBUS_MIN_MSG_SIZE) & mask;
			memcpy(buf + cap, buf, n);
		}

		// parse the fixed header
		size_t hsz, bsz;
		if (parse_message_size(hdr, &hsz, &bsz)) {
			return STREAM_ERROR;
		}
		size_t msz = hsz + bsz;
		if (msz > cap || hsz > s->defrag) {
			// message is too long, will need to skip it
			s->used += msz;
			continue;
		}
		if (used + msz > have) {
			return STREAM_MORE;
		}

		// defragment the rest of the header
		if (begin + hsz > cap) {
			size_t n = (begin + hsz) & mask;
			memcpy(buf + cap, buf, n);
		}

		// parse the full header
		if (parse_header(msg, hdr)) {
			// drop the message and continue
			s->used += msz;
			continue;
		}

		// find the body
		begin = (used + hsz) & mask;
		end = (used + msz) & mask;
		s->body = buf + begin;
		s->used += msz;

		if (begin <= end) {
			/* |  B+++E  | */
			s->bsz[0] = bsz;
			s->bsz[1] = 0;
		} else {
			/* |++E    B++| */
			s->bsz[0] = cap - begin;
			s->bsz[1] = end;
		}

		return STREAM_OK;
	}
}

int defragment_body(struct msg_stream *s, struct message *msg,
		    struct iterator *ii)
{
	if (s->bsz[0] + s->bsz[1] > s->defrag) {
		return -1;
	}
	if (s->bsz[1]) {
		// Second part should be at the beginning of the buffer.
		// We're going to copy it to the end in the defrag portion.
		memcpy(s->buf + s->cap, s->buf, s->bsz[1]);
	}
	init_iterator(ii, msg->signature, s->body, s->bsz[0] + s->bsz[1]);
	return 0;
}
