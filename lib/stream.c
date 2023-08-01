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
	// shouldn't be possible to under/overflow the buffer
	assert(s->used <= s->have && s->have <= s->used + s->cap);

	if (s->used == s->have) {
		// empty buffer
		s->used = 0;
		s->have = 0;
		*p1 = s->buf;
		*n1 = s->cap;
		*n2 = 0;
		return;
	} else if (s->used + s->cap == s->have) {
		// full buffer
		*n1 = 0;
		*n2 = 0;
		return;
	}

	size_t begin = s->used & (s->cap - 1);
	size_t end = s->have & (s->cap - 1);
	*p1 = s->buf + begin;
	*p2 = s->buf;
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
		*n2 = end;
	}
}

int stream_next(struct msg_stream *s, struct message *m, slice_t *b1,
		slice_t *b2)
{
	size_t used = s->used;
	size_t have = s->have;
	size_t defrag = s->defrag;
	size_t cap = s->cap;
	size_t mask = s->cap - 1;
	size_t begin = used & mask;
	size_t end = have & mask;

	if (used + DBUS_MIN_MSG_SIZE > have) {
		return STREAM_MORE;
	}

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
	if (msz > cap || hsz > defrag) {
		return STREAM_ERROR;
	} else if (used + msz > have) {
		return STREAM_MORE;
	}

	// defragment the rest of the header
	if (begin + hsz > cap) {
		size_t n = (begin + hsz) & mask;
		memcpy(buf + cap, buf, n);
	}

	// parse the full header
	if (parse_header(m, hdr)) {
		return STREAM_ERROR;
	}

	// find the body
	begin = (used + hsz) & mask;
	end = (used + hsz + bsz) & mask;

	if (begin <= end) {
		/* |  B+++E  | */
		b1->p = buf + begin;
		b1->len = bsz;
		b2->p = NULL;
		b2->len = 0;
	} else {
		/* |++E    B++| */
		b1->p = buf + begin;
		b1->len = cap - begin;
		b2->p = buf;
		b2->len = end;
	}

	s->used += hsz + bsz;
	return STREAM_OK;
}

int defragment_body(struct msg_stream *s, slice_t *b1, slice_t *b2)
{
	if (!b2->len) {
		return 0;
	}
	if (b1->len + b2->len > s->defrag) {
		return -1;
	}
	assert(b2->p == s->buf);
	char *p = s->buf - b1->len;
	memcpy(p, b1->p, b1->len);
	b1->p = p;
	b1->len += b2->len;
	b2->len = 0;
	return 0;
}
