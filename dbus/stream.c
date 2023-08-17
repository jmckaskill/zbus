#include "internal.h"

void zb_init_stream(struct zb_stream *s, size_t msgsz, size_t hdrsz)
{
	assert((msgsz & (msgsz - 1)) == 0);
	assert(hdrsz >= ZB_MIN_MSG_SIZE);

	s->cap = msgsz;
	s->defrag = hdrsz;
	s->have = 0;
	s->used = 0;
}

void zb_get_stream_recvbuf(struct zb_stream *s, char **p1, size_t *n1,
			   char **p2, size_t *n2)
{
	// shouldn't be possible to overflow the buffer
	assert(s->have <= s->used + s->cap);

	// Cases (+ = unparsed data, - = buffer room to fill)
	// 1. used > have - skipping data
	// 2. used == have - empty buffer - |-----EB---|
	// 3. begin < end - good data in one section - |--B++++E---|
	// 4. begin > end - good data in two sections - |++E---B++|
	// 5. begin == end - full buffer - |+++EB++++|

	size_t cap = s->cap;
	size_t mask = s->cap - 1;
	size_t used = s->used;
	size_t have = s->have;
	size_t begin = used & mask;
	size_t end = have & mask;

	if (have < used) {
		// 1. used > have - skipping data
		// Read full buffer lengths up until used == have. We'll then
		// fall in to case #2 and reset the offsets.
		*p1 = s->buf;
		*n1 = used - have;
		if (*n1 > cap) {
			*n1 = cap;
		}
		*n2 = 0;
	} else if (have == used) {
		// 2. used == have - empty buffer - |-----EB---|
		// Reset the offsets to reduce fragementation.
		s->used = 0;
		s->have = 0;
		*p1 = s->buf;
		*n1 = cap;
		*n2 = 0;
	} else if (begin < end) {
		// 3. begin < end - good data in one section - |--B++++E---|
		*p1 = s->buf + end;
		*n1 = cap - end;
		*p2 = s->buf;
		*n2 = begin;
	} else {
		// 4. begin > end - good data in two sections - |++E---B++|
		// 5. begin == end - full buffer - |+++EB++++|
		*p1 = s->buf + end;
		*n1 = begin - end;
		*n2 = 0;
	}
}

int zb_read_auth(struct zb_stream *s)
{
	assert(!s->used);
	int rd = zb_decode_auth_reply(s->buf, s->have);
	if (!rd && s->have == s->cap) {
		return -1;
	} else if (rd <= 0) {
		return rd;
	}
	s->used += rd;
	return 1;
}

int zb_read_message(struct zb_stream *s, struct zb_message *msg)
{
	for (;;) {
		size_t used = s->used;
		size_t have = s->have;

		if (used + ZB_MIN_MSG_SIZE > have) {
			return 0;
		}

		size_t cap = s->cap;
		size_t mask = s->cap - 1;
		size_t begin = s->used & mask;
		size_t end = s->have & mask;

		// defragment the fixed header
		char *buf = s->buf;
		char *hdr = buf + begin;
		if (begin + ZB_MIN_MSG_SIZE > cap) {
			size_t n = (begin + ZB_MIN_MSG_SIZE) & mask;
			memcpy(buf + cap, buf, n);
		}

		// parse the fixed header
		size_t hsz, bsz;
		if (zb_parse_size(hdr, &hsz, &bsz)) {
			return -1;
		}
		size_t msz = hsz + bsz;
		if (msz > cap || hsz > s->defrag) {
			// message is too long, will need to skip it
			s->used += msz;
			continue;
		}
		if (used + msz > have) {
			return 0;
		}

		// defragment the rest of the header
		if (begin + hsz > cap) {
			size_t n = (begin + hsz) & mask;
			memcpy(buf + cap, buf, n);
		}

		// parse the full header
		if (zb_parse_header(msg, hdr)) {
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

		return 1;
	}
}

int zb_defragment_body(struct zb_stream *s, struct zb_message *msg,
		       struct zb_iterator *ii)
{
	if (s->bsz[0] + s->bsz[1] > s->defrag) {
		return -1;
	}
	if (s->bsz[1]) {
		// Second part should be at the beginning of the buffer.
		// We're going to copy it to the end in the defrag portion.
		memcpy(s->buf + s->cap, s->buf, s->bsz[1]);
	}
	zb_init_iterator(ii, msg->signature, s->body, s->bsz[0] + s->bsz[1]);
	return 0;
}
