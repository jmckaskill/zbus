#pragma once
#include "decode.h"
#include <stdlib.h>

struct zb_stream {
	size_t cap;
	size_t defrag;
	size_t used;
	size_t have;
	char *body;
	size_t bsz[2];
	char buf[1];
};

// msgsz must be a power of 2
void zb_init_stream(struct zb_stream *s, size_t msgsz, size_t hdrsz);
void zb_get_stream_recvbuf(struct zb_stream *s, char **p1, size_t *n1,
			   char **p2, size_t *n2);

// returns one of the ZB_STREAM_* error codes
int zb_read_message(struct zb_stream *s, struct zb_message *m);
int zb_read_auth(struct zb_stream *s);

int zb_defragment_body(struct zb_stream *s, struct zb_message *m,
		       struct zb_iterator *ii);

ZB_INLINE void zb_get_stream_body(struct zb_stream *s, char **p1, size_t *n1,
				  char **p2, size_t *n2)
{
	*p1 = s->body;
	*n1 = s->bsz[0];
	*p2 = s->buf;
	*n2 = s->bsz[1];
}
