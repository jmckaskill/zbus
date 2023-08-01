#pragma once
#include "decode.h"
#include <stdlib.h>

struct msg_stream {
	size_t cap;
	size_t defrag;
	size_t used;
	size_t have;
	char buf[0];
};

// msgsz must be a power of 2
void init_msg_stream(struct msg_stream *s, size_t msgsz, size_t defragsz);

void stream_buffers(struct msg_stream *s, char **p1, size_t *n1, char **p2,
		    size_t *n2);

#define STREAM_OK 0
#define STREAM_MORE 1
#define STREAM_ERROR -1

int stream_next(struct msg_stream *s, struct message *m, slice_t *b1,
		slice_t *b2);

int defragment_body(struct msg_stream *s, slice_t *b1, slice_t *b2);
