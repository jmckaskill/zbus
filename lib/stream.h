#pragma once

#include "types.h"
#include "unix.h"

struct stream {
	char *base;
	unsigned cap; // size of memory allocation
	unsigned off; // end of consumed data within buffer
	unsigned end; // end of read data within buffer
	int fd;
	struct unix_oob oob;
};

void init_stream(struct stream *s, int fd, char *p, unsigned cap);
void close_stream(struct stream *s);
int read_char(struct stream *s);
char *read_crlf_line(struct stream *s);
void reset_stream_alignment(struct stream *s);

#define READ_ERROR -1
#define READ_MORE 1
#define READ_OK 0

int read_message(struct stream *s, struct message *msg, struct iterator *body);
void drop_message(struct stream *s, const struct message *msg);
