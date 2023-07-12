#include "stream.h"
#include "message.h"
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static struct msg_header *message_header(struct stream_buffer *b)
{
	return (struct msg_header *)(b->data + ALIGN_UINT_UP(b->off, 8));
}

static void debug_fill(struct stream_buffer *b)
{
#ifndef NDEBUG
	memset(b->data + b->end, 0xDE, b->cap - b->end);
#endif
}

void realign_buffer(struct stream_buffer *b)
{
	memmove(b->data, b->data + b->off, b->end - b->off);
	b->end -= b->off;
	b->off = 0;
	debug_fill(b);
}

static int grow_buffer(struct stream_buffer *b, unsigned need)
{
	// add 7 bytes extra to allow for slop in the alignment
	unsigned newcap = ALIGN_UINT_UP(need + 7, 64 * 1024);
	if (newcap != b->cap) {
		// grow/shrink the buffer
		char *newdata = malloc(newcap);
		if (newdata == NULL) {
			return -1;
		}
		// make sure we maintain 8 byte alignment
		assert((((uintptr_t)newdata) & 7) == 0);
		unsigned off = ALIGN_UINT_DOWN(b->off, 8);
		memcpy(newdata, b->data + off, b->end - off);
		free(b->data);
		b->data = newdata;
		b->cap = newcap;
		b->off -= off;
		b->end -= off;
		debug_fill(b);
	} else if (b->off + need > b->cap) {
		// compact the existing buffer
		unsigned off = ALIGN_UINT_DOWN(b->off, 8);
		memmove(b->data, b->data + off, b->end - off);
		b->off -= off;
		b->end -= off;
		debug_fill(b);
	}
	return 0;
}

static int do_read(int fd, struct stream_buffer *b, unsigned need)
{
	if (grow_buffer(b, need)) {
		return READ_ERROR;
	}

	unsigned newend = b->off + need;
	while (b->end < newend) {
		int n = read(fd, b->data + b->end, b->cap - b->off);
		if (n < 0 && errno == EINTR) {
			continue;
		} else if (n < 0 && errno == EAGAIN) {
			return READ_MORE;
		} else if (n <= 0) {
			return READ_ERROR;
		}
		b->end += n;
	}
	return READ_OK;
}

int read_message(int fd, struct stream_buffer *b, struct msg_header **phdr)
{
	int sts = do_read(fd, b,
			  ALIGN_UINT_UP(b->off, 8) - b->off +
				  sizeof(struct msg_header));
	if (sts != READ_OK) {
		return sts;
	}

	struct msg_header *h = message_header(b);
	int len = raw_message_length(h);
	if (len < 0) {
		return READ_ERROR;
	}
	sts = do_read(fd, b, len);
	if (sts != READ_OK) {
		return sts;
	}
	// do_read may resize the buffer so grab the header again
	*phdr = message_header(b);
	return READ_OK;
}

void drop_message(struct stream_buffer *b)
{
	struct msg_header *h = message_header(b);
	char *data = message_data(h);
	char *end = data + h->body_len;
	b->off = (unsigned)(end - b->data);
}

static int peek_char(int fd, struct stream_buffer *b, unsigned idx)
{
	if (b->off + idx == b->end && do_read(fd, b, idx + 1) != READ_OK) {
		return -1;
	}
	return ((unsigned char *)b->data)[b->off + idx];
}

int read_char(int fd, struct stream_buffer *b)
{
	int ch = peek_char(fd, b, 0);
	if (ch < 0) {
		return -1;
	}
	b->off++;
	return ch;
}

char *read_crlf_line(int fd, struct stream_buffer *b)
{
	assert((fcntl(fd, F_GETFL) & O_NONBLOCK) == 0);
	unsigned n = 0;

	for (;;) {
		int ch = peek_char(fd, b, n);
		// look for a terminating \r\n
		if (ch == '\r') {
			if (peek_char(fd, b, n + 1) != '\n') {
				return NULL;
			}
			// return the line, removing the \r\n
			char *line = b->data + b->off;
			line[n] = 0;
			b->off += n + 2;
			return line;
		}
		// only ASCII non control characters are allowed
		if (ch < 0 || ch < ' ' || ch > '~') {
			return NULL;
		}
		n++;
	}
}