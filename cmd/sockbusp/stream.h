#pragma once

struct msg_header;

struct stream_buffer {
    char *data;
    unsigned cap; // size of memory allocation
    unsigned off; // end of consumed data within buffer
    unsigned end; // end of read data within buffer
};

#define INIT_STREAM_BUFFER {NULL,0,0,0}

int read_char(int fd, struct stream_buffer *b);
char *read_crlf_line(int fd, struct stream_buffer *b);
void realign_buffer(struct stream_buffer *b);

#define READ_ERROR -1
#define READ_MORE 1
#define READ_OK 0

int read_message(int fd, struct stream_buffer *b, const struct msg_header **phdr);
void drop_message(struct stream_buffer *b);

