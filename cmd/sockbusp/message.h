#pragma once

#include "parse.h"
#include <stdint.h>

// allows for alignment within a 64KB buffer
#define MAX_MESSAGE_SIZE ((64 * 1024) - 8)

#define MSG_METHOD 1
#define MSG_REPLY 2
#define MSG_ERROR 3
#define MSG_SIGNAL 4

#define HEADER_PATH 1
#define HEADER_INTERFACE 2
#define HEADER_MEMBER 3
#define HEADER_ERROR_NAME 4
#define HEADER_REPLY_SERIAL 5
#define HEADER_DESTINATION 6
#define HEADER_SENDER 7
#define HEADER_SIGNATURE 8
#define HEADER_UNIX_FDS 9

struct msg_header {
	uint8_t endian;
	uint8_t type;
	uint8_t flags;
	uint8_t version;
	uint32_t body_len;
	uint32_t serial;
	uint32_t header_len;
};

struct msg_fields {
	int64_t reply_serial;
	unsigned fdnum;
	struct string path;
	struct string interface;
	struct string member;
	struct string error;
	struct string destination;
	struct string sender;
	struct string signature;
};

uint8_t native_endian();
int check_member(const char *p);
int check_interface(const char *p);
int check_address(const char *p);
int check_unique_address(const char *p);
static inline int check_error_name(const char *p)
{
	return check_interface(p);
}
static inline int check_known_address(const char *p)
{
	return check_interface(p);
}

int parse_header_fields(struct msg_fields *f, const struct msg_header *h);
char *message_data(struct msg_header *h);
int raw_message_length(const struct msg_header *h);
