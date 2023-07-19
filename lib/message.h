#pragma once

#include "parse.h"
#include "marshal.h"
#include <stdint.h>

#define MIN_MESSAGE_SIZE 16
#define MAX_MESSAGE_SIZE (64 * 1024)
#define MAX_FIELD_SIZE 256
#define MULTIPART_WORKING_SPACE (256 + 8)
#define MAX_UNIX_FDS 16

#define FIELD_PATH 1
#define FIELD_INTERFACE 2
#define FIELD_MEMBER 3
#define FIELD_ERROR_NAME 4
#define FIELD_REPLY_SERIAL 5
#define FIELD_DESTINATION 6
#define FIELD_SENDER 7
#define FIELD_SIGNATURE 8
#define FIELD_UNIX_FDS 9
#define FIELD_LAST 9

#define FTAG_PATH UINT32_C(0x006F0101) // BYTE: 01 SIG: "o"
#define FTAG_INTERFACE UINT32_C(0x00730102) // BYTE: 02 SIG: "s"
#define FTAG_MEMBER UINT32_C(0x00730103) // BYTE: 03 SIG: "s"
#define FTAG_ERROR_NAME UINT32_C(0x00730104) // BYTE: 04 SIG: "s"
#define FTAG_REPLY_SERIAL UINT32_C(0x00750105) // BYTE: 05 SIG: "u"
#define FTAG_DESTINATION UINT32_C(0x00730106) // BYTE: 06 SIG: "s"
#define FTAG_SENDER UINT32_C(0x00730107) // BYTE: 07 SIG: "s"
#define FTAG_SIGNATURE UINT32_C(0x00670108) // BYTE: 08 SIG: "g"
#define FTAG_UNIX_FDS UINT32_C(0x00750109) // BYTE: 09 SIG: "u"

#define DBUS_VERSION 1

#define FLAG_NO_REPLY_EXPECTED 1
#define FLAG_NO_AUTO_START 2
#define FLAG_ALLOW_INTERACTIVE_AUTHORIZATION 4

enum msg_type {
	MSG_INVALID = 0,
	MSG_METHOD = 1,
	MSG_REPLY = 2,
	MSG_ERROR = 3,
	MSG_SIGNAL = 4,
};

struct message {
	slice_t path;
	slice_t interface;
	slice_t member;
	slice_t error;
	slice_t destination;
	slice_t sender;
	const char *signature;
	unsigned fdnum;
	unsigned field_len;
	unsigned body_len;
	uint32_t serial;
	uint32_t reply_serial;
	enum msg_type type;
	uint8_t flags;
};

void init_message(struct message *m, enum msg_type type, uint32_t serial);
bool is_reply(const struct message *request, const struct message *reply);

int check_string(slice_t s);
int check_path(const char *p);
int check_member(const char *p);
int check_interface(const char *p);
int check_address(const char *p);
int check_unique_address(const char *p);
static int check_error_name(const char *p);
static int check_known_address(const char *p);

// buffer needs to be at least MIN_MESSAGE_SIZE large
// returns -ve on invalid message header
// returns number of bytes for full message
int parse_header(struct message *msg, const char *p);

// called after parse_header once we've received enough data bytes
// parts contains the message data bytes and does not need to be aligned
// but each part (except for the last) needs to contain at least
// MULTIPART_WORKING_SPACE available at the end of the part. This is used in
// case a header field falls across a part gap. On success parts is overwritten
// with the message body parts. Returns zero on success, non-zero on error.
int parse_message(struct message *msg, str_t *parts);

static inline int buffer_error(struct buffer b)
{
	return b.off > b.cap;
}

struct buffer start_message(const struct message *m, void *buf, size_t bufsz);

// returns negative on error marshalling the message
// positive number of bytes in the message
int end_message(struct buffer b);

////////////////////////////////////////
// inline implementations

static inline int check_error_name(const char *p)
{
	return check_interface(p);
}

static inline int check_known_address(const char *p)
{
	return check_interface(p);
}
