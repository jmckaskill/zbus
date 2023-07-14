#pragma once

#include "parse.h"
#include "marshal.h"
#include <stdint.h>

#define MAX_MESSAGE_SIZE (64 * 1024)
#define MIN_MESSAGE_SIZE 16
#define MAX_UNIX_FDS 16

#define MSG_INVALID 0
#define MSG_METHOD 1
#define MSG_REPLY 2
#define MSG_ERROR 3
#define MSG_SIGNAL 4

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

struct msg_header {
	uint8_t endian;
	uint8_t type;
	uint8_t flags;
	uint8_t version;
	uint32_t body_len;
	uint32_t serial;
};

struct message {
	struct msg_header hdr;
	int64_t reply_serial;
	slice_t path;
	slice_t interface;
	slice_t member;
	slice_t error;
	slice_t destination;
	slice_t sender;
	const char *signature;
	unsigned fdnum;
};

void init_message(struct message *m);

int check_member(const char *p);
int check_interface(const char *p);
int check_address(const char *p);
int check_unique_address(const char *p);
static int check_error_name(const char *p);
static int check_known_address(const char *p);

// buffer needs to be at least MIN_MESSAGE_SIZE large
// returns -ve on invalid message header
int raw_message_len(const char *p);

// buffer points to at least raw_message_len long
// returns non-zero on parse error
int parse_message(const char *p, struct message *msg, struct iterator *body);
bool is_reply(const struct message *request, const struct message *reply);

struct message_data {
	unsigned start;
	unsigned body;
};

// start_message starts a message appending the message header to the buffer
// buffer must already be initialized
void start_message(struct buffer *b, const struct message *m,
		   struct message_data *data);
void end_message(struct buffer *b, struct message_data *data);
void append_empty_message(struct buffer *b, const struct message *m);

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
