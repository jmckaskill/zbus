#pragma once
#define _GNU_SOURCE
#include "str.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

struct iterator;
struct builder;
struct stream;
struct message;
struct unix_oob;
struct variant_data;
struct array_data;
struct dict_data;

#define ALIGN_UINT_DOWN(VAL, BOUNDARY) ((VAL) & (~(BOUNDARY##U - 1)))

#define ALIGN_UINT_UP(VAL, BOUNDARY) \
	(((VAL) + (BOUNDARY##U - 1)) & (~(BOUNDARY##U - 1)))

#define ALIGN_PTR_UP(PTR, BOUNDARY)                                    \
	((char *)((((uintptr_t)(PTR)) + ((uintptr_t)(BOUNDARY)) - 1) & \
		  (~((((uintptr_t)(BOUNDARY)) - 1)))))

#define MAX_TYPE_DEPTH 64

#define TYPE_INVALID '\0'
#define TYPE_BYTE 'y'
#define TYPE_BOOL 'b'
#define TYPE_INT16 'n'
#define TYPE_UINT16 'q'
#define TYPE_INT32 'i'
#define TYPE_UINT32 'u'
#define TYPE_INT64 'x'
#define TYPE_UINT64 't'
#define TYPE_DOUBLE 'd'
#define TYPE_STRING 's'
#define TYPE_PATH 'o'
#define TYPE_SIGNATURE 'g'
#define TYPE_VARIANT 'v'
#define TYPE_ARRAY 'a'
#define TYPE_STRUCT 'r'
#define TYPE_STRUCT_BEGIN '('
#define TYPE_STRUCT_END ')'
#define TYPE_DICT 'e'
#define TYPE_DICT_BEGIN '{'
#define TYPE_DICT_END '}'

#define DBUS_HDR_SIZE 16
#define DBUS_MAX_MSG_SIZE 0x8000000U
#define DBUS_MAX_VALUE_SIZE 0x4000000U
#define MAX_UNIX_FDS 16

#define BUFSZ_REPLY 64 // 16B hdr, 32B sender, 8B serial, 8B sig
#define BUFSZ_STRING 8 // 3B padding, 4B length, 1B nul
#define BUFSZ_ARRAY 12 // 3B padding, 4B length, 4B padding

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
	uint32_t fdnum;
	uint32_t serial;
	uint32_t reply_serial;
	enum msg_type type;
	uint8_t flags;
	int field_len;
	int body_len;
};

struct raw_header {
	uint8_t endian;
	uint8_t type;
	uint8_t flags;
	uint8_t version;
	uint32_t body_len;
	uint32_t serial;
	uint32_t field_len;
};