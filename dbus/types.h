#pragma once
#define _GNU_SOURCE
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#define ZB_EXTERN_C extern "C"
#else
#define ZB_EXTERN_C extern
#endif

#if !defined ZB_EXPORT_DLL
#define ZB_EXTERN ZB_EXTERN_C
#elif defined ZB_BUILDING
#define ZB_EXTERN ZB_EXTERN_C __declspec(dllexport)
#else
#define ZB_EXTERN ZB_EXTERN_C __declspec(dllimport)
#endif

#define ZB_INLINE static inline

struct zb_iterator;
struct zb_builder;
struct zb_stream;
struct zb_message;
typedef struct zb_str8 zb_str8;

#define ZB_ALIGN_UP(VAL, BOUNDARY) \
	(((VAL) + (BOUNDARY##U - 1)) & (~(BOUNDARY##U - 1)))

#define ZB_BYTE 'y'
#define ZB_BOOL 'b'
#define ZB_INT16 'n'
#define ZB_UINT16 'q'
#define ZB_INT32 'i'
#define ZB_UINT32 'u'
#define ZB_INT64 'x'
#define ZB_UINT64 't'
#define ZB_DOUBLE 'd'
#define ZB_STRING 's'
#define ZB_PATH 'o'
#define ZB_SIGNATURE 'g'
#define ZB_VARIANT 'v'
#define ZB_ARRAY 'a'
#define ZB_STRUCT 'r'
#define ZB_STRUCT_BEGIN '('
#define ZB_STRUCT_END ')'
#define ZB_DICT 'e'
#define ZB_DICT_BEGIN '{'
#define ZB_DICT_END '}'

#define ZB_MIN_MSG_SIZE 16
#define ZB_MAX_MSG_SIZE 0x8000000U
#define ZB_MAX_VALUE_SIZE 0x4000000U

#define ZB_BUF_FIELD 8 // string: 3B padding, 4B tag, u32: 4B tag, 4B value
#define ZB_BUF_STRING 8 // 3B padding, 4B length, 1B nul
#define ZB_BUF_ARRAY 12 // 3B padding, 4B length, 4B padding

#define ZB_NO_REPLY_EXPECTED 1
#define ZB_NO_AUTO_START 2
#define ZB_ALLOW_INTERACTIVE_AUTHORIZATION 4
#define ZB_FLAG_MASK 7

#define ZB_FIELD_PATH 1
#define ZB_FIELD_INTERFACE 2
#define ZB_FIELD_MEMBER 3
#define ZB_FIELD_ERROR_NAME 4
#define ZB_FIELD_REPLY_SERIAL 5
#define ZB_FIELD_DESTINATION 6
#define ZB_FIELD_SENDER 7
#define ZB_FIELD_SIGNATURE 8
#define ZB_FIELD_UNIX_FDS 9
#define ZB_FIELD_LAST 9

#define ZB_STREAM_OK 0
#define ZB_STREAM_ERROR -1
#define ZB_STREAM_READ_MORE -2
#define ZB_STREAM_WRITE_MORE -3

enum zb_msg_type {
	ZB_METHOD = 1,
	ZB_REPLY = 2,
	ZB_ERROR = 3,
	ZB_SIGNAL = 4,
};

struct zb_message {
	// NULL pointer indicates lack of the field
	const zb_str8 *path;
	const zb_str8 *interface;
	const zb_str8 *member;
	const zb_str8 *error;
	const zb_str8 *destination;
	const zb_str8 *sender;
	// signature must be non NULL
	const char *signature;
	uint32_t fdnum;
	// 0 is the invalid serial value
	uint32_t serial;
	uint32_t reply_serial;
	uint8_t type;
	uint8_t flags;
};

struct zb_scope {
	void *data[3];
};

struct zb_iterator {
	char *base;
	const char *nextsig;
	uint32_t next;
	uint32_t end;
};

struct zb_builder {
	char *base;
	const char *nextsig;
	uint32_t next;
	uint32_t end;
};

struct zb_variant {
	const char *sig;
	union {
		bool b;
		uint8_t u8;
		int16_t i16;
		uint16_t u16;
		int32_t i32;
		uint32_t u32;
		int64_t i64;
		uint64_t u64;
		double d;
		struct {
			const char *p;
			size_t len;
		} str, path;
		const char *sig;
		struct zb_iterator record;
		struct zb_iterator array;
		struct zb_iterator variant;
	} u;
};
