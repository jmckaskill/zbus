#pragma once

#include "types.h"
#include <stdlib.h>

struct iterator {
	const char *base;
	const char *sig;
	uint32_t next;
	uint32_t end;
};

struct variant {
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
		slice_t str;
		slice_t path;
		const char *sig;
		struct iterator record;
		struct iterator array;
		struct iterator variant;
	} u;
};

/////////////////////
// raw data decoding

static void init_iterator(struct iterator *ii, const char *sig, slice_t data);

static int iter_error(struct iterator *p);

// check iter_error before using any of these values
extern uint8_t parse_byte(struct iterator *p);
extern bool parse_bool(struct iterator *p);
extern int16_t parse_int16(struct iterator *p);
extern uint16_t parse_uint16(struct iterator *p);
extern int32_t parse_int32(struct iterator *p);
extern uint32_t parse_uint32(struct iterator *p);
extern int64_t parse_int64(struct iterator *p);
extern uint64_t parse_uint64(struct iterator *p);
extern slice_t parse_string(struct iterator *p);
extern slice_t parse_path(struct iterator *p);
extern const char *parse_signature(struct iterator *p);
extern struct variant parse_variant(struct iterator *p);
extern void parse_struct_begin(struct iterator *p);
extern void parse_struct_end(struct iterator *p);
extern void parse_dict_begin(struct iterator *p);
extern void parse_dict_end(struct iterator *p);

extern int check_string(slice_t s);
extern int check_path(slice_t s);
extern int check_member(slice_t s);
extern int check_interface(slice_t s);
extern int check_address(slice_t s);
extern int check_unique_address(slice_t s);
static int check_error_name(slice_t s);
static int check_known_address(slice_t s);

extern struct array_data parse_array(struct iterator *p);
extern bool array_has_more(struct iterator *p, struct array_data *pd);

// skip functions skip over data possibly returning an iterator to the data.
// They do not fully validate the information.
extern struct iterator skip_array(struct iterator *p);
extern struct iterator skip_value(struct iterator *p);
extern int skip_signature(const char **psig, bool in_array);
static bool is_signature(const char *sig, const char *test);

extern void align_iterator_8(struct iterator *p);

extern void TEST_parse();

//////////////////////////////////////
// message decoding

// returns -ve on invalid message header
// returns 0 on insufficient data to determine size
// returns number of bytes in header or message
int parse_header_size(slice_t data);
int parse_message_size(slice_t data);

// buffer needs to include all the message fields data
// returns non-zero on error
int parse_header(struct message *msg, slice_t data);

////////////////////////////////////////
// inline implementations

static inline void init_iterator(struct iterator *ii, const char *sig,
				 slice_t s)
{
	ii->base = s.p;
	ii->next = 0;
	ii->end = s.len;
	ii->sig = sig;
}

static inline int iter_error(struct iterator *p)
{
	return p->next > p->end;
}

static inline int check_error_name(slice_t p)
{
	return check_interface(p);
}

static inline int check_known_address(slice_t p)
{
	return check_interface(p);
}

static inline bool is_signature(const char *sig, const char *test)
{
	// depending on where it's come from sig may contain arguments
	// after the one we're interested in. As long as test is a complete
	// type, which it should be as the programmer provided it, we just
	// need to test up to strlen(test)
	return !strncmp(sig, test, strlen(test));
}

static inline uint8_t native_endian()
{
	union test {
		uint16_t u;
		uint8_t b[2];
	} test;
	test.u = 0x426C; // "Bl"
	return test.b[0];
}
