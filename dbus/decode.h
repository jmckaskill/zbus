#pragma once

#include "types.h"
#include <stdlib.h>

/////////////////////
// raw data decoding

static void init_iterator(struct iterator *ii, const char *sig, char *data,
			  size_t sz);

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
extern double parse_double(struct iterator *p);
extern char *parse_string(struct iterator *p, size_t *psz);
extern char *parse_path(struct iterator *p, size_t *psz);
extern const str8_t *parse_string8(struct iterator *p);
extern const char *parse_signature(struct iterator *p);
extern struct variant parse_variant(struct iterator *p);
extern void parse_struct_begin(struct iterator *p);
extern void parse_struct_end(struct iterator *p);
extern void parse_dict_begin(struct iterator *p);
extern void parse_dict_end(struct iterator *p);

extern struct array_data parse_array(struct iterator *p);
extern bool array_has_more(struct iterator *p, struct array_data *a);

// skip functions skip over data possibly returning an iterator to the data.
// They do not fully validate the information.
extern struct iterator skip_array(struct iterator *p);
extern struct iterator skip_value(struct iterator *p);
extern int skip_signature(const char **psig);
static bool is_signature(const char *sig, const char *test);

extern void align_iterator_8(struct iterator *p);

extern void TEST_parse(void);

//////////////////////////////////////
// message decoding

// buffer must be at least DBUS_MIN_MSG_SIZE long
// returns non-zero on invalid message header
// returns zero on success and sets phdr and pbody to the header and body sizes
// returns number of bytes in header or message
int parse_message_size(char *p, size_t *phdr, size_t *pbody);

// buffer needs to be at least as long as the hdr size returned
// by parse_message_size
// returns non-zero on error
int parse_header(struct message *msg, char *p);

////////////////////////////////////////
// inline implementations

static inline void init_iterator(struct iterator *ii, const char *sig, char *p,
				 size_t sz)
{
	assert(sz < DBUS_MAX_MSG_SIZE);
	ii->base = p;
	ii->next = 0;
	ii->end = (uint32_t)sz;
	ii->sig = sig;
}

static inline int iter_error(struct iterator *p)
{
	return p->next > p->end;
}

static inline bool is_signature(const char *sig, const char *test)
{
	// depending on where it's come from sig may contain arguments
	// after the one we're interested in. As long as test is a complete
	// type, which it should be as the programmer provided it, we just
	// need to test up to strlen(test)
	return !strncmp(sig, test, strlen(test));
}

static inline uint8_t native_endian(void)
{
	union test {
		uint16_t u;
		uint8_t b[2];
	} test;
	test.u = 0x426C; // "Bl"
	return test.b[0];
}
