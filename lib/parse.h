#pragma once

#include "types.h"
#include <stdlib.h>

struct iterator {
	const char *base;
	const char *sig;
	uint32_t next;
	uint32_t end;
};

union variant_union {
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
};

struct variant {
	const char *sig;
	union variant_union u;
};

static void init_iterator(struct iterator *p, const char *sig, const void *base,
			  uint32_t off, uint32_t end);

// check iter_error before using any of these values
uint8_t parse_byte(struct iterator *p);
bool parse_bool(struct iterator *p);
int16_t parse_int16(struct iterator *p);
uint16_t parse_uint16(struct iterator *p);
int32_t parse_int32(struct iterator *p);
uint32_t parse_uint32(struct iterator *p);
int64_t parse_int64(struct iterator *p);
uint64_t parse_uint64(struct iterator *p);
slice_t parse_string(struct iterator *p);
slice_t parse_path(struct iterator *p);
const char *parse_signature(struct iterator *p);
struct variant parse_variant(struct iterator *p);
void parse_struct_begin(struct iterator *p);
void parse_struct_end(struct iterator *p);
void parse_dict_begin(struct iterator *p);
void parse_dict_end(struct iterator *p);

int check_string(slice_t s);
int check_path(const char *p);

static inline int iter_error(struct iterator *p)
{
	return p->next > p->end;
}

// psig must point to NULL before first call
bool parse_array_next(struct iterator *p, const char **psig);

// skip functions skip over data possibly returning an iterator to the data.
// They do not fully validate the information.
struct iterator skip_array(struct iterator *p);
struct iterator skip_value(struct iterator *p);
int skip_signature(const char **psig, bool in_array);

void align_iterator_8(struct iterator *p);

void TEST_parse();

static inline void init_iterator(struct iterator *p, const char *sig,
				 const void *base, uint32_t off, uint32_t end)
{
	p->base = (const char *)base;
	p->next = off;
	p->end = end;
	p->sig = sig;
}
