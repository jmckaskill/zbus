#pragma once

#include "types.h"
#include <stdlib.h>

// check p->error before using any of these values
uint8_t parse_byte(struct iterator *p);
bool parse_bool(struct iterator *p);
int16_t parse_int16(struct iterator *p);
uint16_t parse_uint16(struct iterator *p);
int32_t parse_int32(struct iterator *p);
uint32_t parse_uint32(struct iterator *p);
int64_t parse_int64(struct iterator *p);
uint64_t parse_uint64(struct iterator *p);
struct string parse_string(struct iterator *p);
struct string parse_path(struct iterator *p);
const char *parse_signature(struct iterator *p);
struct variant parse_variant(struct iterator *p);
void parse_struct_begin(struct iterator *p);
void parse_struct_end(struct iterator *p);
void parse_dict_begin(struct iterator *p);
void parse_dict_end(struct iterator *p);

// psig must point to NULL before first call
bool parse_array_next(struct iterator *p, const char **psig);

extern struct iterator skip_array(struct iterator *p);
extern struct iterator skip_struct(struct iterator *p);
int skip_value(struct iterator *p);
int skip_signature(const char **psig);

void align_iterator_8(struct iterator *p);

void TEST_parse();
