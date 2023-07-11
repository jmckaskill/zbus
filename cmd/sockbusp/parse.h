#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define TYPE_BYTE           'y'
#define TYPE_BOOL           'b'
#define TYPE_INT16          'n'
#define TYPE_UINT16         'q'
#define TYPE_INT32          'i'
#define TYPE_UINT32         'u'
#define TYPE_INT64          'x'
#define TYPE_UINT64         't'
#define TYPE_DOUBLE         'd'
#define TYPE_STRING         's'
#define TYPE_PATH           'o'
#define TYPE_SIGNATURE      'g'
#define TYPE_VARIANT        'v'
#define TYPE_ARRAY          'a'
#define TYPE_STRUCT_BEGIN   '('
#define TYPE_STRUCT_END     ')'
#define TYPE_DICT_BEGIN     '{'
#define TYPE_DICT_END       '}'

#define ALIGN_UINT_DOWN(VAL, BOUNDARY) (            \
        (       (unsigned)(VAL)                 )   \
    &   (~(     (((unsigned)(BOUNDARY)) - 1)    ))  \
)

#define ALIGN_UINT_UP(VAL, BOUNDARY) (                          \
        ( ((unsigned)(VAL)) + ((unsigned)(BOUNDARY)) - 1 )      \
    &   (~(     (((unsigned)(BOUNDARY)) - 1)    ))              \
)

#define ALIGN_PTR_UP(TYPE, PTR, BOUNDARY) ((TYPE)(              \
        ( ((uintptr_t)(PTR)) + ((uintptr_t)(BOUNDARY)) - 1 )    \
    &   (~(     (((uintptr_t)(BOUNDARY)) - 1)    ))             \
))

struct parser {
    const char *n;
    const char *e;
};

struct string {
    const char *p;
    unsigned len;
};

struct variant {
    const char *sig;
    struct parser *data;
};

union variant_data {
    bool            b;
    uint8_t         u8;
    int16_t         i16;
    uint16_t        u16;
    int32_t         i32;
    uint32_t        u32;
    int64_t         i64;
    uint64_t        u64;
    double          d;
    struct string   str;
    struct parser   array;
    struct variant  variant;
    struct parser   struct_data;
};

extern const char null_string_bytes[];
extern struct string null_string;
#define INIT_STRING {null_string_bytes,0}

static inline void init_parser(struct parser *p, const char *data, unsigned len) {
    p->n = data;
    p->e = data + len;
}

static inline size_t parser_len(struct parser *p) {
    return p->e - p->n;
}

int parse_byte(struct parser *p, uint8_t *pv);
int parse_bool(struct parser *p, bool *pv);
int parse_uint16(struct parser *p, uint16_t *pv);
int parse_uint32(struct parser *p, uint32_t *pv);
int parse_uint64(struct parser *p, uint64_t *pv);
int parse_string(struct parser *p, struct string *pv);
int parse_path(struct parser *p, struct string *pv);
int parse_signature(struct parser *p, struct string *pv);
int parse_variant(struct parser *p, struct parser *pdata, struct string *psig);
int parse_array(struct parser *p, struct parser *pdata, const char *sig);

int skip_signature(const char **psig);
int skip_value(struct parser *p, const char **psig);

union parser_union {
};

static inline int parse_int16(struct parser *p, int16_t *pv) {
    union parser_union u;
    int sts = parse_uint16(p, &u.u16);
    *pv = u.i16;
    return sts;
}

static inline int parse_int32(struct parser *p, int32_t *pv) {
    union parser_union u;
    int sts = parse_uint32(p, &u.u32);
    *pv = u.i32;
    return sts;
}

static inline int parse_int64(struct parser *p, int64_t *pv) {
    union parser_union u;
    int sts = parse_uint64(p, &u.u64);
    *pv = u.i64;
    return sts;
}

static inline int parse_double(struct parser *p, double *pv) {
    union parser_union u;
    int sts = parse_uint64(p, &u.u64);
    *pv = u.d;
    return sts;
}

static inline int parse_struct_begin(struct parser *p) {
    p->n = ALIGN_PTR_UP(const char*, p->n, 8);
    return p->n > p->e;
}