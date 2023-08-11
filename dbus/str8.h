#pragma once
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

// Used for a short pascal style string. The first byte being the length and is
// null terminated. When allocating on the heap, allocate sizeof(*s) + len.
// The buffer shouldn't contain embedded nuls, but that is only guaranteed if
// the string has been checked. The buffer must have a terminating nul.
struct str8 {
	uint8_t len;
	char p[1];
};
typedef struct str8 str8_t;

#define S8(STR) (assert((STR)[0] + 2 == sizeof(STR)), (const str8_t *)(STR))
#define S_PRI(X) (int)(X).len, (X).p

static inline int check_str8(const str8_t *s)
{
	return s->p[s->len] || memchr(s->p, 0, s->len);
}

static inline void str8cpy(str8_t *to, const str8_t *from)
{
	memcpy(&to->len, &from->len, from->len + 2);
}

// Works as long as one of the two strings has been checked for no embedded
// nuls.
static inline int str8cmp(const str8_t *a, const str8_t *b)
{
	return strcmp((char *)&a->len, (char *)&b->len);
}

static inline int str8eq(const str8_t *a, const str8_t *b)
{
	return !str8cmp(a, b);
}
