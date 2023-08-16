#pragma once
#include "types.h"
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

// Used for a short pascal style string. The first byte being the length and is
// null terminated. When allocating on the heap, allocate sizeof(*s) + len.
// The buffer shouldn't contain embedded nuls, but that is only guaranteed if
// the string has been checked. The buffer must have a terminating nul.
struct zb_str8 {
	uint8_t len;
	char p[1];
};
typedef struct zb_str8 zb_str8;

#define S8(STR) (assert((STR)[0] + 2 == sizeof(STR)), (const zb_str8 *)(STR))
#define S_PRI(X) (int)(X).len, (X).p

ZB_INLINE void zb_copy_str8(zb_str8 *to, const zb_str8 *from)
{
	memcpy(&to->len, &from->len, from->len + 2);
}

// Works as long as one of the two strings has been checked for no embedded
// nuls.
ZB_INLINE int zb_cmp_str8(const zb_str8 *a, const zb_str8 *b)
{
	return strcmp((char *)&a->len, (char *)&b->len);
}

ZB_INLINE int zb_eq_str8(const zb_str8 *a, const zb_str8 *b)
{
	return !zb_cmp_str8(a, b);
}
