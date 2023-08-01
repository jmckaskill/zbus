#pragma once
#include <string.h>
#include <stdbool.h>

// #define S(X) cstr_slice(X)
#define S(X) ((struct slice){ (X), sizeof(X) - 1 })

struct slice {
	const char *p;
	size_t len;
};
typedef struct slice slice_t;

static slice_t empty_slice(void);
static slice_t cstr_slice(const char *str);
static slice_t make_slice(const char *str, size_t len);
static int slice_eq(slice_t a, slice_t b);
static bool slice_has_prefix(slice_t s, slice_t pfx);
static bool slice_has_suffix(slice_t s, slice_t sfx);
extern int split_slice(slice_t src, char sep, slice_t *pleft, slice_t *prest);

#define to_slice(X) make_slice((X).p, (X).len)

/////////////////////////
// inline implementations

static inline slice_t empty_slice(void)
{
	slice_t ret;
	ret.p = "";
	ret.len = 0;
	return ret;
}

static inline slice_t cstr_slice(const char *str)
{
	slice_t ret;
	ret.p = str;
	ret.len = strlen(str);
	return ret;
}

static inline slice_t make_slice(const char *str, size_t sz)
{
	slice_t ret = { str, sz };
	return ret;
}

static inline int slice_eq(slice_t a, slice_t b)
{
	return a.len == b.len && !memcmp(a.p, b.p, a.len);
}

static inline bool slice_has_prefix(slice_t s, slice_t pfx)
{
	return s.len >= pfx.len && !memcmp(s.p, pfx.p, pfx.len);
}

static inline bool slice_has_suffix(slice_t s, slice_t sfx)
{
	return s.len >= sfx.len &&
	       !memcmp(s.p + s.len - sfx.len, sfx.p, sfx.len);
}
