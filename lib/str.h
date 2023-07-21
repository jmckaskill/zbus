#pragma once
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>

struct str {
	char *p;
	int len;
	int cap;
};
typedef struct str str_t;

struct slice {
	const char *p;
	int len;
};
typedef struct slice slice_t;

static str_t make_str(char *buf, int bufsz);
#define MAKE_STR(BUF) make_str((BUF), sizeof(BUF))

extern int str_add(str_t *s, slice_t src);
extern int str_addf(str_t *s, const char *fmt, ...);
extern int str_vaddf(str_t *s, const char *fmt, va_list ap);
static int str_add1(str_t *s, const char *src);
static int str_add2(str_t *s, const char *src, int len);

static int str_copy(char *buf, int bufsz, slice_t s);
static void str_setlen(str_t *s, int len);

static slice_t to_slice(str_t s);
static slice_t make_slice1(const char *str);
static slice_t make_slice2(const char *str, int len);

#define STRLEN(x) (sizeof(x) - 1)
#define S(STR) make_slice2((STR), STRLEN(STR))

static slice_t split_slice(slice_t *pright, int left);
static bool slice_eq(slice_t a, slice_t b);
static bool has_prefix(slice_t s, slice_t pfx);

/////////////////////////////
// Inline implementations

static inline str_t make_str(char *buf, int bufsz)
{
	str_t s;
	s.p = buf;
	s.cap = bufsz;
	str_setlen(&s, 0);
	return s;
}

static inline void str_setlen(str_t *s, int len)
{
	assert(len < s->cap);
	s->p[len] = 0;
	s->len = len;
}

static inline int str_add1(str_t *s, const char *src)
{
	return str_add(s, make_slice1(src));
}

static inline int str_add2(str_t *s, const char *src, int len)
{
	return str_add(s, make_slice2(src, len));
}

static inline int str_copy(char *buf, int bufsz, slice_t s)
{
	str_t str = make_str(buf, bufsz);
	return str_add(&str, s);
}

static inline slice_t to_slice(str_t s)
{
	slice_t ret;
	ret.p = s.p;
	ret.len = s.len;
	return ret;
}

static inline slice_t make_slice1(const char *str)
{
	slice_t ret;
	ret.p = str;
	ret.len = strlen(str);
	return ret;
}

static inline slice_t make_slice2(const char *str, int sz)
{
	slice_t ret = { str, sz };
	return ret;
}

static inline slice_t split_slice(slice_t *pright, int left)
{
	slice_t ret = make_slice2(pright->p, left);
	pright->p += left;
	pright->len -= left;
	return ret;
}

static inline bool slice_eq(slice_t a, slice_t b)
{
	return a.len == b.len && !memcmp(a.p, b.p, a.len);
}

static inline bool has_prefix(slice_t s, slice_t pfx)
{
	return s.len >= pfx.len && !memcmp(s.p, pfx.p, pfx.len);
}
