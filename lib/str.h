#pragma once
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>

struct buf {
	char *p;
	int len;
	int cap;
};
typedef struct buf buf_t;

struct slice {
	const char *p;
	int len;
};
typedef struct slice slice_t;

static buf_t make_buf(char *buf, int bufsz);
#define MAKE_BUF(BUF) make_buf((BUF), sizeof(BUF))

static int buf_addch(buf_t *s, char ch);
extern int buf_add(buf_t *s, slice_t src);
extern int buf_addf(buf_t *s, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
extern int buf_vaddf(buf_t *s, const char *fmt, va_list ap);
static int buf_add_cstr(buf_t *s, const char *src);
static int buf_add2(buf_t *s, const char *src, int len);
static int buf_full(buf_t *s);
static char *buf_next(buf_t *s);

static slice_t to_slice(buf_t s);
static slice_t to_right_slice(buf_t s, int len);
static slice_t right_slice(slice_t s, int len);
static slice_t cstr_slice(const char *str);
static slice_t make_slice(const char *str, int len);

#define TO_SLICE(B) make_slice((B).p, (B).len)
#define STRLEN(x) (sizeof(x) - 1)
#define S(STR) make_slice((STR), STRLEN(STR))
#define SLICE_INIT(STR)          \
	{                        \
		STR, STRLEN(STR) \
	}

static bool slice_eq(slice_t a, slice_t b);
static bool has_prefix(slice_t s, slice_t pfx);

/////////////////////////////
// Inline implementations

static inline buf_t make_buf(char *buf, int bufsz)
{
	buf_t s;
	s.p = buf;
	s.cap = bufsz;
	s.len = 0;
	return s;
}

static inline int buf_addch(buf_t *s, char ch)
{
	if (s->len == s->cap) {
		return 1;
	} else {
		s->p[s->len++] = ch;
		return 0;
	}
}

static inline int buf_add_cstr(buf_t *s, const char *src)
{
	return buf_add(s, cstr_slice(src));
}

static inline int buf_add2(buf_t *s, const char *src, int len)
{
	return buf_add(s, make_slice(src, len));
}

static inline int buf_full(buf_t *s)
{
	return s->len == s->cap;
}

static inline char *buf_next(buf_t *s)
{
	return s->p + s->len;
}

static inline slice_t to_slice(buf_t s)
{
	slice_t ret;
	ret.p = s.p;
	ret.len = s.len;
	return ret;
}

static inline slice_t to_right_slice(buf_t s, int len)
{
	slice_t ret;
	ret.p = s.p + s.len - len;
	ret.len = s.len;
	return ret;
}

static inline slice_t right_slice(slice_t s, int len)
{
	slice_t ret;
	ret.p = s.p + s.len - len;
	ret.len = len;
	return ret;
}

static inline slice_t cstr_slice(const char *str)
{
	slice_t ret;
	ret.p = str;
	ret.len = strlen(str);
	return ret;
}

static inline slice_t make_slice(const char *str, int sz)
{
	slice_t ret = { str, sz };
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
