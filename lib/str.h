#pragma once
#include <assert.h>
#include <string.h>

#define STRLEN(x) (sizeof(x) - 1)

struct str {
	char *p;
	unsigned cap;
	unsigned len;
};
typedef struct str str_t;

struct slice {
	const char *p;
	unsigned len;
};
typedef struct slice slice_t;

static inline str_t make_str(char *buf, unsigned bufsz)
{
	str_t s;
	s.p = buf;
	s.cap = bufsz;
	s.len = 0;
	buf[0] = 0;
	return s;
}

#define MAKE_STR(BUF) make_str((BUF), sizeof(BUF))

static inline void str_trunc(str_t *s, unsigned len)
{
	assert(len < s->cap);
	s->p[len] = 0;
	s->len = len;
}

int str_cat2(str_t *s, const char *src, unsigned n);
int str_catf(str_t *s, const char *fmt, ...);

static inline int str_cat(str_t *s, const char *src)
{
	return str_cat2(s, src, strlen(src));
}

static inline int str_cats(str_t *s, slice_t src)
{
	return str_cat2(s, src.p, src.len);
}

#define STR_CAT(P, STRING) str_cat2((P), (STRING), STRLEN(STRING))

static inline slice_t make_slice(const char *str)
{
	slice_t ret;
	ret.p = str;
	ret.len = strlen(str);
	return ret;
}

static inline slice_t make_slice2(const char *str, unsigned sz)
{
	slice_t ret = { str, sz };
	return ret;
}

#define MAKE_SLICE(STR) make_slice2((STR), STRLEN(STR))

static inline int slice_eq(slice_t a, const char *test)
{
	return a.len == strlen(test) && !memcmp(a.p, test, a.len);
}

static inline int slice_eqs(slice_t a, slice_t b)
{
	return a.len == b.len && !memcmp(a.p, b.p, a.len);
}
