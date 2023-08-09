#define _GNU_SOURCE
#include "config.h"
#include "lib/log.h"
#include <fcntl.h>
#include <unistd.h>

static bool is_space(char ch)
{
	return ch == ' ' || ch == '\t' || ch == '\r';
}

static const char *trim_left_space(const char *b, const char *e)
{
	while (b < e && is_space(b[0])) {
		b++;
	}
	return b;
}

static const char *trim_right_space(const char *b, const char *e)
{
	while (b < e && is_space(e[-1])) {
		e--;
	}
	return e;
}

static const char *trim_left_dots(const char *b, const char *e)
{
	while (b < e && *b == '.') {
		b++;
	}
	return b;
}

static const char *trim_right_dots(const char *b, const char *e)
{
	while (b < e && e[-1] == '.') {
		e--;
	}
	return e;
}

static const char *find_line(const char *p, const char *e, const char **pnl)
{
	while (p < e) {
		switch (*p++) {
		case '\n':
			*pnl = p - 1;
			return p;
		case ';':
		case '#':
			*pnl = p - 1;
			const char *nl = memchr(p, '\n', e - p);
			return nl ? (nl + 1) : e;
		case '\0':
			return NULL;
		}
	}
	*pnl = e;
	return p;
}

void init_ini(struct ini_reader *p, const char *data, size_t sz)
{
	p->data = data;
	p->end = data + sz;
	p->lineno = 0;
	p->section = NULL;
	p->seclen = 0;
}

int read_ini(struct ini_reader *p, char *key, char *val)
{
	while (p->data < p->end) {
		const char *e;
		const char *s = p->data;
		p->data = find_line(s, p->end, &e);
		if (!p->data) {
			return INI_ERROR;
		}

		p->lineno++;
		s = trim_left_space(s, e);
		e = trim_right_space(s, e);

		if (s == e) {
			continue;
		} else if (*s == '[') {
			const char *close = memchr(s, ']', e - s);
			if (!close) {
				return INI_ERROR;
			}
			s++;
			e = close;
			s = trim_left_space(s, e);
			e = trim_right_space(s, e);
			s = trim_left_dots(s, e);
			e = trim_right_dots(s, e);
			p->seclen = 0;
			size_t n = e - s;
			if (n == 0 || n > INI_BUFLEN - 16) {
				return INI_ERROR;
			}
			p->section = s;
			p->seclen = n;
			continue;
		} else {
			const char *equals = memchr(s, '=', e - s);
			if (!equals) {
				return INI_ERROR;
			}
			const char *ks = s;
			const char *ke = trim_right_space(ks, equals);
			size_t kn = ke - ks;
			const char *vs = trim_left_space(equals + 1, e);
			const char *ve = e;
			size_t vn = ve - vs;
			if (!kn || p->seclen + 1 + kn + 1 > INI_BUFLEN ||
			    vn + 1 > INI_BUFLEN) {
				return INI_ERROR;
			}

			if (p->seclen) {
				memcpy(key, p->section, p->seclen);
				key[p->seclen] = '.';
				memcpy(key + p->seclen + 1, ks, kn);
				key[p->seclen + 1 + kn] = 0;
			} else {
				memcpy(key, ks, kn);
				key[kn] = 0;
			}

			memcpy(val, vs, vn);
			val[vn] = 0;

			return INI_OK;
		}
	}

	return INI_EOF;
}
