#include "ini.h"

static bool is_space(char ch)
{
	return ch == ' ' || ch == '\t' || ch == '\r';
}

static char *trim_left_space(char *b, char *e)
{
	while (b < e && is_space(b[0])) {
		b++;
	}
	return b;
}

static char *trim_right_space(char *b, char *e)
{
	while (b < e && is_space(e[-1])) {
		e--;
	}
	return e;
}

static char *trim_left_dots(char *b, char *e)
{
	while (b < e && *b == '.') {
		b++;
	}
	return b;
}

static char *trim_right_dots(char *b, char *e)
{
	while (b < e && e[-1] == '.') {
		e--;
	}
	return e;
}

static char *find_line(char *p, char *e, char **pnl)
{
	while (p < e) {
		switch (*p++) {
		case '\n':
			*pnl = p - 1;
			return p;
		case ';':
		case '#':
			*pnl = p - 1;
			char *nl = memchr(p, '\n', e - p);
			return nl ? (nl + 1) : e;
		case '\0':
			return NULL;
		}
	}
	*pnl = e;
	return p;
}

void init_ini(struct ini_reader *p, char *data, size_t sz)
{
	p->data = data;
	p->end = data + sz;
	p->lineno = 0;
	p->section = NULL;
	p->seclen = 0;
}

int read_ini(struct ini_reader *p, char *key, size_t *pksz, char **pval)
{
	while (p->data < p->end) {
		char *e;
		char *s = p->data;
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
			char *close = memchr(s, ']', e - s);
			if (!close) {
				return INI_ERROR;
			}
			s++;
			e = close;
			s = trim_left_space(s, e);
			e = trim_right_space(s, e);
			s = trim_left_dots(s, e);
			e = trim_right_dots(s, e);
			p->section = s;
			p->seclen = e - s;
			continue;
		} else {
			char *equals = memchr(s, '=', e - s);
			if (!equals) {
				return INI_ERROR;
			}
			char *ks = s;
			char *ke = trim_right_space(ks, equals);
			size_t kn = ke - ks;
			char *vs = trim_left_space(equals + 1, e);
			char *ve = e;
			if (!kn || p->seclen + 1 + kn + 1 > *pksz) {
				return INI_ERROR;
			}

			if (p->seclen) {
				memcpy(key, p->section, p->seclen);
				key[p->seclen] = '.';
				memcpy(key + p->seclen + 1, ks, kn);
				key[p->seclen + 1 + kn] = 0;
				*pksz = p->seclen + 1 + kn;
			} else {
				memcpy(key, ks, kn);
				key[kn] = 0;
				*pksz = kn;
			}

			*pval = vs;
			*ve = 0;

			return INI_OK;
		}
	}

	return INI_EOF;
}
