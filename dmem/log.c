#define _GNU_SOURCE
#include "log.h"
#include <stdint.h>
#include <threads.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>

int log_verbose_flag = 0;
int log_quiet_flag = 0;
enum log_type log_type = LOG_TEXT;
int log_fd;

#define YELLOW "\033[33m"
#define RED "\033[31m"
#define CLEAR "\033[0m"

static const char *prefix[] = {
	[(LOG_JSON * LOG_LEVELS) + LOG_DEBUG] = "{\"lvl\":\"debug\",\"ts\":\"",
	[(LOG_JSON * LOG_LEVELS) + LOG_VERBOSE] = "{\"lvl\":\"info\",\"ts\":\"",
	[(LOG_JSON * LOG_LEVELS) + LOG_NOTICE] =
		"{\"lvl\":\"notice\",\"ts\":\"",
	[(LOG_JSON * LOG_LEVELS) + LOG_WARNING] =
		"{\"lvl\":\"warning\",\"ts\":\"",
	[(LOG_JSON * LOG_LEVELS) + LOG_ERROR] = "{\"lvl\":\"error\",\"ts\":\"",
	[(LOG_JSON * LOG_LEVELS) + LOG_FATAL] = "{\"lvl\":\"fatal\",\"ts\":\"",
	[(LOG_TEXT * LOG_LEVELS) + LOG_DEBUG] = "DBG ",
	[(LOG_TEXT * LOG_LEVELS) + LOG_VERBOSE] = "",
	[(LOG_TEXT * LOG_LEVELS) + LOG_NOTICE] = "",
	[(LOG_TEXT * LOG_LEVELS) + LOG_WARNING] = YELLOW "WARN ",
	[(LOG_TEXT * LOG_LEVELS) + LOG_ERROR] = RED "ERROR ",
	[(LOG_TEXT * LOG_LEVELS) + LOG_FATAL] = RED "FATAL ",
};

#define MSG_KEY_SYSLOG "]: {\"msg\":\""
#define MSG_KEY_JSON "\",\"message\":\""
#define MSG_KEY_TEXT " "
#define FIELD_KEY_JSON ",\""
#define FIELD_KEY_TEXT "\n\t"
#define FIELD_STR_JSON "\":\""
#define FIELD_STR_TEXT "\t\t"
#define FIELD_NUM_JSON "\":"
#define FIELD_NUM_TEXT "\t\t"
#define STR_END_JSON "\""
#define STR_END_TEXT ""
#define SUFFIX_JSON "}\n"
#define SUFFIX_TEXT ("\n" CLEAR)
#define ENCODE_INT32_LEN 11 // -2147483648
#define ENCODE_UINT32_LEN 10 // 4294967295
#define ENCODE_INT64_LEN 20 // -9223372036854775808
#define ENCODE_UINT64_LEN 20 // 18446744073709551615
#define ENCODE_CHAR_LEN 6 // \u1234

// enough for a field open, field seperator, number and closing brace/newline
// if we have this much spare room on top of the key length then we start an
// field entry
#define MIN_FIELD_LEN 32

#define MIN_HEADER_LEN 128

#define MSG_KEY ((log_type == LOG_TEXT) ? MSG_KEY_TEXT : MSG_KEY_JSON)
#define STR_END ((log_type == LOG_TEXT) ? STR_END_TEXT : STR_END_JSON)
#define SUFFIX ((log_type == LOG_TEXT) ? SUFFIX_TEXT : SUFFIX_JSON)
#define FIELD_KEY ((log_type == LOG_TEXT) ? FIELD_KEY_TEXT : FIELD_KEY_JSON)
#define FIELD_STR ((log_type == LOG_TEXT) ? FIELD_STR_TEXT : FIELD_STR_JSON)
#define FIELD_NUM ((log_type == LOG_TEXT) ? FIELD_NUM_TEXT : FIELD_NUM_JSON)

static const char escapes[128] = {
	1,   1,	  1,   1, 1,	1,   1, 1, // 0
	'b', 't', 'n', 1, 'f',	'r', 1, 1, // 8
	1,   1,	  1,   1, 1,	1,   1, 1, // 16
	1,   1,	  1,   1, 1,	1,   1, 1, // 24
	0,   0,	  '"', 0, 0,	0,   0, 0, // 32
	0,   0,	  0,   0, 0,	0,   0, 0, // 40
	0,   0,	  0,   0, 0,	0,   0, 0, // 48
	0,   0,	  0,   0, 0,	0,   0, 0, // 56
	0,   0,	  0,   0, 0,	0,   0, 0, // 64
	0,   0,	  0,   0, 0,	0,   0, 0, // 72
	0,   0,	  0,   0, 0,	0,   0, 0, // 80
	0,   0,	  0,   0, '\\', 0,   0, 0, // 88
	0,   0,	  0,   0, 0,	0,   0, 0, // 96
	0,   0,	  0,   0, 0,	0,   0, 0, // 104
	0,   0,	  0,   0, 0,	0,   0, 0, // 112
	0,   0,	  0,   0, 0,	0,   0, 1, // 120
};

static const char hexdigit[] = "0123456789ABCDEF";

static unsigned write_char(char *buf, unsigned off, char ch)
{
	unsigned char u = (unsigned char)ch;
	signed char s = (signed char)ch;
	int esc = s > 0 ? escapes[s] : 0;
	if (!esc) {
		buf[off++] = ch;
	} else if (esc > 1) {
		buf[off++] = '\\';
		buf[off++] = esc;
	} else if (log_type == LOG_JSON) {
		buf[off++] = '\\';
		buf[off++] = 'u';
		buf[off++] = '0';
		buf[off++] = '0';
		buf[off++] = hexdigit[u >> 4];
		buf[off++] = hexdigit[u & 15];
	} else {
		buf[off++] = '\\';
		buf[off++] = 'x';
		buf[off++] = hexdigit[u >> 4];
		buf[off++] = hexdigit[u & 15];
	}
	return off;
}

static inline int append(char *buf, int off, const char *str, size_t len)
{
	memcpy(buf + off, str, len);
	return off + len;
}

static inline int grow(struct logbuf *b, size_t sz)
{
	if (b->lvl >= LOG_VERBOSE) {
		size_t alloc = b->off + sz;
		if (alloc < b->end * 2) {
			alloc = b->end * 2;
		}
		char *newbuf = realloc(b->buf, alloc);
		if (!newbuf) {
			return -1;
		}
		b->buf = newbuf;
		return 0;
	} else {
		b->off = append(b->buf, b->off, "...", 3);
		finish_log(b);
		return -1;
	}
}

static void write_nstring(struct logbuf *b, const char *str, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (b->off + MIN_FIELD_LEN > b->end && grow(b, MIN_FIELD_LEN)) {
			return;
		}
		b->off = write_char(b->buf, b->off, str[i]);
	}
}

static int append_uint64(char *buf, int off, uint64_t num)
{
	char e[ENCODE_UINT64_LEN];
	char *p = e + sizeof(e);
	do {
		*--p = '0' + (num % 10);
		num /= 10;
	} while (num);
	size_t len = e + sizeof(e) - p;
	return append(buf, off, p, len);
}

static int append_int64(char *buf, int off, int64_t num)
{
	char e[ENCODE_INT64_LEN];
	char *p = e + sizeof(e);
	int sign = 0;
	if (num < 0) {
		sign = 1;
		num = -num;
	}
	do {
		*--p = '0' + (num % 10);
		num /= 10;
	} while (num);
	if (sign) {
		*--p = '-';
	}
	size_t len = e + sizeof(e) - p;
	return append(buf, off, p, len);
}

static int append_padded(char *buf, int off, unsigned num, int len)
{
	for (int i = len - 1; i >= 0; i--) {
		buf[off + i] = (num % 10) + '0';
		num /= 10;
	}
	return off + len;
}

static int append_key(char *buf, int off, const char *key, size_t len,
		      bool is_string)
{
	off = append(buf, off, key, len);
	if (log_type == LOG_TEXT) {
		buf[off++] = (len < 8) ? '\t' : ' ';
	} else {
		buf[off++] = '"';
		buf[off++] = ':';
		if (is_string) {
			buf[off++] = '"';
		}
	}
	return off;
}

int start_log2(struct logbuf *b, char *buf, size_t sz, enum log_level lvl,
	       const char *msg, size_t mlen)
{
	switch (lvl) {
	case LOG_NOTICE:
		if (log_quiet_flag) {
			return 0;
		}
		break;
	case LOG_WARNING:
	case LOG_ERROR:
	case LOG_FATAL:
		break;
	case LOG_DEBUG:
#ifdef NDEBUG
		return 0;
#else
		// fallthrough
#endif
	case LOG_VERBOSE:
		if (!log_verbose_flag) {
			return 0;
		}
		buf = malloc(1024);
		break;
	default:
		assert(0);
	}

	if (sz < MIN_HEADER_LEN) {
		return 0;
	}

	int err = errno;
	int off = 0;
	const char *pfx = prefix[(log_type * LOG_LEVELS) + lvl];
	off = append(buf, off, pfx, strlen(pfx));

	struct timespec ts;
	struct tm tm;
	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		ts.tv_sec = 0;
		ts.tv_nsec = 0;
	}

	switch (log_type) {
	case LOG_TEXT:
		if (localtime_r(&ts.tv_sec, &tm)) {
			off = append_padded(buf, off, tm.tm_hour, 2);
			buf[off++] = ':';
			off = append_padded(buf, off, tm.tm_min, 2);
			buf[off++] = ':';
			off = append_padded(buf, off, tm.tm_sec, 2);
			buf[off++] = '.';
			off = append_padded(buf, off, ts.tv_nsec / 1000000, 3);
		}
		off = append(buf, off, MSG_KEY_TEXT, strlen(MSG_KEY_TEXT));
		break;
	case LOG_JSON:
		if (gmtime_r(&ts.tv_sec, &tm)) {
			off = append_padded(buf, off, tm.tm_year + 1900, 4);
			buf[off++] = '-';
			off = append_padded(buf, off, tm.tm_mon + 1, 2);
			buf[off++] = '-';
			off = append_padded(buf, off, tm.tm_mday, 2);
			buf[off++] = 'T';
			off = append_padded(buf, off, tm.tm_hour, 2);
			buf[off++] = ':';
			off = append_padded(buf, off, tm.tm_min, 2);
			buf[off++] = ':';
			off = append_padded(buf, off, tm.tm_sec, 2);
			buf[off++] = '.';
			off = append_padded(buf, off, ts.tv_nsec / 1000000, 3);
			buf[off++] = 'Z';
		}
		off = append(buf, off, MSG_KEY_JSON, strlen(MSG_KEY_JSON));
		break;
	}

	b->buf = buf;
	b->off = off;
	b->end = sz;
	b->err = err;
	b->lvl = lvl;

	write_nstring(b, msg, mlen);
	b->off = append(b->buf, b->off, STR_END, strlen(STR_END));

	return 1;
}

int finish_log(struct logbuf *b)
{
	if (b->lvl == LOG_FATAL) {
		abort();
	}
	if (!b->buf) {
		return -1;
	}
	b->off = append(b->buf, b->off, SUFFIX, strlen(SUFFIX));
	write(log_fd, b->buf, b->off);
	if (b->lvl >= LOG_VERBOSE) {
		free(b->buf);
	}
	b->buf = NULL;
	b->off = 0;
	b->end = 0;
	return 0;
}

void log_bool_2(struct logbuf *b, const char *key, size_t klen, bool val)
{
	char *buf = b->buf;
	int off = b->off;
	if (off + MIN_FIELD_LEN + klen > b->end &&
	    grow(b, MIN_FIELD_LEN + klen)) {
		return;
	}
	off = append(buf, off, FIELD_KEY, strlen(FIELD_KEY));
	off = append_key(buf, off, key, klen, false);
	if (val) {
		b->off = append(buf, off, "true", 4);
	} else {
		b->off = append(buf, off, "false", 5);
	}
}

void log_errno_2(struct logbuf *b, const char *key, size_t klen)
{
	const char *estr = strerror(b->err);
	int len = strlen(estr);
	log_nstring_2(b, key, klen, len, estr);
}

void log_cstring_2(struct logbuf *b, const char *key, size_t klen,
		   const char *str)
{
	if (b->off + MIN_FIELD_LEN + klen > b->end &&
	    grow(b, MIN_FIELD_LEN + klen)) {
		return;
	}

	b->off = append(b->buf, b->off, FIELD_KEY, strlen(FIELD_KEY));
	b->off = append_key(b->buf, b->off, key, klen, str != NULL);
	if (str) {
		write_nstring(b, str, strlen(str));
		b->off = append(b->buf, b->off, STR_END, strlen(STR_END));
	} else {
		b->off = append(b->buf, b->off, "null", 4);
	}
}

void log_nstring_2(struct logbuf *b, const char *key, size_t klen, int len,
		   const char *str)
{
	char *buf = b->buf;
	int off = b->off;
	if (off + MIN_FIELD_LEN + klen > b->end &&
	    grow(b, MIN_FIELD_LEN + klen)) {
		return;
	}
	off = append(buf, off, FIELD_KEY, strlen(FIELD_KEY));
	off = append_key(buf, off, key, klen, true);
	b->off = off;
	write_nstring(b, str, len);
	b->off = append(buf, b->off, STR_END, strlen(STR_END));
}

void log_int_2(struct logbuf *b, const char *key, size_t klen, int val)
{
	char *buf = b->buf;
	int off = b->off;
	if (off + MIN_FIELD_LEN + klen > b->end &&
	    grow(b, MIN_FIELD_LEN + klen)) {
		return;
	}
	off = append(buf, off, FIELD_KEY, strlen(FIELD_KEY));
	off = append_key(buf, off, key, klen, false);
	b->off = append_int64(buf, off, val);
}

void log_uint_2(struct logbuf *b, const char *key, size_t klen, unsigned val)
{
	char *buf = b->buf;
	int off = b->off;
	if (off + MIN_FIELD_LEN + klen > b->end &&
	    grow(b, MIN_FIELD_LEN + klen)) {
		return;
	}
	off = append(buf, off, FIELD_KEY, strlen(FIELD_KEY));
	off = append_key(buf, off, key, klen, false);
	b->off = append_uint64(buf, off, val);
}

void log_int64_2(struct logbuf *b, const char *key, size_t klen, int64_t val)
{
	char *buf = b->buf;
	int off = b->off;
	if (off + MIN_FIELD_LEN + klen > b->end &&
	    grow(b, MIN_FIELD_LEN + klen)) {
		return;
	}
	off = append(buf, off, FIELD_KEY, strlen(FIELD_KEY));
	off = append_key(buf, off, key, klen, true);
	off = append_int64(buf, off, val);
	b->off = append(buf, off, STR_END, strlen(STR_END));
}

void log_uint64_2(struct logbuf *b, const char *key, size_t klen, uint64_t val)
{
	char *buf = b->buf;
	int off = b->off;
	if (off + MIN_FIELD_LEN + klen > b->end &&
	    grow(b, MIN_FIELD_LEN + klen)) {
		return;
	}
	off = append(buf, off, FIELD_KEY, strlen(FIELD_KEY));
	off = append_key(buf, off, key, klen, true);
	off = append_uint64(buf, off, val);
	b->off = append(buf, off, STR_END, strlen(STR_END));
}

void log_hex_2(struct logbuf *b, const char *key, size_t klen, unsigned val)
{
	if (log_type != LOG_TEXT) {
		log_uint_2(b, key, klen, val);
		return;
	}
	char *buf = b->buf;
	int off = b->off;
	if (off + MIN_FIELD_LEN + klen > b->end &&
	    grow(b, MIN_FIELD_LEN + klen)) {
		return;
	}
	char x[10];
	x[0] = '0';
	x[1] = 'x';
	x[2] = hexdigit[(val >> 28) & 15];
	x[3] = hexdigit[(val >> 24) & 15];
	x[4] = hexdigit[(val >> 20) & 15];
	x[5] = hexdigit[(val >> 16) & 15];
	x[6] = hexdigit[(val >> 12) & 15];
	x[7] = hexdigit[(val >> 8) & 15];
	x[8] = hexdigit[(val >> 4) & 15];
	x[9] = hexdigit[(val >> 0) & 15];
	off = append(buf, off, FIELD_KEY_TEXT, strlen(FIELD_KEY_TEXT));
	off = append_key(buf, off, key, klen, false);
	b->off = append(buf, off, x, 10);
}

static const char b64digits[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void to_base64(char d[4], const uint8_t s[3])
{
	/* Input:  xxxx xxxx yyyy yyyy zzzz zzzz
	 * Output: 00xx xxxx 00xx yyyy 00yy yyzz 00zz zzzz
	 */
	int i0 = ((s[0] >> 2) & 0x3F);

	int i1 = ((s[0] << 4) & 0x30) | ((s[1] >> 4) & 0x0F);

	int i2 = ((s[1] << 2) & 0x3C) | ((s[2] >> 6) & 0x03);

	int i3 = (s[2] & 0x3F);

	d[0] = b64digits[i0];
	d[1] = b64digits[i1];
	d[2] = b64digits[i2];
	d[3] = b64digits[i3];
}

static int write_base64(char *buf, int off, const uint8_t *data, size_t sz)
{
	size_t i;
	for (i = 0; i + 3 <= sz; i += 3) {
		to_base64(buf + off, data + i);
		off += 4;
	}
	switch (sz - i) {
	case 2: {
		uint8_t pad[3];
		pad[0] = data[i];
		pad[1] = data[i + 1];
		pad[2] = 0;
		to_base64(buf + off, pad);
		buf[off + 3] = '=';
		return off + 4;
	}
	case 1: {
		uint8_t pad[3];
		pad[0] = data[i];
		pad[1] = 0;
		pad[2] = 0;
		to_base64(buf + off, pad);
		buf[off + 2] = '=';
		buf[off + 3] = '=';
		return off + 4;
	}
	default:
		return off;
	}
}

static void log_json_bytes(struct logbuf *b, const char *key, size_t klen,
			   const uint8_t *data, size_t sz)
{
	char *buf = b->buf;
	int off = b->off;
	size_t b64bytes = ((sz + 2) / 3) * 4;
	if (off + MIN_FIELD_LEN + klen + b64bytes > b->end &&
	    grow(b, MIN_FIELD_LEN + klen + b64bytes)) {
		return;
	}
	off = append(buf, off, FIELD_KEY_JSON, strlen(FIELD_KEY_JSON));
	off = append(buf, off, key, klen);
	off = append(buf, off, FIELD_STR_JSON, strlen(FIELD_STR_JSON));
	off = write_base64(buf, off, data, sz);
	b->off = append(buf, off, STR_END_JSON, strlen(STR_END_JSON));
}

static char ascii(unsigned char ch)
{
	return (' ' <= ch && ch <= '~') ? ch : '.';
}

static void log_text_bytes(struct logbuf *b, const char *key, size_t klen,
			   const uint8_t *data, size_t sz)
{
	char *buf = b->buf;
	int off = b->off;
	size_t rowb = strlen(FIELD_KEY_TEXT) + klen + 6 + (2 * 8) + 1 + 8;
	size_t rows = ((sz + 7) / 8);
	size_t need = rows * rowb;
	if (off + need > b->end && grow(b, need)) {
		return;
	}

	size_t i = 0;
	for (;;) {
		off = append(buf, off, FIELD_KEY_TEXT, strlen(FIELD_KEY_TEXT));
		off = append(buf, off, key, klen);

		size_t n = sz - i;
		if (n > 8) {
			n = 8;
		}

		buf[off++] = (klen < 8) ? '\t' : ' ';
		buf[off++] = hexdigit[(i >> 12) & 15];
		buf[off++] = hexdigit[(i >> 8) & 15];
		buf[off++] = hexdigit[(i >> 4) & 15];
		buf[off++] = hexdigit[i & 15];
		buf[off++] = ' ';

		for (size_t j = 0; j < n; j++) {
			buf[off++] = hexdigit[data[i + j] >> 4];
			buf[off++] = hexdigit[data[i + j] & 15];
		}
		for (size_t j = n; j < 8; j++) {
			buf[off++] = ' ';
			buf[off++] = ' ';
		}
		buf[off++] = ' ';

		for (size_t j = 0; j < n; j++) {
			buf[off++] = ascii(data[i + j]);
		}

		i += 8;
		if (i >= sz) {
			break;
		}
	}

	b->off = off;
}

void log_bytes_2(struct logbuf *b, const char *key, size_t klen,
		 const void *data, size_t sz)
{
	if (log_type == LOG_TEXT) {
		log_text_bytes(b, key, klen, data, sz);
	} else {
		log_json_bytes(b, key, klen, data, sz);
	}
}

int log_vargs(struct logbuf *b, const char *fmt, va_list ap)
{
	while (*fmt) {
		const char *key = fmt;
		const char *pct = strchr(key, '%');
		if (!pct) {
			goto error;
		}
		size_t klen = pct - key;
		if (klen && key[klen - 1] == ':') {
			klen--;
		}
		fmt = pct + 1;
		switch (*(fmt++)) {
		case '.': {
			if (*(fmt++) != '*' || *(fmt++) != 's') {
				goto error;
			}
			int len = va_arg(ap, int);
			const char *str = va_arg(ap, const char *);
			log_nstring_2(b, key, klen, len, str);
			break;
		}
		case 's':
			// cstring
			log_cstring_2(b, key, klen, va_arg(ap, const char *));
			break;
		case 'd':
		case 'i':
			// int
			log_int_2(b, key, klen, va_arg(ap, int));
			break;
		case 'x':
		case 'X':
			// hex
			log_hex_2(b, key, klen, va_arg(ap, unsigned));
			break;
		case 'u':
			// unsigned
			log_uint_2(b, key, klen, va_arg(ap, unsigned));
			break;
		case 'm':
			// errno
			log_errno_2(b, key, klen);
			break;
		case 'l':
			if (*(fmt++) != 'l') {
				goto error;
			}
			switch (*(fmt++)) {
			case 'u':
				log_uint64_2(b, key, klen,
					     va_arg(ap, uint64_t));
				break;
			case 'd':
			case 'i':
				log_int64_2(b, key, klen, va_arg(ap, int64_t));
				break;
			default:
				goto error;
			}
		default:
			goto error;
		}
		if (*fmt == ',') {
			fmt++;
		}
	}
	return 0;

error:
	assert(0);
	return -1;
}

int log_args(struct logbuf *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	return log_vargs(b, fmt, ap);
}

int flog(enum log_level lvl, const char *fmt, ...)
{
	char buf[256];
	struct logbuf b;
	const char *args = strchrnul(fmt, ',');
	if (!start_log2(&b, buf, sizeof(buf), lvl, fmt, args - fmt)) {
		return 0;
	}
	if (*args == ',') {
		va_list ap;
		va_start(ap, fmt);
		log_vargs(&b, args + 1, ap);
	}
	return finish_log(&b);
}
