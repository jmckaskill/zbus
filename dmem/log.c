#define _POSIX_C_SOURCE 199309L
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

enum log_type log_type = LOG_TEXT;
int log_verbose_flag = 0;
int log_quiet_flag = 0;
int log_fd = 2;
const char *log_arg0;

static mtx_t log_mutex;
static char logbuf[512];
static int logoff;
static int logabort;
static char syshost[256];

#ifndef NDEBUG
static bool log_is_setup;
#endif

int setup_log(void)
{
	if (mtx_init(&log_mutex, mtx_plain) != thrd_success) {
		return -1;
	}
	if (log_type == LOG_SYSLOG && gethostname(syshost, sizeof(syshost))) {
		return -1;
	}
	syshost[sizeof(syshost) - 1] = 0;
#ifndef NDEBUG
	log_is_setup = true;
#endif
	return 0;
}

#define YELLOW "\033[33m"
#define RED "\033[31m"
#define CLEAR "\033[0m"

static const char *prefix[] = {
	[(LOG_JSON * LOG_LEVELS) + LOG_DEBUG] =
		"{\"level\":\"debug\",\"timestamp\":\"",
	[(LOG_JSON * LOG_LEVELS) + LOG_VERBOSE] =
		"{\"level\":\"info\",\"timestamp\":\"",
	[(LOG_JSON * LOG_LEVELS) + LOG_NOTICE] =
		"{\"level\":\"notice\",\"timestamp\":\"",
	[(LOG_JSON * LOG_LEVELS) + LOG_WARNING] =
		"{\"level\":\"warning\",\"timestamp\":\"",
	[(LOG_JSON * LOG_LEVELS) + LOG_ERROR] =
		"{\"level\":\"error\",\"timestamp\":\"",
	[(LOG_JSON * LOG_LEVELS) + LOG_ABORT] =
		"{\"level\":\"emergency\",\"timestamp\":\"",
	[(LOG_SYSLOG * LOG_LEVELS) + LOG_DEBUG] = "<7>",
	[(LOG_SYSLOG * LOG_LEVELS) + LOG_VERBOSE] = "<6>",
	[(LOG_SYSLOG * LOG_LEVELS) + LOG_NOTICE] = "<5>",
	[(LOG_SYSLOG * LOG_LEVELS) + LOG_WARNING] = "<4>",
	[(LOG_SYSLOG * LOG_LEVELS) + LOG_ERROR] = "<3>",
	[(LOG_SYSLOG * LOG_LEVELS) + LOG_ABORT] = "<0>",
	[(LOG_TEXT * LOG_LEVELS) + LOG_DEBUG] = "DBG ",
	[(LOG_TEXT * LOG_LEVELS) + LOG_VERBOSE] = "",
	[(LOG_TEXT * LOG_LEVELS) + LOG_NOTICE] = "",
	[(LOG_TEXT * LOG_LEVELS) + LOG_WARNING] = YELLOW "WARN ",
	[(LOG_TEXT * LOG_LEVELS) + LOG_ERROR] = RED "ERROR ",
	[(LOG_TEXT * LOG_LEVELS) + LOG_ABORT] = RED "FATAL ",
};

#define MSG_KEY_SYSLOG "]: {\"msg\":\""
#define MSG_KEY_JSON "\",\"message\":\""
#define MSG_KEY_TEXT " "
#define ERR_SEP_JSON "\",\"syserror\":\"\""
#define ERR_SEP_TEXT ": "
#define FIELD_KEY_JSON ",\""
#define FIELD_KEY_TEXT "\n\t"
#define FIELD_STR_JSON "\":\""
#define FIELD_NUM_JSON "\":"
#define STR_END_JSON "\""
#define STR_END_TEXT ""
#define SUFFIX_JSON "}\n"
#define SUFFIX_TEXT ("\n" CLEAR)
#define ENCODE_INT32_LEN 11 // -2147483648
#define ENCODE_CHAR_LEN 6 // \u1234
#define FIELD_KEY_PAD (strlen(FIELD_KEY_TEXT) + 12 + 1)

#define MSG_KEY ((log_type == LOG_TEXT) ? MSG_KEY_TEXT : MSG_KEY_JSON)
#define ERR_SEP ((log_type == LOG_TEXT) ? ERR_SEP_TEXT : ERR_SEP_JSON)
#define STR_END ((log_type == LOG_TEXT) ? STR_END_TEXT : STR_END_JSON)
#define SUFFIX ((log_type == LOG_TEXT) ? SUFFIX_TEXT : SUFFIX_JSON)
#define FIELD_KEY ((log_type == LOG_TEXT) ? FIELD_KEY_TEXT : FIELD_KEY_JSON)

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MAX3(a, b, c) MAX(MAX(a, b), c)
#define MAX4(a, b, c, d) MAX(MAX3(a, b, c), d)
#define MAX5(a, b, c, d, e) MAX(MAX4(a, b, c, d), e)

// anywhere in a string
#define STRING_TAIL ENCODE_CHAR_LEN

// after the key in a number field
#define NUM_FIELD_TAIL \
	MAX(FIELD_KEY_PAD, strlen(FIELD_NUM_JSON)) + ENCODE_INT32_LEN

// after the key in a string field
#define STR_FIELD_TAIL MAX(FIELD_KEY_PAD, strlen(FIELD_STR_JSON))

// after the msg field in the header
#define HDR_TAIL MAX(strlen(ERR_SEP_JSON), strlen(ERR_SEP_TEXT))

// after the arg0 field in the syslog header
#define HDR_TAG_TAIL (1 /*[*/ + ENCODE_INT32_LEN + strlen(MSG_KEY_SYSLOG))

// Longest fixed string which goes after a variable length before the next
// variable length. We reserve this much in the buffer when writing variable
// length items.
#define MAX_TAIL                                                    \
	MAX5(STRING_TAIL, NUM_FIELD_TAIL, STR_FIELD_TAIL, HDR_TAIL, \
	     HDR_TAG_TAIL)

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

static const char hexdigit[] = "0123456789abcdef";

// leave enough room for \u1234

static void write_char(char ch)
{
	if (logoff + MAX_TAIL > sizeof(logbuf)) {
		write(log_fd, logbuf, logoff);
		logoff = 0;
	}

	unsigned char u = (unsigned char)ch;
	signed char s = (signed char)ch;
	int esc = s > 0 ? escapes[s] : 0;
	if (!esc) {
		logbuf[logoff++] = ch;
	} else if (esc > 1) {
		logbuf[logoff++] = '\\';
		logbuf[logoff++] = esc;
	} else if (log_type == LOG_JSON) {
		logbuf[logoff++] = '\\';
		logbuf[logoff++] = 'u';
		logbuf[logoff++] = '0';
		logbuf[logoff++] = '0';
		logbuf[logoff++] = hexdigit[u >> 4];
		logbuf[logoff++] = hexdigit[u & 15];
	} else {
		logbuf[logoff++] = '\\';
		logbuf[logoff++] = 'x';
		logbuf[logoff++] = hexdigit[u >> 4];
		logbuf[logoff++] = hexdigit[u & 15];
	}
}

static void write_string(const char *str)
{
	while (*str) {
		write_char(*(str++));
	}
}

static void write_slice(const char *str, int len)
{
	for (int i = 0; i < len; i++) {
		write_char(str[i]);
	}
}

static void append_number(int32_t num)
{
	char buf[ENCODE_INT32_LEN];
	char *p = buf + sizeof(buf);
	int sign = 0;
	if (num < 0) {
		sign = 1;
		num = -num;
	}
	while (num) {
		*--p = '0' + (num % 10);
		num /= 10;
	}
	if (sign) {
		*--p = '-';
	}
	assert(logoff + ENCODE_INT32_LEN <= sizeof(logbuf));
	size_t len = buf + sizeof(buf) - p;
	memcpy(logbuf + logoff, p, len);
	logoff += len;
}

static void append_padded(int num, int len)
{
	assert(logoff + len <= sizeof(logbuf));
	for (int i = len - 1; i >= 0; i--) {
		logbuf[logoff + i] = (num % 10) + '0';
		num /= 10;
	}
	logoff += len;
}

static inline void append(const char *str)
{
	int len = strlen(str);
	assert(logoff + len <= sizeof(logbuf));
	memcpy(logbuf + logoff, str, len);
	logoff += len;
}

static inline void pad_key(int start, const char *js)
{
	if (log_type == LOG_TEXT) {
		do {
			logbuf[logoff++] = ' ';
		} while (logoff < start + FIELD_KEY_PAD);
	} else {
		append(js);
	}
}

int start_log(enum log_level lvl, const char *msg, int err)
{
	assert(log_is_setup);
	switch (lvl) {
	case LOG_NOTICE:
		if (log_quiet_flag) {
			return 0;
		}
		break;
	case LOG_WARNING:
	case LOG_ERROR:
	case LOG_ABORT:
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
		break;
	default:
		assert(0);
	}

	mtx_lock(&log_mutex);

	logabort = (lvl == LOG_ABORT);
	append(prefix[(log_type * LOG_LEVELS) + lvl]);

	struct timespec ts;
	struct tm tm;
	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		ts.tv_sec = 0;
		ts.tv_nsec = 0;
	}

	switch (log_type) {
	case LOG_TEXT:
		if (localtime_r(&ts.tv_sec, &tm)) {
			append_padded(tm.tm_hour, 2);
			logbuf[logoff++] = ':';
			append_padded(tm.tm_min, 2);
			logbuf[logoff++] = ':';
			append_padded(tm.tm_sec, 2);
			logbuf[logoff++] = '.';
			append_padded(ts.tv_nsec / 1000000, 3);
		}
		append(MSG_KEY_TEXT);
		break;
	case LOG_SYSLOG:
		if (localtime_r(&ts.tv_sec, &tm)) {
			static const char months[12][5] = {
				"Jan ", "Feb ", "Mar ", "Apr ", "May ", "Jun ",
				"Jul ", "Aug ", "Sep ", "Oct ", "Nov ", "Dec ",
			};
			append(months[tm.tm_mon]);
			append_padded(tm.tm_mday, 2);
			logbuf[logoff++] = ' ';
			append_padded(tm.tm_hour, 2);
			logbuf[logoff++] = ':';
			append_padded(tm.tm_min, 2);
			logbuf[logoff++] = ':';
			append_padded(tm.tm_sec, 2);
			logbuf[logoff++] = ' ';
			write_string(syshost);
			logbuf[logoff++] = ' ';
		}
		if (log_arg0) {
			write_string(log_arg0);
		}
		logbuf[logoff++] = '[';
		append_number(getpid());
		append(MSG_KEY_SYSLOG);
		break;
	case LOG_JSON:
		if (gmtime_r(&ts.tv_sec, &tm)) {
			append_padded(tm.tm_year + 1900, 4);
			logbuf[logoff++] = '-';
			append_padded(tm.tm_mon + 1, 2);
			logbuf[logoff++] = '-';
			append_padded(tm.tm_mday, 2);
			logbuf[logoff++] = 'T';
			append_padded(tm.tm_hour, 2);
			logbuf[logoff++] = ':';
			append_padded(tm.tm_min, 2);
			logbuf[logoff++] = ':';
			append_padded(tm.tm_sec, 2);
			logbuf[logoff++] = '.';
			append_padded(ts.tv_nsec / 1000000, 3);
			logbuf[logoff++] = 'Z';
		}
		append(MSG_KEY_JSON);
		break;
	}

	write_string(msg);
	if (err) {
		append(ERR_SEP);
		write_string(strerror(err));
	}
	append(STR_END);
	return 1;
}

int finish_log(void)
{
	append(SUFFIX);
	write(log_fd, logbuf, logoff);
	logoff = 0;
	if (logabort) {
		abort();
	}
	mtx_unlock(&log_mutex);
	return 0;
}

void log_cstring(const char *key, const char *str)
{
	int start = logoff;
	append(FIELD_KEY);
	write_string(key);
	pad_key(start, FIELD_STR_JSON);
	write_string(str ? str : "(null)");
	append(STR_END);
}

void log_nstring(const char *key, const char *str, size_t len)
{
	int start = logoff;
	append(FIELD_KEY);
	write_string(key);
	pad_key(start, FIELD_STR_JSON);
	write_slice(str, len);
	append(STR_END);
}

void log_number(const char *key, int number)
{
	int start = logoff;
	append(FIELD_KEY);
	write_string(key);
	pad_key(start, FIELD_NUM_JSON);
	append_number(number);
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

static void write_base64(const uint8_t *data, size_t sz)
{
	size_t i;
	for (i = 0; i + 3 <= sz; i += 3) {
		if (logoff + 4 + 4 + MAX_TAIL > sizeof(logbuf)) {
			write(log_fd, logbuf, logoff);
			logoff = 0;
		}
		to_base64(logbuf + logoff, data + i);
		logoff += 4;
	}
	switch (sz - i) {
	case 2: {
		uint8_t pad[3];
		pad[0] = data[i];
		pad[1] = data[i + 1];
		pad[2] = 0;
		to_base64(logbuf + logoff, pad);
		logbuf[logoff + 3] = '=';
		logoff += 4;
		break;
	}
	case 1: {
		uint8_t pad[3];
		pad[0] = data[i];
		pad[1] = 0;
		pad[2] = 0;
		to_base64(logbuf + logoff, pad);
		logbuf[logoff + 2] = '=';
		logbuf[logoff + 3] = '=';
		logoff += 4;
		break;
	}
	}
}

static void log_json_data(const char *key, const uint8_t *data, size_t sz)
{
	append(FIELD_KEY_JSON);
	write_string(key);
	append(FIELD_STR_JSON);
	write_base64(data, sz);
	append(STR_END_JSON);
}

static char ascii(unsigned char ch)
{
	return (' ' <= ch && ch <= '~') ? ch : '.';
}

static void log_text_data(const char *key, const uint8_t *data, size_t sz)
{
	size_t i = 0;
	for (;;) {
		append(FIELD_KEY_TEXT);
		write_string(key);

		if (logoff + 6 + (8 * 2) + 1 + 8 + MAX_TAIL > sizeof(logbuf)) {
			write(log_fd, logbuf, logoff);
			logoff = 0;
		}

		size_t n = MIN(sz - i, 8);

		logbuf[logoff++] = '\t';
		logbuf[logoff++] = hexdigit[(i >> 12) & 15];
		logbuf[logoff++] = hexdigit[(i >> 8) & 15];
		logbuf[logoff++] = hexdigit[(i >> 4) & 15];
		logbuf[logoff++] = hexdigit[i & 15];
		logbuf[logoff++] = ' ';

		for (size_t j = 0; j < n; j++) {
			logbuf[logoff++] = hexdigit[data[i + j] >> 4];
			logbuf[logoff++] = hexdigit[data[i + j] & 15];
		}
		for (size_t j = n; j < 8; j++) {
			logbuf[logoff++] = ' ';
			logbuf[logoff++] = ' ';
		}
		logbuf[logoff++] = ' ';

		for (size_t j = 0; j < n; j++) {
			logbuf[logoff++] = ascii(data[i + j]);
		}

		i += 8;
		if (i >= sz) {
			break;
		}
	}
}

void log_data(const char *key, const void *data, size_t sz)
{
	if (log_type == LOG_TEXT) {
		log_text_data(key, data, sz);
	} else {
		log_json_data(key, data, sz);
	}
}
