#pragma once
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

enum log_level {
	LOG_FATAL = 0, // equivalent to syslog emergency/panic - always sent,
	LOG_ERROR = 3, // equivalent to syslog error - always sent
	LOG_WARNING = 4, // equivalent to syslog warning - always sent
	LOG_NOTICE = 5, // equivalent to syslog notice - disabled with quiet
			// flag
	LOG_VERBOSE = 6, // equivalent to syslog info - only enabled with
			 // verbose flag
	LOG_DEBUG = 7, // equivalent to syslog debug - compiled out in release
		       // builds
	LOG_LEVELS = 8,
};

enum log_type {
	LOG_TEXT,
	LOG_JSON,
};

extern int log_verbose_flag;
extern int log_quiet_flag;
extern enum log_type log_type;
extern int log_fd;

struct logbuf {
	char *buf;
	unsigned off, end;
	int err;
	enum log_level lvl;
};

int start_log2(struct logbuf *b, char *buf, size_t sz, enum log_level lvl,
	       const char *msg, size_t mlen);
int flog(enum log_level lvl, const char *fmt, ...)
	__attribute__((format(gnu_printf, 2, 3)));
int finish_log(struct logbuf *b);

int log_args(struct logbuf *b, const char *fmt, ...)
	__attribute__((format(gnu_printf, 2, 3)));
int log_vargs(struct logbuf *b, const char *fmt, va_list ap)
	__attribute__((format(gnu_printf, 2, 0)));
void log_errno_2(struct logbuf *b, const char *key, size_t klen);
void log_bool_2(struct logbuf *b, const char *key, size_t klen, bool val);
void log_cstring_2(struct logbuf *b, const char *key, size_t klen,
		   const char *str);
void log_nstring_2(struct logbuf *b, const char *key, size_t klen, int len,
		   const char *str);
void log_bytes_2(struct logbuf *b, const char *key, size_t klen,
		 const void *data, size_t sz);
void log_uint_2(struct logbuf *b, const char *key, size_t klen, unsigned val);
void log_int_2(struct logbuf *b, const char *key, size_t klen, int val);
void log_hex_2(struct logbuf *b, const char *key, size_t klen, unsigned val);
void log_uint64_2(struct logbuf *b, const char *key, size_t klen, uint64_t val);
void log_int64_2(struct logbuf *b, const char *key, size_t klen, int64_t val);

static inline int start_log(struct logbuf *b, char *buf, size_t sz,
			    enum log_level lvl, const char *msg)
{
	return start_log2(b, buf, sz, lvl, msg, strlen(msg));
}

static inline void log_errno(struct logbuf *b, const char *key)
{
	log_errno_2(b, key, strlen(key));
}
static inline void log_bool(struct logbuf *b, const char *key, bool val)
{
	log_bool_2(b, key, strlen(key), val);
}
static inline void log_cstring(struct logbuf *b, const char *key,
			       const char *str)
{
	log_cstring_2(b, key, strlen(key), str);
}
static inline void log_nstring(struct logbuf *b, const char *key, int len,
			       const char *str)
{
	log_nstring_2(b, key, strlen(key), len, str);
}
static inline void log_bytes(struct logbuf *b, const char *key,
			     const void *data, size_t sz)
{
	log_bytes_2(b, key, strlen(key), data, sz);
}
static inline void log_uint(struct logbuf *b, const char *key, unsigned val)
{
	log_uint_2(b, key, strlen(key), val);
}
static inline void log_int(struct logbuf *b, const char *key, int val)
{
	log_int_2(b, key, strlen(key), val);
}
static inline void log_hex(struct logbuf *b, const char *key, unsigned val)
{
	log_hex_2(b, key, strlen(key), val);
}
static inline void log_uint64(struct logbuf *b, const char *key, uint64_t val)
{
	log_uint64_2(b, key, strlen(key), val);
}
static inline void log_int64(struct logbuf *b, const char *key, int64_t val)
{
	log_int64_2(b, key, strlen(key), val);
}

#define FATAL(...) flog(LOG_FATAL, __VA_ARGS__)
#define ERROR(...) flog(LOG_ERROR, __VA_ARGS__)
#define WARN(...) flog(LOG_WARNING, __VA_ARGS__)
#define NOTICE(...) (void)(log_quiet_flag || flog(LOG_NOTICE, __VA_ARGS__))
#define VERBOSE(...) (void)(log_verbose_flag && flog(LOG_VERBOSE, __VA_ARGS__))
#define start_verbose(B, MSG) \
	(log_verbose_flag && start_log(B, NULL, 0, LOG_VERBOSE, MSG))

#ifdef NDEBUG
#define DEBUG(...) (0)
#define start_debug(B, MSG) (void)(B)
#else
#define DEBUG(...) (void)(log_verbose_flag && flog(LOG_DEBUG, __VA_ARGS__))
#define start_debug(B, MSG) \
	(log_verbose_flag && start_log(B, NULL, 0, LOG_DEBUG, MSG))
#endif