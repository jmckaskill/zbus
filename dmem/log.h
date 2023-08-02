#pragma once
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

enum log_level {
	LOG_FATAL = 0, // equivalent to syslog emergency/panic - always sent,
		       // aborts program on finish_log
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
	LOG_SYSLOG,
};

extern int log_verbose_flag;
extern int log_quiet_flag;

int setup_log(enum log_type type, int fd, const char *arg0);
int start_log2(enum log_level lvl, const char *msg, size_t mlen);
int flog(enum log_level lvl, const char *fmt, ...)
	__attribute__((format(gnu_printf, 2, 3)));
int finish_log(void);

int log_args(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
int log_vargs(const char *fmt, va_list ap)
	__attribute__((format(gnu_printf, 1, 0)));
void log_errno_2(const char *key, size_t klen);
void log_bool_2(const char *key, size_t klen, bool val);
void log_cstring_2(const char *key, size_t klen, const char *str);
void log_nstring_2(const char *key, size_t klen, int len, const char *str);
void log_bytes_2(const char *key, size_t klen, const void *data, size_t sz);
void log_uint_2(const char *key, size_t klen, unsigned val);
void log_int_2(const char *key, size_t klen, int val);
void log_hex_2(const char *key, size_t klen, unsigned val);
void log_uint64_2(const char *key, size_t klen, uint64_t val);
void log_int64_2(const char *key, size_t klen, int64_t val);

static inline int start_log(enum log_level lvl, const char *msg)
{
	return start_log2(lvl, msg, strlen(msg));
}

static inline void log_errno(const char *key)
{
	log_errno_2(key, strlen(key));
}
static inline void log_bool(const char *key, bool val)
{
	log_bool_2(key, strlen(key), val);
}
static inline void log_cstring(const char *key, const char *str)
{
	log_cstring_2(key, strlen(key), str);
}
static inline void log_nstring(const char *key, int len, const char *str)
{
	log_nstring_2(key, strlen(key), len, str);
}
static inline void log_bytes(const char *key, const void *data, size_t sz)
{
	log_bytes_2(key, strlen(key), data, sz);
}
static inline void log_uint(const char *key, unsigned val)
{
	log_uint_2(key, strlen(key), val);
}
static inline void log_int(const char *key, int val)
{
	log_int_2(key, strlen(key), val);
}
static inline void log_hex(const char *key, unsigned val)
{
	log_hex_2(key, strlen(key), val);
}
static inline void log_uint64(const char *key, uint64_t val)
{
	log_uint64_2(key, strlen(key), val);
}
static inline void log_int64(const char *key, int64_t val)
{
	log_int64_2(key, strlen(key), val);
}

#define FATAL(...) flog(LOG_FATAL, __VA_ARGS__)
#define ERROR(...) flog(LOG_ERROR, __VA_ARGS__)
#define WARN(...) flog(LOG_WARNING, __VA_ARGS__)
#define NOTICE(...) (void)(log_quiet_flag || flog(LOG_NOTICE, __VA_ARGS__))
#define VERBOSE(...) (void)(log_verbose_flag && flog(LOG_VERBOSE, __VA_ARGS__))
#define start_verbose(MSG) (log_verbose_flag && start_log(LOG_VERBOSE, MSG))

#ifdef NDEBUG
#define DEBUG(...) (0)
#define start_debug(MSG) (0)
#else
#define DEBUG(...) (void)(log_verbose_flag && flog(LOG_DEBUG, __VA_ARGS__))
#define start_debug(MSG) (log_verbose_flag && start_log(LOG_DEBUG, MSG))
#endif