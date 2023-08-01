#pragma once
#include <stdlib.h>

enum log_level {
	LOG_ABORT = 0, // equivalent to syslog emergency/panic - always sent,
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

extern enum log_type log_type;
extern int log_verbose_flag;
extern int log_quiet_flag;
extern int log_fd;
extern const char *log_arg0;

int setup_log(void);
int start_log(enum log_level lvl, const char *msg, int err);
int finish_log(void);

void log_cstring(const char *key, const char *str);
void log_nstring(const char *key, const char *str, size_t len);
void log_bytes(const char *key, const void *data, size_t sz);
void log_number(const char *key, int number);
void log_data(const char *key, const void *data, size_t sz);

static inline int start_abort(const char *msg, int syserr);
static inline int start_error(const char *msg, int syserr);
static inline int start_warning(const char *msg, int syserr);
static inline int start_notice(const char *msg);
static inline int start_verbose(const char *msg);
static inline int start_debug(const char *msg);

static void write_abort(const char *msg, int syserr);
static void write_error(const char *msg, int syserr);
static void write_warning(const char *msg, int syserr);
static void write_notice(const char *msg);
static void write_verbose(const char *msg);
static void write_debug(const char *msg);

////////////////////////////////
// inline implementations

static inline int start_abort(const char *msg, int syserr)
{
	return start_log(LOG_ABORT, msg, syserr);
}
static inline int start_error(const char *msg, int syserr)
{
	return start_log(LOG_ERROR, msg, syserr);
}
static inline int start_warning(const char *msg, int syserr)
{
	return start_log(LOG_WARNING, msg, syserr);
}
static inline int start_notice(const char *msg)
{
	return log_quiet_flag || start_log(LOG_NOTICE, msg, 0);
}
static inline int start_verbose(const char *msg)
{
	return log_verbose_flag && start_log(LOG_VERBOSE, msg, 0);
}
static inline int start_debug(const char *msg)
{
#ifdef NDEBUG
	return 0;
#else
	return log_verbose_flag && start_log(LOG_DEBUG, msg, 0);
#endif
}

static inline void write_abort(const char *msg, int syserr)
{
	start_log(LOG_ABORT, msg, syserr);
	finish_log();
}
static inline void write_error(const char *msg, int syserr)
{
	start_log(LOG_ERROR, msg, syserr);
	finish_log();
}
static inline void write_warning(const char *msg, int syserr)
{
	start_log(LOG_WARNING, msg, syserr);
	finish_log();
}
static inline void write_notice(const char *msg)
{
	if (!log_quiet_flag) {
		start_log(LOG_NOTICE, msg, 0);
		finish_log();
	}
}
static inline void write_verbose(const char *msg)
{
	if (log_verbose_flag) {
		start_log(LOG_VERBOSE, msg, 0);
		finish_log();
	}
}
static inline void write_debug(const char *msg)
{
#ifndef NDEBUG
	if (log_verbose_flag) {
		start_log(LOG_DEBUG, msg, 0);
		finish_log();
	}
#endif
}
