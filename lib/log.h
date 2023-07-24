#pragma once
#include "str.h"
#include <stdlib.h>
#include <stdarg.h>

enum log_level {
	log_error,
	log_info,
	log_debug,
};

extern int log_verbose;
extern int log_quiet;

void log_vfmt(enum log_level lvl, const char *fmt, va_list ap);
int log_fmt(enum log_level lvl, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
int log_data(slice_t s, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#define ELOG(...) log_fmt(log_error, __VA_ARGS__)
#define ILOG(...) ((void)(log_quiet || log_fmt(log_info, __VA_ARGS__)))
#define DLOG(...) ((void)(log_verbose && log_fmt(log_debug, __VA_ARGS__)))
#define LOG_DATA(DATA, ...) \
	((void)(log_verbose && log_data(TO_SLICE(DATA), __VA_ARGS__)))
