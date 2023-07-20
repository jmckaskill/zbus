#pragma once
#include <stdlib.h>

extern int verbose;

void elog(const char *fmt, ...);
void dlog(const char *fmt, ...);
void log_data(const void *p, size_t len, const char *fmt, ...);
