#pragma once
#include "config.h"
#include "bus.h"

struct ini_reader {
	const char *data;
	const char *end;
	int lineno;
	const char *section;
	size_t seclen;
};

void init_ini(struct ini_reader *p, const char *data, size_t sz);

#define INI_OK 0
#define INI_ERROR -1
#define INI_EOF 1
#define INI_BUFLEN 256

int read_ini(struct ini_reader *p, char *key, char *val);
