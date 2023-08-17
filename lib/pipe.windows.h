#pragma once
#include <stddef.h>
#include <stdbool.h>

struct winmmap {
	void *handle;
	void *data;
	size_t sz;
};

#define MAP_WIN_ERROR -1
#define MAP_WIN_OK 0
#define MAP_WIN_CREATED 1
int create_win_pipename(struct winmmap *m, const char *name);
int open_win_pipename(struct winmmap *m, const char *name);
void unmap_win_pipename(struct winmmap *m);

int read_win_pipename(const struct winmmap *m, char *buf, size_t bufsz);
int write_win_pipename(const struct winmmap *m, const char *pipename);
