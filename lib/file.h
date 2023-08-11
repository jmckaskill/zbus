#pragma once
#include <stddef.h>
#include <stdint.h>

int sys_slurp(const char *filename, char **pbuf, size_t *psz);

struct sysdir;
int sys_opendir(struct sysdir **pd, const char *pn);
const char *sys_nextfile(struct sysdir *d);
void sys_closedir(struct sysdir *d);

