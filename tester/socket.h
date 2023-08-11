#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
typedef uintptr_t fd_t;
#else
typedef int fd_t;
#endif

int sys_open(fd_t *pfd, const char *pn, bool block);
void sys_close(fd_t fd);
int sys_send(fd_t fd, const char *b, int sz);
int sys_recv(fd_t fd, char *b, int sz);
char *sys_userid(char *buf, size_t sz);
