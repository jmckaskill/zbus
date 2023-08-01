#pragma once
#include <stdbool.h>

#define BUSID_MAXLEN 32
int generate_busid(char *busid);
int bind_bus(const char *sockpn);
int setup_signals(void);
int poll_one(int fd, bool read, bool write);
int set_non_blocking(int fd);
