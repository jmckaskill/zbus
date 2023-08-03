#pragma once
#include "lib/slice.h"
#include <stdbool.h>

#define BUSID_MAXLEN 32
int generate_busid(char *busid);
int bind_bus(const char *sockpn);
int setup_signals(void);
int poll_one(int fd, bool read, bool write);
int set_non_blocking(int fd);

#ifdef NDEBUG
static inline void set_thread_name(slice_t s) {}
#else
void set_thread_name(slice_t s);
#endif
