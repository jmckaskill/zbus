#pragma once
#include "lib/slice.h"
#include <stdbool.h>

struct bus;

#define BUSID_MAXLEN 32
int generate_busid(char *busid);
int bind_bus(const char *sockpn);
int setup_signals(void);
int poll_one(int fd, bool read, bool write);
int set_non_blocking(int fd);
int launch_service(struct bus *bus, slice_t name);
void kill_services(void);

#ifdef NDEBUG
static inline void set_thread_name(slice_t s)
{
}
#else
void set_thread_name(slice_t s);
#endif
