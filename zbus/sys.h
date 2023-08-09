#pragma once
#include "dbus/str8.h"
#include <stdbool.h>
#include <stdatomic.h>

struct bus;

#define BUSID_BUFLEN 33
int generate_busid(char *busid);
int bind_bus(const char *sockpn);
int setup_signals(void);
int poll_one(int fd, bool read, bool write);
void must_set_non_blocking(int fd);
int launch_service(struct bus *bus, const str8_t *name);
void kill_services(void);

#define POLL_ACCEPT 0
#define POLL_SIGHUP 1
int poll_accept(int fd);

#ifdef NDEBUG
static inline void set_thread_name(const char *s)
{
}
#else
void set_thread_name(const char *s);
#endif
