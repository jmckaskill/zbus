#pragma once
#include "zbus.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef _WIN32
typedef void *zb_handle_t;
#else
typedef int zb_handle_t;
#endif

ZB_EXTERN int zb_connect(zb_handle_t *pfd, const char *address);
ZB_EXTERN void zb_close(zb_handle_t fd);
ZB_EXTERN int zb_send(zb_handle_t fd, const void *buf, size_t sz);
ZB_EXTERN int zb_recv(zb_handle_t fd, void *buf, size_t sz);
ZB_EXTERN char *zb_userid(char *buf, size_t sz);

// returns # of bytes consumed or -ve on error
ZB_EXTERN int zb_parse_address(char *address, const char **ptype,
			       const char **phost, const char **pport);