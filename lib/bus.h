#pragma once
#include "types.h"

int bind_unique_address(const char *dir, int owner, int group, int mode,
			char *uniqbuf, unsigned bufsz);

int blocking_poll(int fd, int event);
int blocking_send(int fd, const char *bus, slice_t to, const void *p,
		  unsigned sz, const struct unix_oob *oob);

#define RECV_ERROR -1
#define RECV_MORE 1
#define RECV_OK 0

int recv_message(int fd, char *buf, unsigned bufsz, struct message *msg,
		 struct iterator *body, struct unix_oob *oob);
