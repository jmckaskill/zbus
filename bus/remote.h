#pragma once
#include "msgq.h"
#include "unix.h"
#include "page.h"
#include "messages.h"
#include "lib/types.h"
#include <threads.h>

struct bus;

struct remote {
	// usable by any threads
	struct msgq *qcontrol;
	struct msgq *qdata;
	slice_t addr;
	int id;

	// used by the bus thread and this particular remote thread
	struct bus *bus;
	struct msgq *busq;
	struct gc_handle *handle;
	thrd_t thread;
	slice_t busid;
	int sock;

	// used by the remote thread itself
	char _pad[CACHE_LINE_SIZE];
	int recv_used, recv_have;
	bool send_stalled;
	struct unix_oob send_oob;
	struct unix_oob recv_oob;
	struct page *in;
	struct page_buffer out;
	uint32_t next_serial;
	char addr_buf[16];
};

// API used by the bus thread

void init_remote(struct remote *r, int id);
void gc_remote(void *p);
int start_remote(struct remote *r);
void join_remote(struct remote *r);

// API used internally by the remote thread

#define STS_OK 0

// need to be in same order as error_names global
// errors we can send to the client
#define STS_NOT_ALLOWED -1
#define STS_WRONG_SIGNATURE -2
#define STS_NOT_FOUND -3
#define STS_NOT_SUPPORTED -4
#define STS_NO_REMOTE -5
#define STS_REMOTE_FAILED -6
#define STS_NAME_HAS_NO_OWNER -7
#define STS_ERROR_NUM -9
// non-recoverable errors
#define STS_SEND_FAILED -100
#define STS_PARSE_FAILED -101

#define BUS_DESTINATION S("org.freedesktop.DBus")

struct body {
	slice_t *slices;
};

int authenticate(struct remote *r);
int poll_remote(struct remote *r);
int read_socket(struct remote *r);
int process_dataq(struct remote *r);

int read_string_msg(str_t *buf, struct message *m, struct body b, slice_t *p);
slice_t defragment(str_t *buf, slice_t *slices, int len);

int send_to(struct remote *r, struct remote *to, struct message *m,
	    struct body b);

int send_loopback(struct remote *r, const char *buf, int msgsz);
int loopback_error(struct remote *r, uint32_t serial, int errcode);
int loopback_uint32(struct remote *r, uint32_t serial, uint32_t value);
int loopback_bool(struct remote *r, uint32_t serial, bool value);
int loopback_string(struct remote *r, uint32_t serial, slice_t str);
int loopback_empty(struct remote *r, uint32_t serial);

#define UNIQUE_ADDR_PREFIX S(":1.")

void id_to_string(str_t *s, int id);
int id_from_string(slice_t s);

int unicast(struct remote *r, struct message *m, struct body b);
int broadcast(struct remote *r, struct message *m, struct body b);
int peer_interface(struct remote *r, struct message *m, struct body b);
int monitoring_interface(struct remote *r, struct message *m, struct body b);
int bus_interface(struct remote *r, struct message *m, struct body b);
int reply_request_name(struct remote *r, struct rep_name *q);