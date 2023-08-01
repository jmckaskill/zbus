#pragma once
#include "msgq.h"
#include "unix.h"
#include "page.h"
#include "messages.h"
#include "lib/types.h"
#include "lib/match.h"
#include <threads.h>

struct bus;

struct remote {
	// const data used by any thread
	struct msg_queue *qcontrol;
	struct msg_queue *qdata;
	slice_t addr;
	int id;
	char addr_buf[16];

	// const data setup by the bus thread and used by this thread
	struct msg_queue *busq;
	struct gc_handle *handle;
	thrd_t thread;
	slice_t busid;
	int sock;

	// mutable data used by the remote thread
	char _pad[CACHE_LINE_SIZE];

	// recv data
	int recv_used, recv_have;
	struct unix_oob recv_oob;
	struct page *in;

	// queue data
	struct msg_waiter waiter;
	int icontrol;
	int idata;

	// send data
	bool can_write;
	struct unix_oob send_oob;
	struct page_buffer out;
	uint32_t next_serial;

	// Matches are those that our client has asked for
	struct match matches[MAX_MATCH_NUM];
	int name_sub_num;
	int match_num;

	// Subscriptions are those that other clients asked for that we publish
	// against
	struct ucast_sub subs[MAX_MATCH_NUM];
	int sub_num;
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
#define STS_OOM -8
#define STS_MAX_ERROR -9
// non-recoverable errors
#define STS_SEND_FAILED -100
#define STS_PARSE_FAILED -101

#define BUS_DESTINATION S("org.freedesktop.DBus")
#define BUS_PATH S("/org/freedesktop/DBus")
#define BUS_INTERFACE S("org.freedesktop.DBus")
#define PEER_INTERFACE S("org.freedesktop.DBus.Peer")
#define MONITORING_INTERFACE S("org.freedesktop.DBus.Monitoring")

struct body {
	slice_t *slices;
	int len;
};

int authenticate(struct remote *r);
int poll_socket(int fd, bool *pcan_write);
int read_socket(struct remote *r);
int process_dataq(struct remote *r);

int read_string_msg(buf_t *buf, struct message *m, struct body b, slice_t *p);
slice_t defragment(buf_t *buf, const slice_t *slices, int to_get);
slice_t *skip_parts(slice_t *parts, int to_skip);

int send_to(struct remote *r, struct remote *to, struct message *m,
	    struct body b);

int send_loopback(struct remote *r, slice_t data);
int loopback_error(struct remote *r, uint32_t serial, int errcode);
int loopback_uint32(struct remote *r, uint32_t serial, uint32_t value);
int loopback_bool(struct remote *r, uint32_t serial, bool value);
int loopback_string(struct remote *r, uint32_t serial, slice_t str);
int loopback_empty(struct remote *r, uint32_t serial);

int unicast(struct remote *r, struct message *m, struct body b);
int broadcast(struct remote *r, struct message *m, struct body b);
int peer_interface(struct remote *r, struct message *m, struct body b);
int monitoring_interface(struct remote *r, struct message *m, struct body b);
int bus_interface(struct remote *r, struct message *m, struct body b);
int reply_errcode(struct remote *r, struct rep_errcode *c);

void remove_all_matches(struct remote *r);
void update_bus_matches(struct remote *r, slice_t sender);
int add_match(struct remote *r, struct message *m, struct body b);
int rm_match(struct remote *r, struct message *m, struct body b);
int add_subscription(struct remote *r, struct ucast_sub *s);
int rm_subscription(struct remote *r, struct ucast_sub *s);
