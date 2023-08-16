#pragma once
#include "config.h"
#include "tx.h"
#include "rcu.h"
#include "bus.h"
#include "dispatch.h"
#include "txmap.h"
#include "socket.h"
#include "dbus/stream.h"
#include "dbus/str8.h"

// this is the largest potential message we have to generate
#define NAME_OWNER_CHANGED_BUFSZ                                   \
	(ZB_MIN_MSG_SIZE + ZB_BUF_FIELD /*reply*/ +                \
	 (ZB_BUF_FIELD + 1 + sizeof("sss")) +                      \
	 (ZB_BUF_FIELD + 4 + sizeof("NameOwnerChanged")) +         \
	 2 * (ZB_BUF_FIELD + 4 + sizeof("org.freedesktop.DBus")) + \
	 (ZB_BUF_FIELD + 4 + sizeof("/org/freedesktop/DBus")) +    \
	 (ZB_BUF_STRING + 256 /*name*/) +                          \
	 2 * (ZB_BUF_STRING + UNIQ_ADDR_BUFLEN))

// full length: mbr,iface,path,sig
// controlled length: reply,sender
#define SIGNAL_HDR_BUFSZ                                                \
	(ZB_MIN_MSG_SIZE + 4 * (ZB_BUF_FIELD + ZB_BUF_STRING + 255) +   \
	 (ZB_BUF_FIELD + ZB_BUF_STRING + UNIQ_ADDR_BUFLEN) /*sender*/ + \
	 ZB_BUF_FIELD /*reply*/)

// Maximum size of messages we'll process
#define RX_BUFSZ (128 * 1024)
// Maximum size of received headers or bus messages we'll process. This
// is allocated on top of the buf size to allow for defragmentation.
#define RX_HDRSZ (2048)
// Maximum size of headers or bus messages we'll send.
#define TX_BUFSZ (2048)

static_assert(TX_BUFSZ > NAME_OWNER_CHANGED_BUFSZ, "");
static_assert(TX_BUFSZ > SIGNAL_HDR_BUFSZ, "");

struct rxname {
	struct rxname *next;
	zb_str8 name;
};

struct rx {
	struct bus *bus;
	struct tx *tx;
	struct rcu_reader *reader; // struct rcu_data
	struct rxconn conn;
	int num_names;
	int num_subs;
	struct rxname *names;
	struct subscription *subs;
	char *txbuf;
	zb_str8 addr;
};

struct rx *new_rx(struct bus *bus, int id);
void free_rx(struct rx *r);
int run_rx(struct rx *r);
