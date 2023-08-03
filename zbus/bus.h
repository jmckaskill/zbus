#pragma once
#include "sys.h"
#include "tx.h"
#include "rcu.h"
#include "addr.h"
#include "sub.h"
#include "lib/slice.h"
#include "lib/match.h"
#include <threads.h>

struct rcu_names {
	struct rcu_object rcu;
	struct address_map *unique;
	struct address_map *named;
	struct subscription_map *broadcast;
	struct subscription_map *name_changed;
};

struct bus {
	struct {
		char len;
		char p[BUSID_MAXLEN];
	} busid;

	mtx_t lk;
	struct rcu_writer *names; // struct rcu_names
};

// all calls to the bus must be serialized using the lock

int init_bus(struct bus *b);
void destroy_bus(struct bus *b);

int register_remote(struct bus *b, int id, slice_t name, struct tx *tx,
		    struct circ_list *names, struct rcu_reader **preader);

int unregister_remote(struct bus *b, int id);

int add_name(struct bus *b, slice_t name, bool autostart);
int autolaunch_service(struct bus *b, slice_t name, struct address **paddr);
void service_exited(struct bus *b, slice_t name);

#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER 1
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE 2
#define DBUS_REQUEST_NAME_REPLY_EXISTS 3
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER 4

int request_name(struct bus *b, slice_t name, int id, struct tx *tx,
		 struct circ_list *names);

#define DBUS_RELEASE_NAME_REPLY_RELEASED 1
#define DBUS_RELEASE_NAME_REPLY_NON_EXISTENT 2
#define DBUS_RELEASE_NAME_REPLY_NOT_OWNER 3

int release_name(struct bus *b, slice_t name, int id, struct tx *tx);

int update_bus_sub(struct bus *b, bool add, struct tx *to, struct match *m,
		   uint32_t serial, struct circ_list *o);
int update_bcast_sub(struct bus *b, bool add, struct tx *to, struct match *m,
		     uint32_t serial, struct circ_list *o);
int update_ucast_sub(struct bus *b, bool add, struct tx *to, struct match *m,
		     uint32_t serial, struct circ_list *o);
