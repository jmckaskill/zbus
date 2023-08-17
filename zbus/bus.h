#pragma once
#include "config.h"
#include "tx.h"
#include "rcu.h"
#include "addr.h"
#include "sub.h"
#include "rx.h"
#include "vector.h"
#include "txmap.h"
#include "threads.h"
#include "match.h"
#include "lib/log.h"

struct tx;
struct rx;
struct address;

#define BUSID_STRLEN 32

struct config {
	struct rcu_object rcu;
	unsigned max_msg_size;
	unsigned max_num_remotes;
	unsigned max_num_names;
	unsigned max_num_subs;

	bool allow_unknown_destinations;
	bool allow_unknown_interfaces;
	bool autoexit;

	int listenfd;
	char *listenpn;
	char *address; // address in dbus format
	char *type;

#if HAVE_READY_FIFO
	char *readypn;
#endif
};

struct rcu_data {
	struct rcu_object rcu;
	const struct config *config;
	const struct addrmap *destinations;
	const struct addrmap *interfaces;
	const struct submap *name_changed;
	const struct txmap *remotes;
};

struct bus {
	zb_str8 busid;
	char idbuf[BUSID_STRLEN];

	mtx_t lk;
	cnd_t launch;
	struct rcu_writer *rcu; // struct rcu_data
};

// all calls to the bus must be serialized using the lock

int init_bus(struct bus *b);
void destroy_bus(struct bus *b);

int register_remote(struct bus *b, struct rx *r, const zb_str8 *name,
		    uint32_t serial, struct rcu_reader **preader);
int unregister_remote(struct bus *b, struct rx *r, const zb_str8 *name,
		      struct rcu_reader *reader);

extern int sys_launch(struct bus *bus, const struct address *addr);

int autolaunch_service(struct bus *b, const zb_str8 *name,
		       const struct address **paddr);
void service_exited(struct bus *b, const zb_str8 *name);

int request_name(struct bus *b, struct rx *r, const zb_str8 *name,
		 uint32_t serial);
int release_name(struct bus *b, struct rx *r, const zb_str8 *name,
		 uint32_t serial, bool send_name_lost);

#define DBUS_RELEASE_NAME_REPLY_RELEASED 1
#define DBUS_RELEASE_NAME_REPLY_NON_EXISTENT 2
#define DBUS_RELEASE_NAME_REPLY_NOT_OWNER 3

int update_sub(struct bus *b, bool add, struct rx *r, const char *str,
	       struct match m, uint32_t serial);

#define MAX_ARGUMENTS 32

struct config_arguments {
	int num;
	struct {
		const char *key;
		size_t klen;
		const char *value;
	} v[MAX_ARGUMENTS];
};

int load_config(struct bus *b, struct config_arguments *c);
int parse_argv(struct config_arguments *c, int argc, char **argv);
