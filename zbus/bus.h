#pragma once
#include "config.h"
#include "tx.h"
#include "rcu.h"
#include "addr.h"
#include "sub.h"
#include "rx.h"
#include "vector.h"
#include "txmap.h"
#include "dbus/match.h"
#include "lib/log.h"
#include "lib/threads.h"

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
	str8_t *sockpn;

#ifdef HAVE_LISTENFD
	int sockfd;
#endif

#ifdef HAVE_READY_FIFO
	str8_t *readypn;
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
	str8_t busid;
	char idbuf[BUSID_STRLEN];

	mtx_t lk;
	cnd_t launch;
	struct rcu_writer *rcu; // struct rcu_data
};

// all calls to the bus must be serialized using the lock

int init_bus(struct bus *b);
void destroy_bus(struct bus *b);

int register_remote(struct bus *b, struct rx *r, const str8_t *name,
		    uint32_t serial, struct rcu_reader **preader);
int unregister_remote(struct bus *b, struct rx *r, const str8_t *name,
		      struct rcu_reader *reader);

extern int sys_launch(struct bus *bus, const str8_t *name);

int autolaunch_service(struct bus *b, const str8_t *name,
		       const struct address **paddr);
void service_exited(struct bus *b, const str8_t *name);

int request_name(struct bus *b, struct rx *r, const str8_t *name,
		 uint32_t serial);
int release_name(struct bus *b, struct rx *r, const str8_t *name,
		 uint32_t serial);

#define DBUS_RELEASE_NAME_REPLY_RELEASED 1
#define DBUS_RELEASE_NAME_REPLY_NON_EXISTENT 2
#define DBUS_RELEASE_NAME_REPLY_NOT_OWNER 3

int update_sub(struct bus *b, bool add, struct rx *r, const char *str,
	       struct match m, uint32_t serial);

#define MAX_ARGUMENTS 32

struct config_arguments {
	int num;
	struct {
		const char *cmdline;
		const char *file;
	} v[MAX_ARGUMENTS];
};

int load_config(struct bus *b, struct config_arguments *c);

static inline str8_t *str8dup(const str8_t *from)
{
	str8_t *ret = fmalloc(from->len + 2);
	memcpy(ret, from, from->len + 2);
	return ret;
}
