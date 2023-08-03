#pragma once
#include "rcu.h"
#include "tx.h"
#include "algo.h"
#include <limits.h>
#include <time.h>

struct autostart {
	cnd_t wait;
	time_t last_launch;
	bool running;
	int waiters;
};

struct address {
	struct rcu_object obj;
	struct rcu_reader *subs_reader; // struct subscription_map
	struct rcu_writer *subs_writer;
	struct tx *tx;
	struct circ_list owner_list;
	int owner_id;
	struct autostart *autostart;
	struct {
		int len;
		char p[0];
	} name;
};

struct address_map {
	struct rcu_object obj;
	int len;
	struct address *v[0];
};

struct autostart *new_autostart(void);
void free_autostart(struct autostart *a);

void free_address_map(struct address_map *m);

struct address *update_address(struct rcu_writer *w, struct address_map **pmap,
			       int idx);
struct address *add_address(struct rcu_writer *w, struct address_map **pmap,
			    int idx, slice_t name);
int remove_address(struct rcu_writer *w, struct address_map **pmap, int idx);

int find_unique_address(struct address_map *m, int id);
int find_named_address(struct address_map *m, slice_t name);

#define STRINGIZE(X) #X
#define RESOLVE(X) (X)
#define STRLEN(X) (sizeof(X) - 1)

#define UNIQ_ADDR_PREFIX ":1."
#define UNIQ_ADDR_MAXLEN \
	(STRLEN(UNIQ_ADDR_PREFIX) + STRLEN(STRINGIZE(RESOLVE(INT_MAX))))

// buffer must be at least UNIX_ADDR_MAXLEN long
size_t id_to_address(char *buf, int id);
int address_to_id(slice_t s);
