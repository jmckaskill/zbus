#define _GNU_SOURCE
#include "bus.h"
#include "config.h"
#include "busmsg.h"
#include "dispatch.h"
#include "dbus/decode.h"
#include "lib/log.h"
#include "lib/algo.h"
#include "lib/sys.h"
#include <sys/types.h>
#include <dirent.h>
#include <time.h>

static struct config *new_config(void);
static void free_config(struct rcu_object *o);

int init_bus(struct bus *b)
{
	b->rcu = NULL;
	if (mtx_init(&b->lk, mtx_plain) != thrd_success) {
		return -1;
	}
	if (cnd_init(&b->launch) != thrd_success) {
		goto destroy_mutex;
	}

	int n = generate_busid(b->busid.p);
	if (n < 0) {
		goto destroy_cnd;
	}
	b->busid.len = (char)n;

	b->rcu = new_rcu_writer();

	struct rcu_data *d = fmalloc(sizeof(*d));
	memset(d, 0, sizeof(*d));
	d->config = new_config();
	rcu_commit(b->rcu, d, NULL);

	return 0;
destroy_cnd:
	cnd_destroy(&b->launch);
destroy_mutex:
	mtx_destroy(&b->lk);
	free_rcu_writer(b->rcu);
	return -1;
}

static void free_addrmap(struct addrmap *m)
{
	for (int i = 0, n = vector_len(&m->hdr); i < n; i++) {
		struct address *a = (struct address *)m->v[i];
		assert(!a->subs);
		assert(!a->tx);
		// the only reason we should still have the address is if it's
		// got a configuration
		assert(a->in_config);
		free_address(a);
	}
	free_vector(&m->hdr);
}

void destroy_bus(struct bus *b)
{
	struct rcu_data *d = (struct rcu_data *)rcu_root(b->rcu);
	free_config(&((struct config *)d->config)->rcu);
	free_addrmap((struct addrmap *)d->destinations);
	free_addrmap((struct addrmap *)d->interfaces);
	assert(!d->name_changed);
	free(d);

	free_rcu_writer(b->rcu);
	cnd_destroy(&b->launch);
	mtx_destroy(&b->lk);
}

static struct rcu_data *edit_rcu_data(struct rcu_object **objs,
				      const struct rcu_data *od)
{
	struct rcu_data *nd = fmalloc(sizeof(*nd));
	*nd = *od;
	static_assert(offsetof(struct rcu_data, rcu) == 0, "");
	rcu_register_gc(objs, (rcu_fn)&free, &od->rcu);
	return nd;
}

////////////////////
// NameOwerChanged

static void notify_name_changed(struct bus *bus, struct rx *r, bool acquired,
				const str8_t *name)
{
	int id = r->tx->id;

	// send the NameAcquired/NameLost Signal
	struct txmsg m;
	init_message(&m.m, MSG_SIGNAL, NO_REPLY_SERIAL);
	m.m.path = BUS_PATH;
	m.m.interface = BUS_INTERFACE;
	m.m.member = acquired ? SIGNAL_NAME_ACQUIRED : SIGNAL_NAME_LOST;
	// leave error blank
	// leave destination blank
	m.m.sender = BUS_DESTINATION;
	m.m.signature = "s";
	// leave fdnum as 0
	// leave reply_serial as 0
	// leave flags as 0

	struct builder b = start_message(r->buf, sizeof(r->buf), &m.m);
	append_string8(&b, name);
	int sz = end_message(b);
	if (send_data(r->tx, false, &m, r->buf, sz)) {
		ERROR("failed to send NameAcquired/Lost message,id:%d", id);
	}

	const struct rcu_data *d = rcu_root(bus->rcu);
	const struct submap *subs = d->name_changed;
	int nsubs = vector_len(&subs->hdr);
	if (!nsubs) {
		return;
	}

	// send the NameOwnerChanged signal
	init_message(&m.m, MSG_SIGNAL, NO_REPLY_SERIAL);
	m.m.path = BUS_PATH;
	m.m.interface = BUS_INTERFACE;
	m.m.member = SIGNAL_NAME_OWNER_CHANGED;
	// leave error blank
	// leave destination blank
	m.m.sender = BUS_DESTINATION;
	m.m.signature = "sss";
	// leave fdnum as 0
	// leave reply_serial as 0
	// leave flags as 0

	b = start_message(r->buf, sizeof(r->buf), &m.m);
	append_string8(&b, name);
	if (acquired) {
		append_string8(&b, S8("\0"));
		append_id_address(&b, id);
	} else {
		append_id_address(&b, id);
		append_string8(&b, S8("\0"));
	}
	sz = end_message(b);

	for (int i = 0; i < nsubs; i++) {
		struct tx *to = subs->v[i]->tx;
		if (send_data(to, false, &m, r->buf, sz)) {
			ERROR("failed to send NameOwnerChanged message,name:%s,txid:%d",
			      name->p, to->id);
		}
	}
}

/////////////////////////////////
// Unique address handling

int register_remote(struct bus *b, struct rx *r, const str8_t *name,
		    uint32_t serial, struct rcu_reader **preader)
{
	int id = r->tx->id;
	const struct rcu_data *od = rcu_root(b->rcu);
	int idx = bsearch_tx(od->remotes, id);
	if (idx >= 0) {
		return -1;
	}

	// Send Hello response first
	reply_string(r, serial, name);

	// then release the new name to everyone else
	struct rcu_object *objs = NULL;
	struct rcu_data *nd = edit_rcu_data(&objs, od);
	struct txmap *nm = edit_txmap(&objs, od->remotes, idx, 1);
	nm->v[idx] = ref_tx(r->tx);
	nd->remotes = nm;
	rcu_commit(b->rcu, nd, objs);

	notify_name_changed(b, r, true, name);

	*preader = new_rcu_reader(b->rcu);
	return 0;
}

int unregister_remote(struct bus *b, struct rx *r, const str8_t *name,
		      struct rcu_reader *reader)
{
	free_rcu_reader(b->rcu, reader);

	int id = r->tx->id;
	const struct rcu_data *od = rcu_root(b->rcu);
	int idx = bsearch_tx(od->remotes, id);
	if (idx < 0) {
		return -1;
	}
	assert(r->tx == od->remotes->v[idx]);

	struct rcu_object *objs = NULL;
	struct rcu_data *nd = edit_rcu_data(&objs, od);
	struct txmap *nm = edit_txmap(&objs, od->remotes, idx, -1);
	rcu_register_gc(&objs, (rcu_fn)&deref_tx, &r->tx->rcu);
	nd->remotes = nm;
	rcu_commit(b->rcu, nd, objs);

	notify_name_changed(b, r, false, name);
	return 0;
}

///////////////////////////
// Named address handling

#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER 1
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE 2
#define DBUS_REQUEST_NAME_REPLY_EXISTS 3
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER 4

int request_name(struct bus *b, struct rx *r, const str8_t *name,
		 uint32_t serial)
{
	// lookup the name
	const struct rcu_data *od = rcu_root(b->rcu);
	int idx = bsearch_address(od->destinations, name);
	if (idx < 0) {
		// TODO: dynamic address creation
		return ERR_NOT_ALLOWED;
	}

	// calculate the return errcode
	int sts;
	const struct addrmap *om = od->destinations;
	const struct address *oa = om->v[idx];
	if (oa->tx == r->tx) {
		sts = DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
	} else if (oa->tx) {
		sts = DBUS_REQUEST_NAME_REPLY_EXISTS;
	} else {
		sts = DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
	}

	bool autolaunch = false;
	struct rcu_object *objs = NULL;
	struct rcu_data *nd = NULL;

	if (sts == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		nd = edit_rcu_data(&objs, od);
		struct address *na = edit_address(&objs, oa);
		struct addrmap *nm = edit_addrmap(&objs, om, idx, 0);
		na->tx = r->tx;
		nm->v[idx] = na;
		nd->destinations = nm;

		autolaunch = na->activatable;
	}

	// first notify the requester
	if (serial) {
		reply_uint32(r, serial, sts);
	}

	// then everyone else
	if (nd) {
		rcu_commit(b->rcu, nd, objs);
		if (autolaunch) {
			cnd_broadcast(&b->launch);
		}
		notify_name_changed(b, r, true, name);
	}
	return 0;
}

int release_name(struct bus *b, struct rx *r, const str8_t *name,
		 uint32_t serial)
{
	int sts;
	const struct rcu_data *od = rcu_root(b->rcu);
	const struct addrmap *om = od->destinations;
	int idx = bsearch_address(om, name);
	if (idx < 0) {
		sts = DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
	} else if (om->v[idx]->tx != r->tx) {
		sts = DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
	} else {
		sts = DBUS_RELEASE_NAME_REPLY_RELEASED;
	}

	struct rcu_object *objs = NULL;
	struct rcu_data *nd = NULL;

	if (sts == DBUS_RELEASE_NAME_REPLY_RELEASED) {
		const struct address *oa = om->v[idx];

		nd = edit_rcu_data(&objs, od);
		struct address *na = edit_address(&objs, oa);
		struct addrmap *nm = edit_addrmap(&objs, om, idx, 0);
		na->tx = NULL;
		nm->v[idx] = na;
		nd->destinations = nm;
	}

	// first notify the requester
	if (serial) {
		reply_uint32(r, serial, sts);
	}

	// then everyone else
	if (nd) {
		rcu_commit(b->rcu, nd, objs);
		notify_name_changed(b, r, false, name);
	}

	return 0;
}

///////////////////////////////
// autolaunch functions

int autolaunch_service(struct bus *b, const str8_t *name,
		       const struct address **paddr)
{
	struct timespec now;
	if (timespec_get(&now, TIME_UTC) != TIME_UTC) {
		ERROR("what is the time?,errno:%m");
		return ERR_INTERNAL;
	}
	struct timespec wait = {
		.tv_sec = now.tv_sec + 500,
		.tv_nsec = now.tv_nsec,
	};

	bool launched = false;

	for (;;) {
		const struct rcu_data *od = rcu_root(b->rcu);
		const struct addrmap *om = od->destinations;
		int idx = bsearch_address(om, name);
		if (idx < 0) {
			return ERR_NO_REMOTE;
		}

		const struct address *oa = om->v[idx];
		if (oa->tx) {
			*paddr = oa;
			return 0;
		} else if (!oa->activatable) {
			return ERR_NOT_ALLOWED;
		}

		if (!oa->running && !launched &&
		    difftime(now.tv_sec, oa->last_launch) > 5) {
			// it's been a while since we launched it, let's try and
			// launch it again
			if (launch_service(b, name)) {
				return ERR_LAUNCH_FAILED;
			}

			// now update the config to indicate that we started it
			struct rcu_object *objs = NULL;
			struct rcu_data *nd = edit_rcu_data(&objs, od);
			struct addrmap *nm = edit_addrmap(&objs, om, idx, 0);
			struct address *na = edit_address(&objs, oa);
			na->last_launch = now.tv_sec;
			na->running = true;
			nm->v[idx] = na;
			nd->destinations = nm;
			rcu_commit(b->rcu, nd, objs);

			launched = true;

		} else if (!oa->running) {
			return ERR_LAUNCH_FAILED;
		}

		// can't touch the address record after the wait as it may
		// have been free'd by a config update
		if (cnd_timedwait(&b->launch, &b->lk, &wait) != thrd_success) {
			return ERR_TIMED_OUT;
		}

		if (timespec_get(&now, TIME_UTC) != TIME_UTC) {
			ERROR("what is the time?,errno:%m");
			return ERR_INTERNAL;
		}
	}
}

void service_exited(struct bus *b, const str8_t *name)
{
	struct rcu_writer *w = b->rcu;
	const struct rcu_data *od = rcu_root(w);
	const struct addrmap *om = od->destinations;
	int idx = bsearch_address(om, name);
	if (idx < 0) {
		return;
	}
	const struct address *oa = om->v[idx];

	struct rcu_object *objs = NULL;
	struct rcu_data *nd = edit_rcu_data(&objs, od);
	struct addrmap *nm = edit_addrmap(&objs, om, idx, 0);
	struct address *na = edit_address(&objs, oa);
	na->running = false;
	nm->v[idx] = na;
	nd->destinations = nm;
	rcu_commit(b->rcu, nd, objs);

	cnd_broadcast(&b->launch);
}

////////////////////////////////////
// subscriptions

static int update_bus_sub(struct bus *b, bool add, struct tx *tx,
			  const char *str, struct match match, uint32_t serial)
{
	const struct rcu_data *od = rcu_root(b->rcu);
	const struct submap *om = od->name_changed;

	int idx;
	if (!add && (idx = bsearch_subscription(om, tx, str, match)) < 0) {
		return ERR_NOT_FOUND;
	}

	struct rcu_object *objs = NULL;
	struct rcu_data *nd = edit_rcu_data(&objs, od);
	struct submap *nm =
		add ? add_subscription(&objs, om, tx, str, match, serial) :
		      rm_subscription(&objs, om, idx);

	nd->name_changed = nm;
	rcu_commit(b->rcu, nd, objs);
	return 0;
}

int update_sub(struct bus *b, bool add, struct tx *tx, const char *str,
	       struct match match, uint32_t serial)
{
	const str8_t *iface = match_interface(str, match);
	const str8_t *sender = match_sender(str, match);
	const str8_t *mbr = match_member(str, match);
	assert(iface);

	if (str8eq(iface, BUS_INTERFACE)) {
		if (!path_matches(str, match, BUS_PATH) ||
		    !str8eq(mbr, SIGNAL_NAME_OWNER_CHANGED)) {
			return ERR_NOT_FOUND;
		}
		return update_bus_sub(b, add, tx, str, match, serial);
	}

	// lookup the address in the current RCU data
	const struct rcu_data *od = rcu_root(b->rcu);
	const struct addrmap *om = sender ? od->destinations : od->interfaces;
	int aidx = bsearch_address(om, sender ? sender : iface);
	if (aidx < 0) {
		// TODO: dynamic interface/destination creation
		return add ? ERR_NOT_ALLOWED : ERR_NOT_FOUND;
	}
	const struct address *oa = om->v[aidx];
	const struct submap *os = oa->subs;

	int sidx;
	if (!add && (sidx = bsearch_subscription(os, tx, str, match)) < 0) {
		return ERR_NOT_FOUND;
	}

	// create new RCU chain
	struct rcu_object *objs = NULL;
	struct rcu_data *nd = edit_rcu_data(&objs, od);
	struct address *na = edit_address(&objs, oa);
	struct addrmap *nm = edit_addrmap(&objs, om, aidx, 0);
	struct submap *ns =
		add ? add_subscription(&objs, os, tx, str, match, serial) :
		      rm_subscription(&objs, os, sidx);

	na->subs = ns;
	nm->v[aidx] = na;
	const struct addrmap **pnm = sender ? &nd->destinations :
					      &nd->interfaces;
	*pnm = nm;
	rcu_commit(b->rcu, nd, objs);
	return 0;
}

/////////////////////////////////
// config option processing

static inline int str8set(str8_t **pstr, const char *from, size_t len)
{
	if (len > UINT8_MAX) {
		return -1;
	}
	str8_t *ret = frealloc(*pstr, len + 2);
	ret->len = len;
	memcpy(&ret->p, from, len);
	ret->p[len] = 0;
	*pstr = ret;
	return 0;
}

static void free_config(struct rcu_object *o)
{
	struct config *c = container_of(o, struct config, rcu);
	if (c) {
		free(c->launch_helper);
		free(c->sockpn);
		free(c->readypn);
		free(c);
	}
}

static struct config *new_config(void)
{
	struct config *c = fmalloc(sizeof(*c));
	c->max_msg_size = 128 * 1024;
	c->max_num_remotes = 64;
	c->max_num_names = 4;
	c->max_num_subs = 16;
	c->runas_user = -1;
	c->runas_group = -1;
	c->launch_helper = NULL;
	c->readypn = NULL;
	c->sockpn = NULL;
	c->sockfd = -1;
	return c;
}

static int cmp_str8_addresss_node(CRBTree *t, void *k, CRBNode *n)
{
	str8_t *key = k;
	struct address *a = node_to_addr(n);
	return str8cmp(key, &a->name);
}

static struct address *get_address(CRBTree *t, char *key, size_t klen,
				   size_t *pfxlen)
{
	// key is of the form address.org.example.Service.enabled
	// want to pick out the middle piece. *pfxlen gives the length of the
	// "address." prefix. Pick out the last section and return the length of
	// "address.org.example.Service." in pfxlen.
	char *firstdot = key + *pfxlen;
	char *lastdot = memrchr(firstdot, '.', klen - *pfxlen);
	if (!lastdot || lastdot - firstdot > UINT8_MAX) {
		return NULL;
	}
	*pfxlen = lastdot - key + 1;

	// create a str8 for use with the lookup, but save the len and nul bytes
	// so we can restore them after.
	str8_t *s = (str8_t *)(firstdot - 1);
	size_t slen = lastdot - firstdot;
	uint8_t prevlen = s->len;
	char prevnul = s->p[slen];
	s->len = slen;
	s->p[slen] = 0;

	CRBNode *p;
	CRBNode **l = c_rbtree_find_slot(t, &cmp_str8_addresss_node, s, &p);
	struct address *a;
	if (l) {
		a = new_address(s);
		a->in_config = true;
		c_rbtree_add(t, p, l, &a->rb);
	} else {
		a = node_to_addr(p);
	}
	s->len = prevlen;
	s->p[slen] = prevnul;
	return a;
}

#define CFG_KEY -1
#define CFG_VALUE -2
#define CFG_OVERLONG -3

static int parse_global_config(struct config *c, const char *key,
			       const char *val)
{
	switch (strlen(key)) {
	case 6:
		if (!strcmp(key, "listen")) {
			c->sockfd = -1;
			if (str8set(&c->sockpn, val, strlen(val))) {
				return CFG_OVERLONG;
			}
			return 0;
		} else {
			return CFG_KEY;
		}

	case 8:
		if (!strcmp(key, "log_type")) {
			if (!strcasecmp(val, "json")) {
				g_log_type = LOG_JSON;
			} else if (!strcasecmp(val, "text")) {
				g_log_type = LOG_TEXT;
			} else {
				return CFG_VALUE;
			}
			return 0;
		} else if (!strcmp(key, "listenfd")) {
			c->sockfd = atoi(val);
			free(c->sockpn);
			c->sockpn = NULL;
			return 0;
		} else {
			return CFG_KEY;
		}

	case 9:
		if (!strcmp(key, "log_level")) {
			if (!strcasecmp(val, "debug")) {
				g_log_level = LOG_DEBUG;
			} else if (!strcasecmp(val, "verbose")) {
				g_log_level = LOG_VERBOSE;
			} else if (!strcasecmp(val, "notice")) {
				g_log_level = LOG_NOTICE;
			} else if (!strcasecmp(val, "warning")) {
				g_log_level = LOG_WARNING;
			} else if (!strcasecmp(val, "error")) {
				g_log_level = LOG_ERROR;
			} else {
				return CFG_VALUE;
			}
			return 0;
		} else {
			return CFG_KEY;
		}

	case 10:
		if (!strcmp(key, "ready_fifo")) {
			if (str8set(&c->readypn, val, strlen(val))) {
				return CFG_OVERLONG;
			}
			return 0;
		} else {
			return CFG_KEY;
		}
	case 13:
		if (!strcmp(key, "launch_helper")) {
			if (str8set(&c->launch_helper, val, strlen(val))) {
				return CFG_OVERLONG;
			}
			return 0;
		} else {
			return CFG_KEY;
		}
	default:
		return CFG_KEY;
	}
}

static int parse_address_config(struct address *a, const char *key,
				const char *val)
{
	if (!strcmp(key, "description")) {
		return 0;
	} else if (!strcmp(key, "activatable")) {
		if (!strcasecmp(val, "true")) {
			a->activatable = true;
		} else if (!strcasecmp(val, "false")) {
			a->activatable = false;
		} else {
			return CFG_VALUE;
		}
		return 0;
	} else {
		return CFG_KEY;
	}
}

static int parse_interface_config(struct address *a, const char *key,
				  const char *val)
{
	if (!strcmp(key, "description")) {
		return 0;
	} else {
		return CFG_KEY;
	}
}

static bool has_prefix(char *str, size_t len, const char *pfx, size_t plen)
{
	return len >= plen && !memcmp(str, pfx, plen) && len <= UINT8_MAX;
}

static int parse_config_entry(struct config_loader *c, const char *fn,
			      int lineno, char *key, char *val)
{
	int err;
	size_t klen = strlen(key);
	if (has_prefix(key, klen, "interface.", 10)) {
		size_t pfx = strlen("interface.");
		struct address *a =
			get_address(&c->interfaces, key, klen, &pfx);
		err = a ? parse_interface_config(a, key + pfx, val) :
			  CFG_OVERLONG;

	} else if (has_prefix(key, klen, "address.", 8)) {
		size_t pfx = strlen("address.");
		struct address *a = get_address(&c->addresses, key, klen, &pfx);
		err = a ? parse_address_config(a, key + pfx, val) :
			  CFG_OVERLONG;

	} else {
		err = parse_global_config(c->global, key, val);
	}

	switch (err) {
	case 0:
		return 0;
	case CFG_OVERLONG:
		ERROR("overlong config value,file:%s,line:%d", fn, lineno);
		return -1;
	case CFG_KEY:
		ERROR("unknown config key,file:%s,line:%d,key:%s", fn, lineno,
		      key);
		return -1;
	case CFG_VALUE:
		ERROR("unknown config value,file:%s,line:%d,key:%s,val:%s", fn,
		      lineno, key, val);
		return -1;
	default:
		return -1;
	}
}

struct stack_entry {
	struct ini_reader ini;
	char *fn;
	char *heap;
	struct sysdir *dir;
};

struct parse_stack {
	struct stack_entry v[16];
};

static int load_next_file(struct stack_entry *s, const char *file)
{
	char *fn = strdup(file);
	char *data;
	size_t sz;
	if (sys_slurp(fn, &data, &sz)) {
		free(fn);
		return -1;
	}
	init_ini(&s->ini, data, sz);
	s->heap = data;
	s->fn = fn;
	return 0;
}

static void load_string(struct stack_entry *s, const char *str)
{
	init_ini(&s->ini, str, strlen(str));
	s->heap = NULL;
	s->fn = strdup("cmdline");
	s->dir = NULL;
}

static int load_file(struct stack_entry *s, const char *pn)
{
	s->dir = NULL;
	return load_next_file(s, pn);
}

static int load_dir(struct stack_entry *s, const char *pn)
{
	struct sysdir *d;
	if (sys_opendir(&d, pn)) {
		ERROR("failed to open config dir,dir:%s,errno:%m", pn);
		return -1;
	}
	init_ini(&s->ini, NULL, 0);
	s->dir = d;
	s->heap = NULL;
	s->fn = NULL;
	return 0;
}

static void close_file(struct stack_entry *s)
{
	free(s->fn);
	free(s->heap);
	sys_closedir(s->dir);
}

static struct stack_entry *next_file(struct stack_entry *s)
{
	free(s->fn);
	free(s->heap);

	if (!s->dir) {
		return s - 1;
	}

next_file:
	const char *fn = sys_nextfile(s->dir);
	if (!fn) {
		sys_closedir(s->dir);
		return s - 1;
	}
	if (load_next_file(s, fn)) {
		goto next_file;
	}
	return s;
}

static int do_parse(struct parse_stack *p, struct config_loader *c)
{
	struct stack_entry *s = p->v;
	struct stack_entry *sbot = p->v;
	struct stack_entry *stop = p->v + sizeof(p->v) / sizeof(p->v[0]);

	for (;;) {
		char key[INI_BUFLEN];
		char val[INI_BUFLEN];
		int sts = read_ini(&s->ini, key, val);
		if (sts == INI_EOF) {
			s = next_file(s);
			if (s < sbot) {
				return 0;
			}
		} else if (sts != INI_OK) {
			ERROR("parse error,file:%s,line:%d", s->fn,
			      s->ini.lineno);
			break;
		}

		if (!strcmp(key, "include")) {
			if (++s == stop) {
				ERROR("parse include depth too deep");
				break;
			}
			if (load_file(s, val)) {
				break;
			}
		} else if (!strcmp(key, "includedir")) {
			if (++s == stop) {
				ERROR("parse include depth too deep");
				break;
			}
			if (load_dir(s, val)) {
				break;
			}
		} else if (parse_config_entry(c, s->fn, s->ini.lineno, key,
					      val)) {
			break;
		}
	}

	while (s >= sbot) {
		close_file(s--);
	}
	return -1;
}

int add_config_file(struct config_loader *c, const char *fn)
{
	struct parse_stack s;
	if (load_file(s.v, fn)) {
		return -1;
	}
	return do_parse(&s, c);
}

int add_config_cmdline(struct config_loader *c, const char *str)
{
	struct parse_stack s;
	load_string(s.v, str);
	return do_parse(&s, c);
}

static void free_tree(CRBTree *t)
{
	// Use postorder traversal, that is children first and then parent. That
	// way we can safely free the data as we go.

	CRBNode *n = c_rbtree_first_postorder(t);
	while (n) {
		CRBNode *next = c_rbnode_next_postorder(n);
		struct address *a = node_to_addr(n);
		free_address(a);
		n = next;
	}
}

void init_config(struct config_loader *c)
{
	memset(c, 0, sizeof(*c));
	c->global = new_config();
}

void destroy_config(struct config_loader *c)
{
	free_tree(&c->addresses);
	free_tree(&c->interfaces);
	free_config(&c->global->rcu);
}

void load_config(struct config_loader *c, struct bus *b)
{
	struct rcu_object *objs = NULL;
	const struct rcu_data *od = rcu_root(b->rcu);
	struct rcu_data *nd = edit_rcu_data(&objs, od);
	rcu_register_gc(&objs, &free_config, &nd->config->rcu);
	nd->config = c->global;
	nd->destinations =
		merge_addresses(&objs, nd->destinations, &c->addresses);
	nd->interfaces = merge_addresses(&objs, nd->interfaces, &c->interfaces);
	rcu_commit(b->rcu, nd, objs);
	// we consumed all the data, reset to blank
	memset(c, 0, sizeof(*c));
}
