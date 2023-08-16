#define _GNU_SOURCE
#include "config.h"
#include "bus.h"
#include "ini.h"
#include "busmsg.h"
#include "dispatch.h"
#include "sec.h"
#include "dbus/decode.h"
#include "lib/log.h"
#include "lib/algo.h"
#include "lib/file.h"
#include "lib/print.h"
#include "vendor/c-rbtree-3.1.0/src/c-rbtree.h"

#if HAVE_MEMRCHR
#define x_memrchr memrchr
#else
static char *x_memrchr(char *p, char ch, size_t len)
{
	char *s = p + len;
	for (;;) {
		if (s == p) {
			return NULL;
		} else if (*(--s) == ch) {
			return s;
		}
	}
}
#endif

static struct config *new_config(void);
static void free_config(struct rcu_object *o);

int generate_busid(zb_str8 *s)
{
	static const char hex_enc[] = "0123456789abcdef";
	uint8_t rand[BUSID_STRLEN / 2];
	if (getentropy(rand, sizeof(rand))) {
		ERROR("getentropy,errno:%m");
		return -1;
	}
	for (int i = 0; i < sizeof(rand); i++) {
		s->p[2 * i] = hex_enc[rand[i] >> 4];
		s->p[2 * i + 1] = hex_enc[rand[i] & 15];
	}
	size_t n = 2 * sizeof(rand);
	s->len = (uint8_t)n;
	s->p[n] = '\0';
	return 0;
}

int init_bus(struct bus *b)
{
	b->rcu = NULL;
	if (mtx_init(&b->lk, mtx_plain) != thrd_success) {
		return -1;
	}
	if (cnd_init(&b->launch) != thrd_success) {
		goto destroy_mutex;
	}
	if (generate_busid(&b->busid)) {
		goto destroy_cnd;
	}

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
		assert(a->cfg);
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

static void notify_name_acquired(struct bus *bus, char *buf, bool acquired,
				 struct tx *tx, const zb_str8 *name)
{
	// send the NameAcquired/NameLost Signal
	struct txmsg m;
	zb_init_message(&m.m, ZB_SIGNAL, NO_REPLY_SERIAL);
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

	struct zb_builder b;
	zb_start(&b, buf, NAME_OWNER_CHANGED_BUFSZ, &m.m);
	zb_add_str8(&b, name);
	int sz = zb_end(&b);
	if (send_data(tx, false, &m, buf, sz)) {
		ERROR("failed to send NameAcquired/Lost message,id:%d", tx->id);
	}
}

static void notify_name_changed(struct bus *bus, char *buf, bool acquired,
				int id, const zb_str8 *name)
{
	const struct rcu_data *d = rcu_root(bus->rcu);
	const struct submap *subs = d->name_changed;
	int nsubs = vector_len(&subs->hdr);
	if (!nsubs) {
		return;
	}

	// send the NameOwnerChanged signal
	struct txmsg m;
	zb_init_message(&m.m, ZB_SIGNAL, NO_REPLY_SERIAL);
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

	struct zb_builder b;
	zb_start(&b, buf, NAME_OWNER_CHANGED_BUFSZ, &m.m);
	zb_add_str8(&b, name);
	if (acquired) {
		zb_add_str8(&b, S8("\0"));
		append_id_address(&b, id);
	} else {
		append_id_address(&b, id);
		zb_add_str8(&b, S8("\0"));
	}
	int sz = zb_end(&b);

	for (int i = 0; i < nsubs; i++) {
		struct tx *to = subs->v[i]->tx;
		if (send_data(to, false, &m, buf, sz)) {
			ERROR("failed to send NameOwnerChanged message,name:%s,txid:%d",
			      name->p, to->id);
		}
	}
}

/////////////////////////////////
// Unique address handling

int register_remote(struct bus *b, struct rx *r, const zb_str8 *name,
		    uint32_t serial, struct rcu_reader **preader)
{
	struct tx *tx = r->tx;
	const struct rcu_data *od = rcu_root(b->rcu);
	int idx = bsearch_tx(od->remotes, tx->id);
	if (idx >= 0) {
		return -1;
	}
	idx = -(idx + 1);

	// Send Hello response first
	reply_string(r, serial, name);

	// then release the new name to everyone else
	struct rcu_object *objs = NULL;
	struct rcu_data *nd = edit_rcu_data(&objs, od);
	struct txmap *nm = edit_txmap(&objs, od->remotes, idx, 1);
	nm->v[idx] = ref_tx(tx);
	nd->remotes = nm;
	rcu_commit(b->rcu, nd, objs);

	notify_name_acquired(b, r->txbuf, true, tx, name);
	notify_name_changed(b, r->txbuf, true, tx->id, name);

	*preader = new_rcu_reader(b->rcu);
	return 0;
}

int unregister_remote(struct bus *b, struct rx *r, const zb_str8 *name,
		      struct rcu_reader *reader)
{
	free_rcu_reader(b->rcu, reader);

	struct tx *tx = r->tx;
	const struct rcu_data *od = rcu_root(b->rcu);
	int idx = bsearch_tx(od->remotes, tx->id);
	if (idx < 0) {
		return -1;
	}
	assert(tx == od->remotes->v[idx]);
	static_assert(offsetof(struct tx, rcu) == 0, "");

	struct rcu_object *objs = NULL;
	struct rcu_data *nd = edit_rcu_data(&objs, od);
	struct txmap *nm = edit_txmap(&objs, od->remotes, idx, -1);
	rcu_register_gc(&objs, (rcu_fn)&deref_tx, &tx->rcu);
	nd->remotes = nm;
	rcu_commit(b->rcu, nd, objs);

	// don't need to send NameLost when unregistering the unique address as
	// the remote is already gone
	notify_name_changed(b, r->txbuf, false, tx->id, name);
	return 0;
}

///////////////////////////
// Named address handling

#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER 1
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE 2
#define DBUS_REQUEST_NAME_REPLY_EXISTS 3
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER 4

int request_name(struct bus *b, struct rx *r, const zb_str8 *name,
		 uint32_t serial)
{
	// lookup the name
	const struct rcu_data *od = rcu_root(b->rcu);
	int idx = bsearch_address(od->destinations, name);

	// calculate the return errcode
	int sts;
	const struct addrmap *om = od->destinations;
	const struct address *oa;
	if (idx >= 0) {
		oa = om->v[idx];
		if (oa->cfg && !has_group(r->tx->sec, oa->cfg->gid_owner)) {
			return ERR_NOT_ALLOWED;
		} else if (oa->tx == r->tx) {
			sts = DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
		} else if (oa->tx) {
			sts = DBUS_REQUEST_NAME_REPLY_EXISTS;
		} else {
			sts = DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
		}
	} else {
		oa = NULL;
		idx = -(idx + 1);
		if (!od->config->allow_unknown_destinations) {
			return ERR_NOT_ALLOWED;
		} else {
			sts = DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
		}
	}

#if ENABLE_AUTOSTART
	bool autolaunch = false;
#endif
	struct rcu_object *objs = NULL;
	struct rcu_data *nd = NULL;
	struct tx *tx = r->tx;

	if (sts == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		nd = edit_rcu_data(&objs, od);
		struct address *na = oa ? edit_address(&objs, oa) :
					  new_address(name);
		struct addrmap *nm = edit_addrmap(&objs, om, idx, (oa ? 0 : 1));
		na->tx = tx;
		nm->v[idx] = na;
		nd->destinations = nm;

#if ENABLE_AUTOSTART
		autolaunch = oa && oa->cfg && oa->cfg->exec;
#endif
	}

	// first notify the requester
	if (serial) {
		reply_uint32(r, serial, sts);
	}

	// then everyone else
	if (nd) {
		rcu_commit(b->rcu, nd, objs);
		notify_name_acquired(b, r->txbuf, true, tx, name);
		notify_name_changed(b, r->txbuf, true, tx->id, name);
#if ENABLE_AUTOSTART
		if (autolaunch) {
			cnd_broadcast(&b->launch);
		}
#endif
	}
	return 0;
}

int release_name(struct bus *b, struct rx *r, const zb_str8 *name,
		 uint32_t serial, bool send_name_lost)
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
	struct tx *tx = r->tx;

	if (sts == DBUS_RELEASE_NAME_REPLY_RELEASED) {
		const struct address *oa = om->v[idx];
		assert(oa->tx == tx);

		nd = edit_rcu_data(&objs, od);
		if (oa->cfg || oa->subs) {
			struct address *na = edit_address(&objs, oa);
			struct addrmap *nm = edit_addrmap(&objs, om, idx, 0);
			na->tx = NULL;
			nm->v[idx] = na;
			nd->destinations = nm;
		} else {
			struct addrmap *nm = edit_addrmap(&objs, om, idx, -1);
			collect_address(&objs, oa);
			nd->destinations = nm;
		}
	}

	// first notify the requester
	if (serial) {
		reply_uint32(r, serial, sts);
	}

	// then everyone else
	if (nd) {
		rcu_commit(b->rcu, nd, objs);
		if (send_name_lost) {
			notify_name_acquired(b, r->txbuf, false, tx, name);
		}
		notify_name_changed(b, r->txbuf, false, tx->id, name);
	}

	return 0;
}

///////////////////////////////
// autolaunch functions

#if ENABLE_AUTOSTART
int autolaunch_service(struct bus *b, const zb_str8 *name,
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
		} else if (!oa->cfg || !oa->cfg->exec) {
			return ERR_NOT_ALLOWED;
		}

		if (!oa->running && !launched &&
		    difftime(now.tv_sec, oa->last_launch) > 5) {
			// it's been a while since we launched it, let's try and
			// launch it again
			if (sys_launch(b, oa)) {
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

void service_exited(struct bus *b, const zb_str8 *name)
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
#endif

////////////////////////////////////
// subscriptions

static int update_bus_sub(struct bus *b, bool add, struct tx *tx,
			  const char *str, struct zb_matcher match,
			  uint32_t serial)
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

int update_sub(struct bus *b, bool add, struct rx *r, const char *str,
	       struct zb_matcher match, uint32_t serial)
{
	struct tx *t = r->tx;
	const zb_str8 *iface = zb_match_interface(str, match);
	const zb_str8 *sender = zb_match_sender(str, match);
	const zb_str8 *mbr = zb_match_member(str, match);
	assert(iface);

	if (zb_eq_str8(iface, BUS_INTERFACE)) {
		if (!zb_path_matches(str, match, BUS_PATH) ||
		    (mbr && !zb_eq_str8(mbr, SIGNAL_NAME_OWNER_CHANGED)) ||
		    (sender && !zb_eq_str8(sender, BUS_DESTINATION))) {
			return ERR_NOT_FOUND;
		}
		return update_bus_sub(b, add, t, str, match, serial);
	}

	// lookup the address in the current RCU data
	const struct rcu_data *od = rcu_root(b->rcu);
	const struct addrmap *om = sender ? od->destinations : od->interfaces;
	const zb_str8 *aname = sender ? sender : iface;
	int aidx = bsearch_address(om, aname);

	struct rcu_object *objs = NULL;
	struct addrmap *nm;

	if (add) {
		const struct address *oa;
		struct address *na;

		if (aidx >= 0) {
			// add a match to an existing address
			oa = om->v[aidx];
			if (oa->cfg &&
			    !has_group(t->sec, oa->cfg->gid_access)) {
				return ERR_NOT_ALLOWED;
			}
			na = edit_address(&objs, oa);

		} else {
			// add a match to a new address
			const struct config *oc = od->config;
			if (!(sender ? oc->allow_unknown_destinations :
				       oc->allow_unknown_interfaces)) {
				return ERR_NOT_ALLOWED;
			}
			oa = NULL;
			aidx = -(aidx + 1);
			na = new_address(aname);
		}

		struct submap *ns = add_subscription(&objs, na->subs, t, str,
						     match, serial);
		na->subs = ns;

		nm = edit_addrmap(&objs, om, aidx, oa ? 0 : 1);
		nm->v[aidx] = na;

	} else {
		// remove the match
		if (aidx < 0) {
			return ERR_NOT_FOUND;
		}
		const struct address *oa = om->v[aidx];
		const struct submap *os = oa->subs;
		int sidx = bsearch_subscription(os, t, str, match);
		if (sidx < 0) {
			return ERR_NOT_FOUND;
		}

		struct submap *ns = rm_subscription(&objs, oa->subs, sidx);

		if (ns || oa->tx || oa->cfg) {
			// we still have a reason to keep the address
			struct address *na = edit_address(&objs, oa);
			na->subs = ns;
			nm = edit_addrmap(&objs, om, aidx, 0);
			nm->v[aidx] = na;
		} else {
			// remove empty address records
			nm = edit_addrmap(&objs, om, aidx, -1);
			collect_address(&objs, oa);
		}
	}

	// hook up the new RCU chain
	struct rcu_data *nd = edit_rcu_data(&objs, od);
	const struct addrmap **pnm = sender ? &nd->destinations :
					      &nd->interfaces;
	*pnm = nm;
	rcu_commit(b->rcu, nd, objs);

	return 0;
}

/////////////////////////////////
// config option processing

static void realloc_str(char **ps, const char *str)
{
	if (str) {
		size_t sz = strlen(str) + 1;
		*ps = memcpy(frealloc(*ps, sz), str, sz);
	} else {
		free(*ps);
		*ps = NULL;
	}
}

static void free_config(struct rcu_object *o)
{
	struct config *c = container_of(o, struct config, rcu);
	if (c) {
		free(c->address);
		free(c->type);
		free(c->listenpn);
#if HAVE_READY_FIFO
		free(c->readypn);
#endif
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
	c->listenpn = NULL;
	c->address = NULL;
	c->type = NULL;
	c->autoexit = false;
#if HAVE_READY_FIFO
	c->readypn = NULL;
#endif
	c->listenfd = -1;
	return c;
}

static struct address *get_address(struct addrtree *t, char *key, size_t klen,
				   size_t *pfxlen)
{
	// key is of the form address.org.example.Service.enabled
	// want to pick out the middle piece. *pfxlen gives the length
	// of the "address." prefix. Pick out the last section and
	// return the length of "address.org.example.Service." in
	// pfxlen.
	char *firstdot = key + *pfxlen;
	char *lastdot = x_memrchr(firstdot, '.', klen - *pfxlen);
	if (!lastdot || lastdot - firstdot > UINT8_MAX) {
		return NULL;
	}
	*pfxlen = lastdot - key + 1;

	// create a str8 for use with the lookup, but save the len and
	// nul bytes so we can restore them after.
	zb_str8 *s = (zb_str8 *)(firstdot - 1);
	size_t slen = lastdot - firstdot;
	uint8_t prevlen = s->len;
	char prevnul = s->p[slen];
	s->len = (uint8_t)slen;
	s->p[slen] = 0;

	struct address *a = insert_addrtree(t, s);

	s->len = prevlen;
	s->p[slen] = prevnul;
	return a;
}

#define CFG_KEY -1
#define CFG_VALUE -2
#define CFG_OVERLONG -3
#define CFG_READ_FILE -4
#define CFG_OPEN_DIR -5
#define CFG_GROUP -6

static int decode_positive_int(const char *val, int *pval)
{
	int n = parse_pos_int(val, pval);
	return (n <= 0 || val[n]) ? CFG_VALUE : 0;
}

static int decode_bool(const char *val, bool *pval)
{
	if (!strcmp(val, "true")) {
		*pval = true;
	} else if (!strcmp(val, "false")) {
		*pval = false;
	} else {
		return CFG_VALUE;
	}
	return 0;
}

static int parse_global_config(struct config *c, const char *key, size_t klen,
			       const char *val)
{
	switch (klen) {
	case 4:
		if (!memcmp(key, "type", 4)) {
			realloc_str(&c->type, val);
			return 0;
		} else {
			return CFG_KEY;
		}

	case 6:
		if (!memcmp(key, "listen", 6)) {
			c->listenfd = -1;
			realloc_str(&c->listenpn, val);
			return 0;
		} else {
			return CFG_KEY;
		}

	case 7:
		if (!memcmp(key, "address", 7)) {
			realloc_str(&c->address, val);
			return 0;
		} else {
			return CFG_KEY;
		}

	case 8:
		if (!memcmp(key, "log_type", 8)) {
			if (!strcmp(val, "json")) {
				g_log_type = LOG_JSON;
			} else if (!strcmp(val, "text")) {
				g_log_type = LOG_TEXT;
			} else {
				return CFG_VALUE;
			}
			return 0;
		} else if (!memcmp(key, "autoexit", 8)) {
			return decode_bool(val, &c->autoexit);
		} else if (!memcmp(key, "listenfd", 8)) {
			realloc_str(&c->listenpn, NULL);
			return decode_positive_int(val, &c->listenfd);
		} else {
			return CFG_KEY;
		}

	case 9:
		if (!memcmp(key, "log_level", 9)) {
			if (!strcmp(val, "debug")) {
				g_log_level = LOG_DEBUG;
			} else if (!strcmp(val, "verbose")) {
				g_log_level = LOG_VERBOSE;
			} else if (!strcmp(val, "notice")) {
				g_log_level = LOG_NOTICE;
			} else if (!strcmp(val, "warning")) {
				g_log_level = LOG_WARNING;
			} else if (!strcmp(val, "error")) {
				g_log_level = LOG_ERROR;
			} else {
				return CFG_VALUE;
			}
			return 0;
		} else {
			return CFG_KEY;
		}

#if HAVE_READY_FIFO
	case 10:
		if (!memcmp(key, "ready_fifo", 10)) {
			realloc_str(&c->readypn, val);
			return 0;
		} else {
			return CFG_KEY;
		}
#endif
	case 23:
		if (!memcmp(key, "allow_unknown_addresses", 23)) {
			return decode_bool(val, &c->allow_unknown_destinations);
		} else {
			return CFG_KEY;
		}
	case 24:
		if (!memcmp(key, "allow_unknown_interfaces", 24)) {
			return decode_bool(val, &c->allow_unknown_interfaces);
		} else {
			return CFG_KEY;
		}
	default:
		return CFG_KEY;
	}
}

#if HAVE_UNIX_GROUPS
static int decode_group(const char *val, int *pgid)
{
	*pgid = lookup_group(val);
	return (*pgid == GROUP_UNKNOWN) ? CFG_VALUE : 0;
}
#endif

static int parse_address_config(struct addrcfg *c, const char *key, size_t klen,
				const char *val)
{
	if (klen == 11 && !memcmp(key, "description", 11)) {
		return 0;

#if ENABLE_AUTOSTART
	} else if (klen == 4 && !memcmp(key, "exec", 4)) {
		realloc_str(&c->exec, val);
		return 0;
#endif

#if HAVE_UNIX_GROUPS
	} else if (klen == 9 && !memcmp(key, "owner_gid", 9)) {
		return decode_positive_int(val, &c->gid_owner);

	} else if (klen == 11 && !memcmp(key, "owner_group", 11)) {
		return decode_group(val, &c->gid_owner);

	} else if (klen == 10 && !memcmp(key, "access_gid", 10)) {
		return decode_positive_int(val, &c->gid_access);

	} else if (klen == 12 && !memcmp(key, "access_group", 12)) {
		return decode_group(val, &c->gid_access);
#endif

	} else {
		return CFG_KEY;
	}
}

static int parse_interface_config(struct addrcfg *c, const char *key,
				  size_t klen, const char *val)
{
	if (klen == 11 && !memcmp(key, "description", 11)) {
		return 0;

#if HAVE_UNIX_GROUPS
	} else if (klen == 13 && !memcmp(key, "subscribe_gid", 13)) {
		return decode_positive_int(val, &c->gid_access);

	} else if (klen == 15 && !memcmp(key, "subscribe_group", 15)) {
		return decode_group(val, &c->gid_access);

	} else if (klen == 11 && !memcmp(key, "publish_gid", 11)) {
		return decode_positive_int(val, &c->gid_owner);

	} else if (klen == 13 && !memcmp(key, "publish_group", 13)) {
		return decode_group(val, &c->gid_owner);
#endif

	} else {
		return CFG_KEY;
	}
}

static bool has_prefix(char *str, size_t len, const char *pfx, size_t plen)
{
	return len >= plen && !memcmp(str, pfx, plen) && len <= UINT8_MAX;
}

struct stack_entry {
	struct ini_reader ini;
	const char *filename;
	char *data;
	struct sysdir *dir;
};

struct parse_stack {
	struct stack_entry v[16];
};

static void init_parser(struct parse_stack *s, const char *key, size_t klen,
			const char *val)
{
	size_t vlen = strlen(val);
	char *kv = fmalloc(klen + 1 + vlen + 1);
	memcpy(kv, key, klen);
	kv[klen] = '=';
	memcpy(kv + klen + 1, val, vlen + 1);
	struct stack_entry *e = &s->v[0];
	init_ini(&e->ini, kv, klen + 1 + vlen);
	e->filename = NULL;
	e->data = kv;
	e->dir = NULL;
}

static int load_file(struct stack_entry *s, const char *file)
{
	char *data;
	size_t sz;
	if (sys_slurp(file, &data, &sz)) {
		return CFG_READ_FILE;
	}
	init_ini(&s->ini, data, sz);
	s->filename = file;
	s->data = data;
	s->dir = NULL;
	return 0;
}

static int load_dir(struct stack_entry *s, const char *pn)
{
	struct sysdir *d;
	if (sys_opendir(&d, pn)) {
		return CFG_OPEN_DIR;
	}
	init_ini(&s->ini, NULL, 0);
	s->filename = NULL;
	s->data = NULL;
	s->dir = d;
	return 0;
}

static void close_file(struct stack_entry *s)
{
	free(s->data);
	sys_closedir(s->dir);
}

static struct stack_entry *next_file(struct stack_entry *s)
{
	free(s->data);

	if (!s->dir) {
		return s - 1;
	}

	struct sysdir *dir = s->dir;
	for (;;) {
		const char *filename = sys_nextfile(dir);
		if (!filename) {
			sys_closedir(dir);
			return s - 1;
		}
		if (load_file(s, filename)) {
			continue;
		}
		s->dir = dir;
		return s;
	}
}

static int do_parse(struct parse_stack *p, struct config *cfg,
		    struct addrtree *taddr, struct addrtree *tiface)
{
	struct stack_entry *s = p->v;
	struct stack_entry *sbot = p->v;
	struct stack_entry *stop = p->v + sizeof(p->v) / sizeof(p->v[0]);

	for (;;) {
		char key[256];
		size_t klen = sizeof(key);
		char *val;
		int sts = read_ini(&s->ini, key, &klen, &val);
		if (sts == INI_EOF) {
			s = next_file(s);
			if (s < sbot) {
				return 0;
			}
			continue;
		} else if (sts != INI_OK) {
			ERROR("parse error,file:%s,line:%d", s->filename,
			      s->ini.lineno);
			break;
		}

		int lineno = s->ini.lineno;
		int err;
		if (klen == strlen("include") &&
		    !memcmp(key, "include", strlen("include"))) {
			if (++s == stop) {
				ERROR("parse include depth too deep");
				break;
			}
			err = load_file(s, val);
		} else if (klen == strlen("includedir") &&
			   !memcmp(key, "includedir", strlen("includedir"))) {
			if (++s == stop) {
				ERROR("parse include depth too deep");
				break;
			}
			err = load_dir(s, val);
		} else if (has_prefix(key, klen, "interface.", 10)) {
			size_t plen = strlen("interface.");
			struct address *a =
				get_address(tiface, key, klen, &plen);
			if (a) {
				err = parse_interface_config(a->cfg, key + plen,
							     klen - plen, val);
			} else {
				err = CFG_OVERLONG;
			}

		} else if (has_prefix(key, klen, "address.", 8)) {
			size_t plen = strlen("address.");
			struct address *a =
				get_address(taddr, key, klen, &plen);
			if (a) {
				err = parse_address_config(a->cfg, key + plen,
							   klen - plen, val);
			} else {
				err = CFG_OVERLONG;
			}

		} else {
			err = parse_global_config(cfg, key, klen, val);
		}

		switch (err) {
		case 0:
			continue;
		case CFG_OPEN_DIR:
			ERROR("failed to open config dir,dir:%s,errno:%m", val);
			return -1;
		case CFG_OVERLONG:
			ERROR("overlong config value,file:%s,line:%d",
			      s->filename, lineno);
			return -1;
		case CFG_KEY:
			ERROR("unknown config key,file:%s,line:%d,key:%s",
			      s->filename, lineno, key);
			return -1;
		case CFG_VALUE:
			ERROR("unknown config value,file:%s,line:%d,key:%s,val:%s",
			      s->filename, lineno, key, val);
			return -1;
		case CFG_GROUP:
			ERROR("failed to lookup group in config file,file:%s,line:%d,group:%s",
			      s->filename, lineno, val);
		default:
			return -1;
		}
	}

	while (s >= sbot) {
		close_file(s--);
	}
	return -1;
}

static void free_tree(struct addrtree *t)
{
	// Use postorder traversal, that is children first and then
	// parent. That way we can safely free the data as we go.

	CRBNode *n = c_rbtree_first_postorder(&t->tree);
	while (n) {
		CRBNode *next = c_rbnode_next_postorder(n);
		struct address *a = node_to_addr(n);
		free_address(a);
		n = next;
	}
}

int load_config(struct bus *b, struct config_arguments *args)
{
	struct config *cfg = new_config();
	struct addrtree taddr, tiface;
	memset(&taddr, 0, sizeof(taddr));
	memset(&tiface, 0, sizeof(tiface));

	for (int i = 0; i < args->num; i++) {
		struct parse_stack s;
		init_parser(&s, args->v[i].key, args->v[i].klen,
			    args->v[i].value);

		if (do_parse(&s, cfg, &taddr, &tiface)) {
			goto error;
		}
	}

	struct rcu_object *objs = NULL;
	struct rcu_object *released = NULL;
	const struct rcu_data *od = rcu_root(b->rcu);
	struct rcu_data *nd = edit_rcu_data(&objs, od);
	rcu_register_gc(&objs, &free_config, &nd->config->rcu);
	nd->config = cfg;
	nd->destinations = merge_addresses(&objs, &released, nd->destinations,
					   &taddr,
					   cfg->allow_unknown_destinations);
	nd->interfaces = merge_addresses(&objs, &objs, nd->interfaces, &tiface,
					 cfg->allow_unknown_interfaces);
	rcu_commit(b->rcu, nd, objs);

	// we consumed the trees and config, so don't need to free them

	// We may have released some names. Need to notify people. The commit
	// above updated the name list so we can now notify about the name
	// changes. Because we kept the address structs out of the collected
	// objects we can still use that data to do the notifications. Just have
	// to collect the address structs when we're done.
	if (!released) {
		return 0;
	}

	for (struct rcu_object *o = released; o != NULL; o = o->next) {
		struct address *a = container_of(o, struct address, rcu);
		if (a->tx) {
			char buf[NAME_OWNER_CHANGED_BUFSZ];
			notify_name_acquired(b, buf, false, a->tx, &a->name);
			notify_name_changed(b, buf, false, a->tx->id, &a->name);
		}
	}

	// now we do another RCU update in order to bump the RCU version and
	// collect the released address structures
	nd = edit_rcu_data(&released, nd);
	rcu_commit(b->rcu, nd, released);

	return 0;

error:
	free_config(&cfg->rcu);
	free_tree(&taddr);
	free_tree(&tiface);
	return -1;
}
