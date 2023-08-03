#include "dispatch.h"
#include "rx.h"
#include "busmsg.h"
#include "dmem/common.h"

///////////////////////////////////////////
// Add/RemoveMatch

static int addrm_match(struct rx *r, const struct message *req,
		       struct iterator *ii, bool add)
{
	slice_t mstr = parse_string(ii);
	if (iter_error(ii)) {
		return ERR_BAD_ARGUMENT;
	}

	struct match m;
	if (decode_match(&m, mstr.p, mstr.len)) {
		return ERR_BAD_ARGUMENT;
	}

	slice_t iface = match_interface(&m);
	if (!iface.len) {
		// we require that the interface is specified for matches as
		// this is used as the sort key for the subscription map
		return ERR_BAD_ARGUMENT;
	}

	int err;
	mtx_lock(&r->bus->lk);

	if (slice_eq(iface, BUS_INTERFACE)) {
		if (path_matches(&m, BUS_PATH) &&
		    member_matches(&m, SIGNAL_NAME_OWNER_CHANGED)) {
			err = update_bus_sub(r->bus, add, r->tx, &m,
					     req->serial, &r->subs);
		} else {
			err = ERR_NOT_FOUND;
		}

	} else if (!m.sender_len) {
		err = update_bcast_sub(r->bus, add, r->tx, &m, req->serial,
				       &r->subs);

	} else {
		err = update_ucast_sub(r->bus, add, r->tx, &m, req->serial,
				       &r->subs);
	}

	mtx_unlock(&r->bus->lk);

	return err ? err : reply_empty(r->tx, req->serial);
}

void rm_all_matches_locked(struct rx *r)
{
	for (struct circ_list *ii = r->subs.next; ii != &r->subs;) {
		struct circ_list *n = ii->next;
		struct subscription *s =
			container_of(ii, struct subscription, owner);
		slice_t src = match_sender(&s->match);
		if (!src.len) {
			update_bcast_sub(r->bus, false, r->tx, &s->match, 0,
					 NULL);
		} else if (slice_eq(src, BUS_DESTINATION)) {
			update_bus_sub(r->bus, false, r->tx, &s->match, 0,
				       NULL);
		} else {
			update_ucast_sub(r->bus, false, r->tx, &s->match, 0,
					 NULL);
		}
		ii = n;
	}
}

/////////////////////////////////////////
// Broadcasts

struct cached_signal {
	char buf[255];
	struct rope rope;
	slice_t src;
	size_t bodysz;
};

static int build_signal(struct cached_signal *c, const struct message *m)
{
	struct message n;
	init_message(&n, MSG_SIGNAL, NO_REPLY_SERIAL);
	n.path = m->path;
	n.interface = m->interface;
	n.member = m->member;
	// leave error blank
	// leave destination blank
	n.sender = c->src;
	n.signature = m->signature;
	// leave fdnum blank
	// add a dummy reply serial that we'll overwrite for each publish
	n.reply_serial = UINT32_MAX;
	n.flags = m->flags;
	size_t bodysz = rope_size(c->rope.next);
	int sz = write_header(c->buf, sizeof(c->buf), &n, bodysz);
	if (sz < 0) {
		return -1;
	}
	c->rope.data.p = c->buf;
	c->rope.data.len = sz;
	return 0;
}

static int send_broadcast(struct subscription_map *s, const struct message *m,
			  struct cached_signal *c)
{
	struct subscription **v;
	int n = find_subscriptions(s, m->interface, &v);
	for (int i = 0; i < n; i++) {
		// have already checked sender & interface
		if (!member_matches(&v[i]->match, m->member) ||
		    !path_matches(&v[i]->match, m->path)) {
			continue;
		}

		if (!c->rope.data.len && build_signal(c, m)) {
			return ERR_OOM;
		}

		set_reply_serial(c->buf, v[i]->serial);
		send_rope(v[i]->tx, false, &c->rope);
	}
	return 0;
}

static void broadcast(struct rx *r, const struct message *m, struct rope *body)
{
	// only encode the header if we have a valid subscription and only
	// encode it once
	struct cached_signal c;
	c.rope.next = body;
	c.rope.data.len = 0;
	c.src = to_slice(r->addr);

	// send to broadcast subscriptions
	struct rcu_names *d = rcu_lock(r->names);
	int err = send_broadcast(d->broadcast, m, &c);
	rcu_unlock(r->names);
	if (err) {
		goto error;
	}

	// send to unicast subscriptions
	for (struct circ_list *ii = r->owned.next; ii != &r->owned;
	     ii = ii->next) {
		struct address *a =
			container_of(ii, struct address, owner_list);
		struct subscription_map *s = rcu_lock(a->subs_reader);
		int err = send_broadcast(s, m, &c);
		rcu_unlock(a->subs_reader);
		if (err) {
			goto error;
		}
	}

	return;
error:
	ERROR("error broadcasting signal");
}

///////////////////////////////////////////
// Request/ReleaseName

static int addrm_name(struct rx *r, const struct message *req,
		      struct iterator *ii, bool add)
{
	slice_t name = parse_string(ii);
	if (iter_error(ii)) {
		return ERR_BAD_ARGUMENT;
	}

	mtx_lock(&r->bus->lk);
	int sts = add ? request_name(r->bus, name, rxid(r), r->tx, &r->owned) :
			release_name(r->bus, name, rxid(r), r->tx);
	mtx_unlock(&r->bus->lk);

	int err = sts < 0 ? sts : reply_uint32(r->tx, req->serial, sts);
	if (err) {
		return err;
	} else if (sts != 1) {
		return 0;
	}

	// send the NameAcquired/NameLost Signal
	char buf[256];
	struct message m;
	init_message(&m, MSG_SIGNAL, NO_REPLY_SERIAL);
	m.path = BUS_PATH;
	m.interface = BUS_INTERFACE;
	m.member = add ? SIGNAL_NAME_ACQUIRED : SIGNAL_NAME_LOST;
	// leave error blank
	// leave destination blank
	m.sender = BUS_DESTINATION;
	m.signature = "s";
	// leave fdnum as 0
	// leave reply_serial as 0
	m.flags = FLAG_NO_REPLY_EXPECTED;

	struct builder b = start_message(buf, sizeof(buf), &m);
	append_string(&b, name);
	int sz = end_message(b);
	if (sz < 0) {
		return ERR_OOM;
	}
	return send_data(r->tx, true, buf, sz);
}

void rm_all_names_locked(struct rx *r)
{
	for (struct circ_list *ii = r->owned.next; ii != &r->owned;) {
		struct circ_list *n = ii->next;
		struct address *a =
			container_of(ii, struct address, owner_list);
		if (a->tx) {
			release_name(r->bus, to_slice(a->name), rxid(r), r->tx);
		}
		ii = n;
	}
}

///////////////////////////////////////////
// ListNames

static int bufsz_names(struct address_map *m)
{
	int ret = 0;
	int n = m ? m->len : 0;
	for (int i = 0; i < n; i++) {
		struct address *a = m->v[i];
		if (a->tx) {
			ret += a->name.len + BUFSZ_STRING;
		}
	}
	return ret;
}

static void encode_names(struct builder *b, struct array_data ad,
			 struct address_map *m)
{
	int n = m ? m->len : 0;
	for (int i = 0; i < n; i++) {
		if (m->v[i]->tx) {
			start_array_entry(b, ad);
			append_string(b, to_slice(m->v[i]->name));
		}
	}
}

static int list_names(struct rx *r, struct rcu_names *n,
		      uint32_t request_serial)
{
	struct message m;
	init_message(&m, MSG_REPLY, NO_REPLY_SERIAL);
	m.flags = FLAG_NO_REPLY_EXPECTED;
	m.reply_serial = request_serial;
	m.signature = "as";

	int bufsz = BUFSZ_REPLY + BUFSZ_ARRAY + bufsz_names(n->named) +
		    bufsz_names(n->unique);

	char *buf = malloc(bufsz);
	if (!buf) {
		return ERR_OOM;
	}

	struct builder b = start_message(buf, bufsz, &m);
	struct array_data ad = start_array(&b);
	encode_names(&b, ad, n->named);
	encode_names(&b, ad, n->unique);
	end_array(&b, ad);
	int sz = end_message(b);
	int err = (sz < 0) ? ERR_OOM : send_data(r->tx, true, buf, sz);
	free(buf);
	return err;
}

///////////////////////////////////
// Bus dispatch

static int bus_method(struct rx *r, const struct message *m,
		      struct iterator *ii)
{
	if (slice_eq(m->path, BUS_PATH) &&
	    slice_eq(m->interface, BUS_INTERFACE)) {
		switch (m->member.len) {
		case 5:
			if (slice_eq(m->member, METHOD_GET_ID)) {
			} else if (slice_eq(m->member, METHOD_HELLO)) {
				return reply_string(r->tx, m->serial,
						    to_slice(r->addr));
			}
			break;
		case 8:
			if (slice_eq(m->member, METHOD_ADD_MATCH)) {
				return addrm_match(r, m, ii, true);
			}
			break;
		case 9:
			if (slice_eq(m->member, METHOD_LIST_NAMES)) {
				struct rcu_names *d = rcu_lock(r->names);
				int err = list_names(r, d, m->serial);
				rcu_unlock(r->names);
				return err;
			}
			break;
		case 11:
			if (slice_eq(m->member, METHOD_REMOVE_MATCH)) {
				return addrm_match(r, m, ii, true);
			} else if (slice_eq(m->member, METHOD_REQUEST_NAME)) {
				return addrm_name(r, m, ii, true);
			} else if (slice_eq(m->member, METHOD_RELEASE_NAME)) {
				return addrm_name(r, m, ii, false);
			}
			break;
		case 12:
			if (slice_eq(m->member, METHOD_GET_NAME_OWNER)) {
			} else if (slice_eq(m->member, METHOD_NAME_HAS_OWNER)) {
			}
			break;
		case 16:

			if (slice_eq(m->member, METHOD_LIST_QUEUED_OWNERS)) {
			}
			break;
		case 18:

			if (slice_eq(m->member, METHOD_START_SERVICE)) {
			}
			break;
		case 20:

			if (slice_eq(m->member,
				     METHOD_LIST_ACTIVATABLE_NAMES)) {
			}
			break;
		case 21:

			if (slice_eq(m->member, METHOD_GET_UNIX_USER)) {
			}
			break;
		case 22:

			if (slice_eq(m->member, METHOD_GET_ADT)) {
			}
			break;
		case 24:

			if (slice_eq(m->member, METHOD_GET_CREDENTIALS)) {
			}
			break;
		case 26:

			if (slice_eq(m->member, METHOD_GET_UNIX_PROCESS_ID)) {
			}
			break;
		case 27:

			if (slice_eq(m->member, METHOD_UPDATE_ENVIRONMENT)) {
			}
			break;
		case 35:

			if (slice_eq(m->member, METHOD_GET_SELINUX)) {
			}
			break;
		}

	} else if (slice_eq(m->interface, MONITORING_INTERFACE)) {
	}
	return ERR_NOT_FOUND;
}

static int peer_method(struct rx *r, const struct message *m, struct rope *body)
{
	if (slice_eq(m->interface, PEER_INTERFACE)) {
		if (slice_eq(m->member, METHOD_PING)) {
			return reply_empty(r->tx, m->serial);
		}
	}
	return ERR_NOT_FOUND;
}

/////////////////////////////////
// Unicast signals and requests

static int ref_unique_tx(struct rx *r, int id, struct tx **ptx)
{
	struct rcu_names *d = rcu_lock(r->names);
	int idx = find_unique_address(d->unique, id);
	if (idx >= 0) {
		*ptx = d->unique->v[idx]->tx;
		ref_tx(*ptx);
	}
	rcu_unlock(r->names);
	return *ptx ? 0 : ERR_NO_REMOTE;
}

static int ref_named_tx(struct rx *r, slice_t name, bool should_autostart,
			struct tx **ptx)
{
	struct tx *tx = NULL;
	struct rcu_names *d = rcu_lock(r->names);
	int idx = find_named_address(d->named, name);
	bool can_autostart = false;
	int err = ERR_NO_REMOTE;
	if (idx >= 0) {
		struct address *a = d->named->v[idx];
		can_autostart = a->autostart != NULL;
		if (a->tx) {
			tx = a->tx;
			ref_tx(tx);
		}
	}
	rcu_unlock(r->names);
	if (tx || !should_autostart || !can_autostart) {
		*ptx = tx;
		return tx ? 0 : ERR_NO_REMOTE;
	}

	mtx_lock(&r->bus->lk);
	struct address *addr;
	err = autolaunch_service(r->bus, name, &addr);
	if (!err) {
		*ptx = addr->tx;
		ref_tx(*ptx);
	}
	mtx_unlock(&r->bus->lk);
	return err;
}

static int unicast(struct rx *r, const struct message *m, struct rope *b)
{
	slice_t name = m->destination;
	struct tx *tx;
	int err;

	if (slice_has_prefix(name, S(UNIQ_ADDR_PREFIX))) {
		int id = address_to_id(name);
		if (id < 0) {
			return ERR_NO_REMOTE;
		}
		err = ref_unique_tx(r, id, &tx);
	} else {
		bool should_autostart = (m->flags & FLAG_NO_AUTO_START) == 0;
		err = ref_named_tx(r, name, should_autostart, &tx);
	}

	if (err) {
		return err;
	}

	err = send_request(r->tx, tx, to_slice(r->addr), m, b);
	deref_tx(tx);
	return err;
}

int dispatch(struct rx *r, const struct message *m, struct rope *b)
{
	switch (m->type) {
	case MSG_SIGNAL:
		if (!m->destination.len) {
			broadcast(r, m, b);
		} else {
			unicast(r, m, b);
		}
		return 0;
	case MSG_METHOD: {
		int err;
		if (!m->destination.len) {
			err = peer_method(r, m, b);
		} else if (slice_eq(m->destination, BUS_DESTINATION)) {
			if (b->next) {
				// we were unable to defragment the
				// message earlier
				err = ERR_OOM;
			} else {
				struct iterator ii;
				init_iterator(&ii, m->signature, b->data.p,
					      b->data.len);
				err = bus_method(r, m, &ii);
			}
		} else {
			err = unicast(r, m, b);
		}

		if (err && !(m->flags & FLAG_NO_REPLY_EXPECTED)) {
			return reply_error(r->tx, m->serial, err);
		}
		return 0;
	}
	case MSG_REPLY:
	case MSG_ERROR:
		send_reply(r->tx, to_slice(r->addr), m, b);
		return 0;
	default:
		assert(0);
		return -1;
	}
}