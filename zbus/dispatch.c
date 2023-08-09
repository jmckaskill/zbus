#include "dispatch.h"
#include "rx.h"
#include "busmsg.h"
#include "lib/algo.h"

///////////////////////////////////////////
// Add/RemoveMatch

static int addmatch(struct rx *r, struct message *req, struct iterator *ii)
{
	const struct rcu_data *d = rcu_lock(r->reader);
	int max_names = d->config->max_num_subs;
	rcu_unlock(r->reader);

	if (r->num_subs >= max_names) {
		return ERR_OOM;
	}

	size_t len;
	char *str = parse_string(ii, &len);
	if (iter_error(ii)) {
		return ERR_BAD_ARGUMENT;
	}

	struct match m;
	if (decode_match(&m, str, len)) {
		return ERR_BAD_ARGUMENT;
	}

	if (!m.interface_off) {
		// We do not support fully open matches. Need to specify the
		// interface so we can somewhat whittle down the list.
		return ERR_BAD_ARGUMENT;
	}

	// keep a copy of the subscription for cleanup on exit
	struct subscription *s = new_subscription(str, m);

	mtx_lock(&r->bus->lk);
	int err = update_sub(r->bus, true, r->tx, str, m, req->serial);
	mtx_unlock(&r->bus->lk);

	if (err) {
		free_subscription(&s->h.rcu);
		return err;
	}

	s->h.next = r->subs;
	r->subs = s;
	r->num_subs++;
	return reply_empty(r, req->serial);
}

static int rmmatch(struct rx *r, struct message *req, struct iterator *ii)
{
	size_t len;
	char *str = parse_string(ii, &len);
	if (iter_error(ii)) {
		return ERR_BAD_ARGUMENT;
	}

	// find our local copy
	struct subscription **ps = &r->subs;
	while (*ps && ((*ps)->m.len != len || memcmp((*ps)->mstr, str, len))) {
		ps = &(*ps)->h.next;
	}
	if (!*ps) {
		return ERR_NOT_FOUND;
	}

	// remove it from the bus
	mtx_lock(&r->bus->lk);
	int err = update_sub(r->bus, false, r->tx, str, (*ps)->m, 0);
	mtx_unlock(&r->bus->lk);

	// free our local copy
	struct subscription *s = *ps;
	*ps = s->h.next;
	free_subscription(&s->h.rcu);
	r->num_subs--;

	return err;
}

void rm_all_matches_locked(struct rx *r)
{
	for (struct subscription *s = r->subs; s != NULL;) {
		struct subscription *n = s->h.next;
		update_sub(r->bus, false, r->tx, s->mstr, s->m, 0);
		free_subscription(&s->h.rcu);
		s = n;
	}
	r->num_subs = 0;
	r->subs = NULL;
}

/////////////////////////////////////////
// Broadcasts

#define SIGNAL_HDR_CAP sizeof(((struct rx *)0)->buf)

static int build_signal(struct tx_msg *m)
{
	// keep path
	// keep interface
	// keep member
	m->m.error = NULL;
	m->m.destination = NULL;
	// keep sender - previously overwritten
	// keep signature
	m->m.fdnum = 0;
	m->m.serial = NO_REPLY_SERIAL;
	m->m.reply_serial = 0; // will be overwritten before each send
	assert(m->m.type == MSG_SIGNAL);
	// keep flags

	size_t bsz = m->body[0].len + m->body[1].len;
	int sz = write_header(m->hdr.buf, SIGNAL_HDR_CAP, &m->m, bsz);
	if (sz <= 0) {
		return -1;
	}
	m->hdr.len = sz;
	return 0;
}

static int send_signal(bool iface_checked, const struct submap *subs,
		       struct tx_msg *m)
{
	// signals are required to specify: member, interface & path

	for (int i = 0, n = vector_len(&subs->hdr); i < n; i++) {
		const struct subscription *s = subs->v[i];
		const str8_t *iface = match_interface(s->mstr, s->m);
		const str8_t *mbr = match_member(s->mstr, s->m);

		if (!iface_checked && !str8eq(iface, m->m.interface)) {
			continue;
		}

		if (!str8eq(mbr, m->m.member)) {
			continue;
		}

		if (!path_matches(s->mstr, s->m, m->m.path)) {
			continue;
		}

		if (!m->hdr.len && build_signal(m)) {
			return ERR_OOM;
		}

		set_reply_serial(m->hdr.buf, s->serial);
		send_message(s->tx, false, m);
		// ignore send errors
	}
	return 0;
}

static const struct address *get_address(const struct addrmap *m,
					 const str8_t *name)
{
	int idx = bsearch_address(m, name);
	if (idx < 0) {
		return NULL;
	}
	return m->v[idx];
}

int broadcast(struct rx *r, struct tx_msg *m)
{
	// only encode the header if we have a valid subscription and
	// only encode it once
	static_assert(SIGNAL_HDR_CAP == sizeof(r->buf), "");
	m->hdr.buf = r->buf;
	m->hdr.len = 0;

	// send to broadcast subscriptions
	const struct rcu_data *d = rcu_lock(r->reader);
	const struct address *a = get_address(d->interfaces, m->m.interface);
	if (a && send_signal(true, a->subs, m)) {
		goto error;
	}

	// send to unicast subscriptions

	for (struct rxname **pn = &r->names; *pn; pn = &(*pn)->next) {
		struct rxname *n = *pn;
		const struct address *a =
			get_address(d->destinations, &n->name);
		if (!a || a->tx != r->tx) {
			// we no longer own this name
			*pn = n->next;
			free(n);
			r->num_names--;
			continue;
		} else if (send_signal(false, a->subs, m)) {
			goto error;
		}
	}

	rcu_unlock(r->reader);
	return 0;
error:
	rcu_unlock(r->reader);
	ERROR("error broadcasting signal");
	return ERR_OOM;
}

///////////////////////////////////////////
// Request/ReleaseName

static int addname(struct rx *r, struct message *req, struct iterator *ii)
{
	const str8_t *name = parse_string8(ii);
	if (iter_error(ii)) {
		return ERR_BAD_ARGUMENT;
	}

	const struct rcu_data *d = rcu_lock(r->reader);
	int max_names = d->config->max_num_names;
	rcu_unlock(r->reader);

	if (r->num_names >= max_names) {
		return ERR_OOM;
	}

	// keep a copy of the name for cleanup on exit and sub lookup
	struct rxname *n = fmalloc(sizeof(*n) + name->len);
	str8cpy(&n->name, name);

	// bus methods will send a reply if we don't error
	mtx_lock(&r->bus->lk);
	int err = request_name(r->bus, r, name, req->serial);
	mtx_unlock(&r->bus->lk);

	if (err) {
		free(n);
		return err;
	}

	n->next = r->names;
	r->names = n;
	r->num_names++;

	return 0;
}

static int rmname(struct rx *r, struct message *req, struct iterator *ii)
{
	const str8_t *name = parse_string8(ii);
	if (iter_error(ii)) {
		return ERR_BAD_ARGUMENT;
	}

	// find our local copy
	struct rxname **pn = &r->names;
	while (*pn && !str8eq(&(*pn)->name, name)) {
		pn = &(*pn)->next;
	}
	if (!*pn) {
		return reply_uint32(r, req->serial,
				    DBUS_RELEASE_NAME_REPLY_NOT_OWNER);
	}

	// remove it from the bus
	mtx_lock(&r->bus->lk);
	int err = release_name(r->bus, r, name, req->serial);
	mtx_unlock(&r->bus->lk);

	// free our local copy
	struct rxname *n = *pn;
	*pn = n->next;
	free(n);
	r->num_names--;

	return err;
}

void rm_all_names_locked(struct rx *r)
{
	for (struct rxname *n = r->names; n != NULL;) {
		struct rxname *next = n->next;
		release_name(r->bus, r, &n->name, 0);
		free(n);
		n = next;
	}
	r->names = NULL;
	r->num_names = 0;
}

///////////////////////////////////////////
// ListNames

static int bufsz_names(const struct addrmap *m)
{
	int ret = 0;
	for (int i = 0, n = vector_len(&m->hdr); i < n; i++) {
		const struct address *a = m->v[i];
		if (a->tx) {
			ret += a->name.len + BUFSZ_STRING;
		}
	}
	return ret;
}

static void encode_names(struct builder *b, struct array_data ad,
			 const struct addrmap *m)
{
	for (int i = 0, n = vector_len(&m->hdr); i < n; i++) {
		const struct address *a = m->v[i];
		if (a->tx) {
			start_array_entry(b, ad);
			append_string8(b, &a->name);
		}
	}
}

static int list_names(struct rx *r, uint32_t request_serial)
{
	struct tx_msg m;
	init_message(&m.m, MSG_REPLY, NO_REPLY_SERIAL);
	m.m.reply_serial = request_serial;
	m.m.signature = "as";

	const struct rcu_data *d = rcu_lock(r->reader);
	int bufsz = BUFSZ_REPLY + BUFSZ_ARRAY + bufsz_names(d->destinations);
	char *buf = fmalloc(bufsz);

	struct builder b = start_message(buf, bufsz, &m.m);
	struct array_data ad = start_array(&b);
	encode_names(&b, ad, d->destinations);
	end_array(&b, ad);
	int sz = end_message(b);
	rcu_unlock(r->reader);

	int err = send_data(r->tx, true, &m, buf, sz);
	free(buf);
	return err;
}

static int name_has_owner(struct rx *r, struct message *req,
			  struct iterator *ii)
{
	const str8_t *name = parse_string8(ii);
	if (!name || iter_error(ii)) {
		return ERR_BAD_ARGUMENT;
	}

	const struct rcu_data *d = rcu_lock(r->reader);
	int idx = bsearch_address(d->destinations, name);
	bool res = (idx >= 0) && (d->destinations->v[idx]->tx != NULL);
	rcu_unlock(r->reader);

	return reply_bool(r, req->serial, res);
}

static int get_name_owner(struct rx *r, struct message *req,
			  struct iterator *ii)
{
	const str8_t *name = parse_string8(ii);
	if (!name || iter_error(ii)) {
		return ERR_BAD_ARGUMENT;
	}

	struct tx_msg m;
	init_message(&m.m, MSG_REPLY, NO_REPLY_SERIAL);
	m.m.reply_serial = req->serial;
	m.m.signature = "s";

	struct builder b = start_message(r->buf, sizeof(r->buf), &m.m);

	const struct rcu_data *d = rcu_lock(r->reader);
	int idx = bsearch_address(d->destinations, name);
	int err = 0;
	if (idx >= 0 && d->destinations->v[idx]->tx) {
		append_id_address(&b, txid(d->destinations->v[idx]->tx));
	} else {
		err = ERR_NAME_HAS_NO_OWNER;
	}
	rcu_unlock(r->reader);

	if (err) {
		return err;
	}

	int sz = end_message(b);
	return send_data(r->tx, false, &m, r->buf, sz);
}

///////////////////////////////////
// Bus dispatch

int bus_method(struct rx *r, struct message *m, struct iterator *ii)
{
	// methods are guarenteed to have a valid path, member, and
	// serial. interface may be unspecified

	if (!str8eq(m->path, BUS_PATH)) {
		// we don't support method calls on the bus on anything but the
		// bus path
		return ERR_NOT_FOUND;
	}

	if (!m->interface || str8eq(m->interface, BUS_INTERFACE)) {
		switch (m->member->len) {
		case 5:
			if (str8eq(m->member, METHOD_GET_ID)) {
			} else if (str8eq(m->member, METHOD_HELLO)) {
				return reply_string(r, m->serial, &r->addr);
			}
			break;
		case 8:
			if (str8eq(m->member, METHOD_ADD_MATCH)) {
				return addmatch(r, m, ii);
			}
			break;
		case 9:
			if (str8eq(m->member, METHOD_LIST_NAMES)) {
				return list_names(r, m->serial);
			}
			break;
		case 11:
			if (str8eq(m->member, METHOD_REMOVE_MATCH)) {
				return rmmatch(r, m, ii);
			} else if (str8eq(m->member, METHOD_REQUEST_NAME)) {
				return addname(r, m, ii);
			} else if (str8eq(m->member, METHOD_RELEASE_NAME)) {
				return rmname(r, m, ii);
			}
			break;
		case 12:
			if (str8eq(m->member, METHOD_GET_NAME_OWNER)) {
				return get_name_owner(r, m, ii);
			} else if (str8eq(m->member, METHOD_NAME_HAS_OWNER)) {
				return name_has_owner(r, m, ii);
			}
			break;
		case 16:

			if (str8eq(m->member, METHOD_LIST_QUEUED_OWNERS)) {
			}
			break;
		case 18:

			if (str8eq(m->member, METHOD_START_SERVICE)) {
			}
			break;
		case 20:

			if (str8eq(m->member, METHOD_LIST_ACTIVATABLE_NAMES)) {
			}
			break;
		case 21:

			if (str8eq(m->member, METHOD_GET_UNIX_USER)) {
			}
			break;
		case 22:

			if (str8eq(m->member, METHOD_GET_ADT)) {
			}
			break;
		case 24:

			if (str8eq(m->member, METHOD_GET_CREDENTIALS)) {
			}
			break;
		case 26:

			if (str8eq(m->member, METHOD_GET_UNIX_PROCESS_ID)) {
			}
			break;
		case 27:

			if (str8eq(m->member, METHOD_UPDATE_ENVIRONMENT)) {
			}
			break;
		case 35:

			if (str8eq(m->member, METHOD_GET_SELINUX)) {
			}
			break;
		}

	} else if (str8eq(m->interface, MONITORING_INTERFACE)) {
	}
	return ERR_NOT_FOUND;
}

int peer_method(struct rx *r, struct message *m)
{
	// for methods, path, member & serial are required
	// interface is optional
	if (!m->interface || str8eq(m->interface, PEER_INTERFACE)) {
		if (str8eq(m->member, METHOD_PING)) {
			return reply_empty(r, m->serial);
		}
	}
	return ERR_NOT_FOUND;
}

/////////////////////////////////
// Unicast signals and requests

static int ref_named_tx(struct rx *r, const str8_t *name, bool should_autostart,
			struct tx **ptx)
{
	struct tx *tx = NULL;
	bool activatable = false;

	{
		const struct rcu_data *d = rcu_lock(r->reader);
		int idx = bsearch_address(d->destinations, name);
		if (idx >= 0) {
			const struct address *a = d->destinations->v[idx];
			activatable = a->activatable;
			if (a->tx) {
				tx = a->tx;
				ref_tx(tx);
			}
		}
		rcu_unlock(r->reader);
	}

	if (tx || !should_autostart || !activatable) {
		*ptx = tx;
		return tx ? 0 : ERR_NO_REMOTE;
	}

	mtx_lock(&r->bus->lk);
	const struct address *addr;
	int err = autolaunch_service(r->bus, name, &addr);
	if (!err) {
		*ptx = addr->tx;
		ref_tx(*ptx);
	}
	mtx_unlock(&r->bus->lk);

	return err;
}

int unicast(struct rx *r, struct tx_msg *m)
{
	struct tx *tx;
	bool should_autostart = (m->m.flags & FLAG_NO_AUTO_START) == 0;
	int err = ref_named_tx(r, m->m.destination, should_autostart, &tx);
	if (err) {
		return err;
	}

	// rewrite the header
	// keep path
	// keep interface
	// keep member
	m->m.error = NULL;
	m->m.destination = NULL;
	// keep sender - previously overwritten
	// keep signature
	m->m.fdnum = 0;
	m->m.serial = NO_REPLY_SERIAL; // this may get overwritten later
	m->m.flags &= FLAG_MASK;

	size_t bsz = m->body[0].len + m->body[1].len;
	int sz = write_header(r->buf, sizeof(r->buf), &m->m, bsz);
	if (sz < 0) {
		return -1;
	}
	m->hdr.buf = r->buf;
	m->hdr.len = sz;
	// keep body[0] and body[1]

	if (m->m.type == MSG_METHOD && !(m->m.flags & FLAG_NO_REPLY_EXPECTED)) {
		err = route_request(r, tx, m);
	} else {
		err = send_message(tx, true, m);
	}
	deref_tx(tx);
	return err;
}

int build_reply(struct rx *r, struct tx_msg *m)
{
	assert(m->m.reply_serial &&
	       (m->m.type == MSG_REPLY || m->m.type == MSG_ERROR));

	// rewrite the header, updating and filtering fields
	m->m.path = NULL;
	m->m.interface = NULL;
	m->m.member = NULL;
	if (m->m.type != MSG_ERROR) {
		m->m.error = NULL;
	}
	m->m.destination = NULL;
	// keep sender - previously overwritten
	// keep signature
	m->m.fdnum = 0;
	m->m.serial = NO_REPLY_SERIAL;
	// keep reply_serial - will be overwritten later
	m->m.flags &= FLAG_MASK;

	size_t bsz = m->body[0].len + m->body[1].len;
	int sz = write_header(r->buf, sizeof(r->buf), &m->m, bsz);

	m->hdr.buf = r->buf;
	m->hdr.len = sz;
	// keep body[0] and body[1]

	return sz > 0;
}
