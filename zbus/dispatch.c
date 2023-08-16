#include "dispatch.h"
#include "rx.h"
#include "busmsg.h"
#include "lib/algo.h"

///////////////////////////////////////////
// Add/RemoveMatch

static int addmatch(struct rx *r, struct zb_message *req,
		    struct zb_iterator *ii)
{
	const struct rcu_data *d = rcu_lock(r->reader);
	int max_names = d->config->max_num_subs;
	rcu_unlock(r->reader);

	if (r->num_subs >= max_names) {
		return ERR_OOM;
	}

	size_t len;
	char *str = zb_parse_string(ii, &len);
	if (zb_get_iter_error(ii)) {
		return ERR_BAD_ARGUMENT;
	}

	struct zb_matcher m;
	if (zb_decode_match(&m, str, len)) {
		return ERR_BAD_ARGUMENT;
	}

	if (!m.interface_off) {
		// We do not support fully open matches. Need to specify the
		// interface so we can somewhat whittle down the list.
		return ERR_BAD_ARGUMENT;
	}

	mtx_lock(&r->bus->lk);
	int err = update_sub(r->bus, true, r, str, m, req->serial);
	mtx_unlock(&r->bus->lk);

	if (err) {
		return err;
	}

	// keep a copy of the subscription for cleanup on exit
	struct subscription *s = new_subscription(str, m);
	s->h.next = r->subs;
	r->subs = s;
	r->num_subs++;
	return reply_empty(r, req->serial);
}

static int rmmatch(struct rx *r, struct zb_message *req, struct zb_iterator *ii)
{
	size_t len;
	char *str = zb_parse_string(ii, &len);
	if (zb_get_iter_error(ii)) {
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

	// take a copy of the cached match params to use to remove the match
	struct zb_matcher m = (*ps)->m;

	// free our local copy
	struct subscription *s = *ps;
	*ps = s->h.next;
	free_subscription(s);
	r->num_subs--;

	// remove it from the bus
	mtx_lock(&r->bus->lk);
	int err = update_sub(r->bus, false, r, str, m, 0);
	mtx_unlock(&r->bus->lk);

	return err;
}

void rm_all_matches_locked(struct rx *r)
{
	for (struct subscription *s = r->subs; s != NULL;) {
		struct subscription *n = s->h.next;
		update_sub(r->bus, false, r, s->mstr, s->m, 0);
		free_subscription(s);
		s = n;
	}
	r->num_subs = 0;
	r->subs = NULL;
}

/////////////////////////////////////////
// Broadcasts

static int build_signal(struct txmsg *m)
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
	m->m.reply_serial = 1; // will be overwritten before each send
	assert(m->m.type == ZB_SIGNAL);
	m->m.flags &= ZB_FLAG_MASK;
	// keep body[0] and body[1]
	m->fdsrc = NULL;

	size_t bsz = m->body[0].len + m->body[1].len;
	int sz = zb_write_header(m->hdr.buf, SIGNAL_HDR_BUFSZ, &m->m, bsz);
	if (sz <= 0) {
		return -1;
	}
	m->hdr.len = sz;
	return 0;
}

static int send_signal(bool iface_checked, const struct submap *subs,
		       struct txmsg *m)
{
	// signals are required to specify: member, interface & path
	// matches are required to have: interface

	for (int i = 0, n = vector_len(&subs->hdr); i < n; i++) {
		const struct subscription *s = subs->v[i];
		const zb_str8 *iface = zb_match_interface(s->mstr, s->m);
		const zb_str8 *mbr = zb_match_member(s->mstr, s->m);

		assert(m->m.member && m->m.interface && m->m.path);
		assert(iface);

		if (!iface_checked && !zb_eq_str8(iface, m->m.interface)) {
			continue;
		}

		if (mbr && !zb_eq_str8(mbr, m->m.member)) {
			continue;
		}

		if (!zb_path_matches(s->mstr, s->m, m->m.path)) {
			continue;
		}

		if (!m->hdr.len && build_signal(m)) {
			return ERR_OOM;
		}

		zb_set_reply_serial(m->hdr.buf, s->serial);
		send_message(s->tx, false, m);
		// ignore send errors
	}
	return 0;
}

static const struct address *get_address(const struct addrmap *m,
					 const zb_str8 *name)
{
	int idx = bsearch_address(m, name);
	if (idx < 0) {
		return NULL;
	}
	return m->v[idx];
}

int broadcast(struct rx *r, struct txmsg *m)
{
	// only encode the header if we have a valid subscription and
	// only encode it once
	m->hdr.buf = r->txbuf;
	m->hdr.len = 0;

	// send to broadcast subscriptions
	const struct rcu_data *d = rcu_lock(r->reader);
	const struct address *a = get_address(d->interfaces, m->m.interface);
	if (a && (!a->cfg || has_group(r->tx->sec, a->cfg->gid_owner)) &&
	    send_signal(true, a->subs, m)) {
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

static int addname(struct rx *r, struct zb_message *req, struct zb_iterator *ii)
{
	const zb_str8 *name = zb_parse_str8(ii);
	if (zb_get_iter_error(ii)) {
		return ERR_BAD_ARGUMENT;
	}

	const struct rcu_data *d = rcu_lock(r->reader);
	int max_names = d->config->max_num_names;
	rcu_unlock(r->reader);

	if (r->num_names >= max_names) {
		return ERR_OOM;
	}

	// bus methods will send a reply if we don't error
	mtx_lock(&r->bus->lk);
	int err = request_name(r->bus, r, name, req->serial);
	mtx_unlock(&r->bus->lk);

	if (err) {
		return err;
	}

	// keep a copy of the name for cleanup on exit and sub lookup
	struct rxname *n = fmalloc(sizeof(*n) + name->len);
	zb_copy_str8(&n->name, name);
	n->next = r->names;
	r->names = n;
	r->num_names++;

	return 0;
}

static int rmname(struct rx *r, struct zb_message *req, struct zb_iterator *ii)
{
	const zb_str8 *name = zb_parse_str8(ii);
	if (zb_get_iter_error(ii)) {
		return ERR_BAD_ARGUMENT;
	}

	// find our local copy
	struct rxname **pn = &r->names;
	while (*pn && !zb_eq_str8(&(*pn)->name, name)) {
		pn = &(*pn)->next;
	}
	if (!*pn) {
		return reply_uint32(r, req->serial,
				    DBUS_RELEASE_NAME_REPLY_NOT_OWNER);
	}

	// free our local copy
	struct rxname *n = *pn;
	*pn = n->next;
	free(n);
	r->num_names--;

	// release the name from the bus. This could still return an error if
	// the bus kicked our name out in the interim.
	mtx_lock(&r->bus->lk);
	int err = release_name(r->bus, r, name, req->serial, true);
	mtx_unlock(&r->bus->lk);

	return err;
}

void rm_all_names_locked(struct rx *r)
{
	for (struct rxname *n = r->names; n != NULL;) {
		struct rxname *next = n->next;
		release_name(r->bus, r, &n->name, 0, false);
		free(n);
		n = next;
	}
	r->names = NULL;
	r->num_names = 0;
}

/////////////////////////////////////////
// name lookup

static int ref_named(struct rx *r, const zb_str8 *name, bool should_autostart,
		     struct tx **ptx)
{
	struct tx *tx = NULL;
	int err = ERR_NO_REMOTE;

	if (!name) {
		return ERR_BAD_ARGUMENT;
	}

	{
		const struct rcu_data *d = rcu_lock(r->reader);
		int idx = bsearch_address(d->destinations, name);
		if (idx < 0) {
			err = ERR_NO_REMOTE;
		} else {
			const struct address *a = d->destinations->v[idx];
			if (a->cfg &&
			    !has_group(r->tx->sec, a->cfg->gid_access)) {
				err = ERR_NOT_ALLOWED;
			} else if (a->tx) {
				tx = ref_tx(a->tx);
#if CAN_AUTOSTART
			} else if (a->cfg && a->cfg->exec && should_autostart) {
				err = 0;
#endif
			}
		}
		rcu_unlock(r->reader);
	}

	if (tx) {
		*ptx = tx;
		return 0;
	}

#if CAN_AUTOSTART
	if (err) {
		return err;
	}
	mtx_lock(&r->bus->lk);
	const struct address *a;
	err = autolaunch_service(r->bus, name, &a);
	if (!err) {
		assert(a->tx);
		if (!a->cfg || !has_group(r->tx->sec, a->cfg->gid_access)) {
			// config may have changed while we were launching the
			// service
			err = ERR_NOT_ALLOWED;
		} else {
			*ptx = ref_tx(a->tx);
		}
	}
	mtx_unlock(&r->bus->lk);
#endif

	return err;
}

static int ref_remote(struct rx *r, const zb_str8 *name, struct tx **ptx)
{
	if (!name) {
		return ERR_BAD_ARGUMENT;
	}

	const struct rcu_data *d = rcu_lock(r->reader);
	int id = address_to_id(name);
	int err = 0;
	if (id >= 0) {
		int idx = bsearch_tx(d->remotes, id);
		if (idx >= 0) {
			*ptx = ref_tx(d->remotes->v[idx]);
		} else {
			err = ERR_NO_REMOTE;
		}
	} else {
		int idx = bsearch_address(d->destinations, name);
		if (idx >= 0 && d->destinations->v[idx]->tx) {
			*ptx = ref_tx(d->destinations->v[idx]->tx);
		} else {
			err = ERR_NO_REMOTE;
		}
	}
	rcu_unlock(r->reader);
	return err;
}

///////////////////////////////////////////
// ListNames

#if CAN_AUTOSTART
static void encode_activatable(struct zb_builder *b, struct zb_scope *array,
			       const struct addrmap *m)
{
	for (int i = 0, n = vector_len(&m->hdr); i < n; i++) {
		const struct address *a = m->v[i];
		if (a->cfg && a->cfg->exec) {
			zb_add_array_entry(b, array);
			zb_add_str8(b, &a->name);
		}
	}
}
#endif

static void encode_names(struct zb_builder *b, struct zb_scope *array,
			 const struct addrmap *m)
{
	for (int i = 0, n = vector_len(&m->hdr); i < n; i++) {
		const struct address *a = m->v[i];
		if (a->tx) {
			zb_add_array_entry(b, array);
			zb_add_str8(b, &a->name);
		}
	}
}

static void encode_unique_names(struct zb_builder *b, struct zb_scope *array,
				const struct txmap *m)
{
	for (int i = 0, n = vector_len(&m->hdr); i < n; i++) {
		zb_add_array_entry(b, array);
		append_id_address(b, m->v[i]->id);
	}
}

static int list_names(struct rx *r, uint32_t request_serial, bool activatable)
{
	struct txmsg m;
	zb_init_message(&m.m, ZB_REPLY, NO_REPLY_SERIAL);
	m.m.reply_serial = request_serial;
	m.m.signature = "as";

	struct zb_builder b;
	struct zb_scope array;
	zb_start(&b, r->txbuf, TX_BUFSZ, &m.m);
	zb_start_array(&b, &array);

	const struct rcu_data *d = rcu_lock(r->reader);
	if (!activatable) {
		encode_names(&b, &array, d->destinations);
		encode_unique_names(&b, &array, d->remotes);
#if CAN_AUTOSTART
	} else {
		encode_activatable(&b, &array, d->destinations);
#endif
	}
	rcu_unlock(r->reader);

	zb_end_array(&b, &array);
	int sz = zb_end(&b);
	return send_data(r->tx, true, &m, r->txbuf, sz);
}

///////////////////////////////////
// credentials

static int get_credentials(struct rx *r, uint32_t serial, const zb_str8 *name)
{
	struct tx *tx = NULL;
	int err = ref_remote(r, name, &tx);
	if (err) {
		return err;
	} else if (!tx->sec) {
		deref_tx(tx);
		return ERR_INTERNAL;
	}

	struct security *s = tx->sec;

	struct txmsg m;
	zb_init_message(&m.m, ZB_REPLY, NO_REPLY_SERIAL);
	m.m.reply_serial = serial;
	m.m.signature = "a{sv}";

	struct zb_builder b;
	zb_start(&b, r->txbuf, TX_BUFSZ, &m.m);
	struct zb_scope dict, variant;
	zb_start_dict(&b, &dict);

	zb_add_dict_entry(&b, &dict);
	zb_add_str8(&b, S8("\011ProcessID"));
	zb_start_variant(&b, "u", &variant);
	zb_add_u32(&b, s->pid);
	zb_end_variant(&b, &variant);

#if HAVE_WINDOWS_SID
	zb_add_dict_entry(&b, &dict);
	zb_add_str8(&b, S8("\012WindowsSID"));
	zb_start_variant(&b, "s", &variant);
	zb_add_string(&b, s->sid, strlen(s->sid));
	zb_end_variant(&b, &variant);
#endif

#if HAVE_UNIX_GROUPS
	zb_add_dict_entry(&b, &dict);
	zb_add_str8(&b, S8("\012UnixUserID"));
	zb_start_variant(&b, "u", &variant);
	zb_add_u32(&b, s->uid);
	zb_end_variant(&b, &variant);

	zb_add_dict_entry(&b, dd);
	zb_add_str8(&b, S8("\014UnixGroupIDs"));
	zb_start_variant(&b, "au", &variant);
	struct zb_scope array;
	zb_start_array(&b, &array);
	for (int i = 0; i < s->groups.n; i++) {
		zb_add_array_entry(&b, &array);
		zb_add_u32(&b, s->groups.v[i]);
	}
	zb_end_array(&b, &array);
	zb_end_variant(&b, &variant);
#endif

	zb_end_dict(&b, &dict);

	deref_tx(tx);
	int sz = zb_end(&b);
	return send_data(r->tx, true, &m, r->txbuf, sz);
}

static int get_sec_u32(struct rx *r, uint32_t serial, const zb_str8 *name,
		       size_t offset)
{
	struct tx *tx = NULL;
	int err = ref_remote(r, name, &tx);
	if (err) {
		return err;
	} else if (!tx->sec) {
		deref_tx(tx);
		return ERR_INTERNAL;
	}
	uint32_t id = *(uint32_t *)((char *)(tx->sec) + offset);
	deref_tx(tx);
	return reply_uint32(r, serial, id);
}

///////////////////////////////////
// Bus dispatch

int bus_method(struct rx *r, struct zb_message *m, struct zb_iterator *ii)
{
	// methods are guarenteed to have a valid path, member, interface and
	// serial

	if (!zb_eq_str8(m->path, BUS_PATH)) {
		// we don't support method calls on the bus on anything but the
		// bus path
		return ERR_NOT_FOUND;
	}

	if (zb_eq_str8(m->interface, BUS_INTERFACE)) {
		switch (m->member->len) {
		case 5:
			if (zb_eq_str8(m->member, METHOD_GET_ID)) {
				return reply_string(r, m->serial,
						    &r->bus->busid);
			} else if (zb_eq_str8(m->member, METHOD_HELLO)) {
				return reply_string(r, m->serial, &r->addr);
			}
			break;
		case 8:
			if (zb_eq_str8(m->member, METHOD_ADD_MATCH)) {
				return addmatch(r, m, ii);
			}
			break;
		case 9:
			if (zb_eq_str8(m->member, METHOD_LIST_NAMES)) {
				return list_names(r, m->serial, false);
			}
			break;
		case 11:
			if (zb_eq_str8(m->member, METHOD_REMOVE_MATCH)) {
				return rmmatch(r, m, ii);
			} else if (zb_eq_str8(m->member, METHOD_REQUEST_NAME)) {
				return addname(r, m, ii);
			} else if (zb_eq_str8(m->member, METHOD_RELEASE_NAME)) {
				return rmname(r, m, ii);
			}
			break;
		case 12:
			if (zb_eq_str8(m->member, METHOD_GET_NAME_OWNER)) {
				struct tx *tx = NULL;
				int err = ref_remote(r, zb_parse_str8(ii), &tx);
				if (!err) {
					err = reply_id_address(r, m->serial,
							       tx->id);
					deref_tx(tx);
				}
				return err;

			} else if (zb_eq_str8(m->member,
					      METHOD_NAME_HAS_OWNER)) {
				struct tx *tx = NULL;
				int err = ref_remote(r, zb_parse_str8(ii), &tx);
				deref_tx(tx);
				return reply_bool(r, m->serial, err == 0);
			}
			break;
		case 16:

			if (zb_eq_str8(m->member, METHOD_LIST_QUEUED_OWNERS)) {
				return ERR_NOT_SUPPORTED;
			}
			break;
		case 18:

			if (zb_eq_str8(m->member, METHOD_START_SERVICE)) {
				struct tx *tx = NULL;
				int err = ref_named(r, zb_parse_str8(ii), true,
						    &tx);
				deref_tx(tx);
				return err;
			}
			break;
		case 20:

			if (zb_eq_str8(m->member,
				       METHOD_LIST_ACTIVATABLE_NAMES)) {
				return list_names(r, m->serial, true);
			}
			break;
		case 21:

			if (zb_eq_str8(m->member, METHOD_GET_UNIX_USER)) {
#if HAVE_UNIX_GROUPS
				return get_sec_u32(
					r, m->serial, zb_parse_str8(ii),
					offsetof(struct security, uid));
#else
				return ERR_NOT_SUPPORTED;
#endif
			}
			break;
		case 22:

			if (zb_eq_str8(m->member, METHOD_GET_ADT)) {
				return ERR_NOT_SUPPORTED;
			}
			break;
		case 24:

			if (zb_eq_str8(m->member, METHOD_GET_CREDENTIALS)) {
				return get_credentials(r, m->serial,
						       zb_parse_str8(ii));
			}
			break;
		case 26:

			if (zb_eq_str8(m->member, METHOD_GET_UNIX_PROCESS_ID)) {
				return get_sec_u32(
					r, m->serial, zb_parse_str8(ii),
					offsetof(struct security, pid));
			}
			break;
		case 27:

			if (zb_eq_str8(m->member, METHOD_UPDATE_ENVIRONMENT)) {
				return ERR_NOT_SUPPORTED;
			}
			break;
		case 35:

			if (zb_eq_str8(m->member, METHOD_GET_SELINUX)) {
				return ERR_NOT_SUPPORTED;
			}
			break;
		}

	} else if (zb_eq_str8(m->interface, MONITORING_INTERFACE)) {
		return ERR_NOT_SUPPORTED;
	}
	return ERR_NOT_FOUND;
}

int peer_method(struct rx *r, struct zb_message *m)
{
	// for methods, path, member & serial are required
	// interface is optional
	if (!m->interface || zb_eq_str8(m->interface, PEER_INTERFACE)) {
		if (zb_eq_str8(m->member, METHOD_PING)) {
			return reply_empty(r, m->serial);
		}
	}
	return ERR_NOT_FOUND;
}

/////////////////////////////////
// Unicast signals and requests

int unicast(struct rx *r, struct txmsg *m)
{
	struct tx *tx;
	bool should_autostart = (m->m.flags & ZB_NO_AUTO_START) == 0;
	int err = ref_named(r, m->m.destination, should_autostart, &tx);
	if (err) {
		return err;
	}

	bool is_request = m->m.type == ZB_METHOD &&
			  !(m->m.flags & ZB_NO_REPLY_EXPECTED);

	// rewrite the header
	// keep path
	// keep interface
	// keep member
	m->m.error = NULL;
	m->m.destination = NULL;
	// keep sender - previously overwritten
	// keep signature
	// keep fdnum
	// keep serial for requests - it will get overwritten later
	if (!is_request) {
		m->m.serial = NO_REPLY_SERIAL;
	}
	m->m.flags &= ZB_FLAG_MASK;

	size_t bsz = m->body[0].len + m->body[1].len;
	int sz = zb_write_header(r->txbuf, TX_BUFSZ, &m->m, bsz);
	if (sz < 0) {
		deref_tx(tx);
		return -1;
	}

	m->hdr.buf = r->txbuf;
	m->hdr.len = sz;
	// keep body[0], body[1]
	m->fdsrc = &r->conn;

	if (is_request) {
		err = route_request(r, tx, m);
	} else {
		err = send_message(tx, true, m);
	}
	deref_tx(tx);
	return err;
}

int build_reply(struct rx *r, struct txmsg *m)
{
	assert(m->m.reply_serial &&
	       (m->m.type == ZB_REPLY || m->m.type == ZB_ERROR));

	// rewrite the header, updating and filtering fields
	m->m.path = NULL;
	m->m.interface = NULL;
	m->m.member = NULL;
	if (m->m.type != ZB_ERROR) {
		m->m.error = NULL;
	}
	m->m.destination = NULL;
	// keep sender - previously overwritten
	// keep signature
	// keep fdnum
	m->m.serial = NO_REPLY_SERIAL;
	// keep reply_serial - will be overwritten later
	m->m.flags &= ZB_FLAG_MASK;

	size_t bsz = m->body[0].len + m->body[1].len;
	int sz = zb_write_header(r->txbuf, TX_BUFSZ, &m->m, bsz);
	if (sz < 0) {
		return -1;
	}

	m->hdr.buf = r->txbuf;
	m->hdr.len = sz;
	// keep body[0], body[1]
	m->fdsrc = &r->conn;

	return 0;
}
