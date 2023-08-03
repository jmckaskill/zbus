#include "bus.h"
#include "algo.h"
#include "busmsg.h"
#include "dispatch.h"
#include "lib/decode.h"
#include "dmem/log.h"
#include "dmem/common.h"

int init_bus(struct bus *b)
{
	b->names = NULL;
	if (mtx_init(&b->lk, mtx_plain) != thrd_success) {
		return -1;
	}

	int n = generate_busid(b->busid.p);
	if (n < 0) {
		goto error;
	}
	b->busid.len = (char)n;

	b->names = new_rcu_writer();
	if (!b->names) {
		goto error;
	}
	rcu_update(b->names, calloc(1, sizeof(struct rcu_names)), &free);

	return 0;
error:
	mtx_destroy(&b->lk);
	free_rcu_writer(b->names);
	return -1;
}

void destroy_bus(struct bus *b)
{
	struct rcu_names *od = rcu_root(b->names);
	free_address_map(od->named);
	free_address_map(od->unique);
	free_subscription_map(od->broadcast);
	free_subscription_map(od->name_changed);
	free_rcu_writer(b->names);
	mtx_destroy(&b->lk);
}

static int append_address(struct builder *b, int id, slice_t name)
{
	if (id < 0) {
		append_string(b, name);
	} else {
		size_t sz;
		char *p = start_string(b, &sz);
		if (id < 0) {
			sz = 0;
		} else if (sz < UNIQ_ADDR_MAXLEN) {
			return -1;
		} else {
			sz = id_to_address(p, id);
		}
		finish_string(b, sz);
	}
	return 0;
}

static void notify_name_changed(struct bus *bus, int id, slice_t name,
				int old_owner, int new_owner)
{
	struct rcu_names *d = rcu_root(bus->names);
	struct subscription_map *s = d->name_changed;
	int n = s ? s->len : 0;
	if (!n) {
		return;
	}

	char buf[256];
	struct message m;
	init_message(&m, MSG_SIGNAL, NO_REPLY_SERIAL);
	m.flags = FLAG_NO_REPLY_EXPECTED;
	m.path = BUS_PATH;
	m.interface = BUS_INTERFACE;
	m.member = SIGNAL_NAME_OWNER_CHANGED;
	m.signature = "sss";

	struct builder b = start_message(buf, sizeof(buf), &m);
	if (append_address(&b, id, name)) {
		goto error;
	}
	if (append_address(&b, old_owner, S(""))) {
		goto error;
	}
	if (append_address(&b, new_owner, S(""))) {
		goto error;
	}

	int sz = end_message(b);
	if (sz < 0) {
		goto error;
	}

	for (int i = 0; i < n; i++) {
		send_data(s->v[i]->tx, false, buf, sz);
	}
	return;
error:
	ERROR("failed to create NameOwnerChanged message,name:%.*s",
	      S_PRI(name));
	return;
}

int register_remote(struct bus *b, int id, slice_t name, struct tx *tx,
		    struct circ_list *names, struct rcu_reader **preader)
{
	struct rcu_names *od = rcu_root(b->names);
	struct rcu_names *nd = malloc(sizeof(*nd));
	struct rcu_reader *rd = new_rcu_reader(b->names);
	if (!nd || !rd) {
		goto error;
	}
	*nd = *od;

	// find where to insert the remote by id
	int idx = -(find_unique_address(nd->unique, id) + 1);
	struct address *a = add_address(b->names, &nd->unique, idx, name);
	if (a == NULL) {
		goto error;
	}

	a->owner_id = id;
	a->tx = tx;
	ref_tx(a->tx);
	circ_add(&a->owner_list, names);

	*preader = rd;
	rcu_update(b->names, nd, &free);
	notify_name_changed(b, id, S(""), -1, id);
	return 0;
error:
	free_rcu_reader(b->names, rd);
	free(nd);
	return -1;
}

int unregister_remote(struct bus *b, int id)
{
	struct rcu_names *od = rcu_root(b->names);
	struct rcu_names *nd = malloc(sizeof(*nd));
	if (!nd) {
		goto error;
	}
	*nd = *od;

	int idx = find_unique_address(nd->unique, id);
	if (remove_address(b->names, &nd->unique, idx)) {
		goto error;
	}

	rcu_update(b->names, nd, &free);
	notify_name_changed(b, id, S(""), id, -1);
	return 0;
error:
	free(nd);
	return -1;
}

int add_name(struct bus *b, slice_t name)
{
	struct rcu_names *od = rcu_root(b->names);
	int idx = find_named_address(od->named, name);
	if (idx >= 0) {
		return -1;
	}

	struct rcu_names *nd = malloc(sizeof(*nd));
	if (!nd) {
		return -1;
	}
	*nd = *od;

	struct address *a = add_address(b->names, &nd->named, -(idx + 1), name);
	if (!a) {
		return -1;
	}

	rcu_update(b->names, nd, &free);
	return 0;
}

int request_name(struct bus *b, slice_t name, int id, struct tx *tx,
		 struct circ_list *names)
{
	// lookup the name
	struct rcu_names *od = rcu_root(b->names);
	int idx = find_named_address(od->named, name);
	if (idx < 0) {
		return ERR_NOT_ALLOWED;
	}

	// look to see if there is already an owner
	struct address *oa = od->named->v[idx];
	if (oa->tx == tx) {
		return DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
	} else if (oa->tx) {
		return DBUS_REQUEST_NAME_REPLY_EXISTS;
	}

	struct rcu_names *nd = malloc(sizeof(*nd));
	if (!nd) {
		return ERR_OOM;
	}
	*nd = *od;

	struct address *na = update_address(b->names, &nd->named, idx);
	if (na == NULL) {
		free(nd);
		return ERR_OOM;
	}

	// update this address to point to the new owner
	assert(!na->tx && !na->owner_list.next);
	na->tx = tx;
	na->owner_id = id;
	ref_tx(tx);
	circ_add(&na->owner_list, names);

	// and release the new name list
	rcu_update(b->names, nd, &free);
	notify_name_changed(b, -1, name, -1, id);
	return DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
}

int release_name(struct bus *b, slice_t name, int id, struct tx *tx)
{
	// lookup the name
	struct rcu_names *od = rcu_root(b->names);
	int idx = find_named_address(od->named, name);
	if (idx < 0) {
		return DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
	}

	// look to see if we are the owner
	struct address *oa = od->named->v[idx];
	if (oa->tx != tx) {
		return DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
	}

	struct rcu_names *nd = malloc(sizeof(*nd));
	if (!nd) {
		return ERR_OOM;
	}
	*nd = *od;

	struct address *na = update_address(b->names, &nd->named, idx);
	if (!oa) {
		free(nd);
		return ERR_OOM;
	}

	// remove ourself from the address
	assert(na->tx && na->owner_list.next);
	circ_remove(&na->owner_list);
	deref_tx(na->tx);
	na->tx = NULL;
	na->owner_id = -1;

	// and release the new name list
	rcu_update(b->names, nd, &free);
	notify_name_changed(b, -1, name, id, -1);
	return DBUS_RELEASE_NAME_REPLY_RELEASED;
}

static int update_root_sub(struct bus *b, bool add, struct tx *to,
			   struct match *m, uint32_t serial,
			   struct circ_list *o, int offset)
{
	struct rcu_names *od = rcu_root(b->names);
	struct rcu_names *nd = malloc(sizeof(*nd));
	if (!nd) {
		return ERR_OOM;
	}
	*nd = *od;

	struct subscription_map **pmap = (void *)((char *)nd + offset);
	int err = addrm_subscription(b->names, pmap, add, m, to, serial, o);
	if (err) {
		free(nd);
		return err;
	}

	rcu_update(b->names, nd, &free);
	return 0;
}

int update_bus_sub(struct bus *b, bool add, struct tx *to, struct match *m,
		   uint32_t serial, struct circ_list *o)
{
	return update_root_sub(b, add, to, m, serial, o,
			       offsetof(struct rcu_names, name_changed));
}

int update_bcast_sub(struct bus *b, bool add, struct tx *to, struct match *m,
		     uint32_t serial, struct circ_list *o)
{
	return update_root_sub(b, add, to, m, serial, o,
			       offsetof(struct rcu_names, broadcast));
}

int update_ucast_sub(struct bus *b, bool add, struct tx *to, struct match *m,
		     uint32_t serial, struct circ_list *o)
{
	struct rcu_names *names = rcu_root(b->names);

	struct address_map *map;
	int idx;
	int id;
	slice_t src = match_sender(m);
	if (!slice_has_prefix(src, cstr_slice(UNIQ_ADDR_PREFIX))) {
		map = names->named;
		idx = find_named_address(map, src);
	} else if ((id = address_to_id(src)) > 0) {
		map = names->unique;
		idx = find_named_address(map, src);
	} else {
		return ERR_BAD_ARGUMENT;
	}

	if (idx < 0) {
		return ERR_NOT_FOUND;
	}
	struct address *a = map->v[idx];
	struct subscription_map *os = rcu_root(a->subs_writer);
	struct subscription_map *ns = os;
	int err =
		addrm_subscription(a->subs_writer, &ns, add, m, to, serial, o);
	if (err) {
		return err;
	}
	if (ns != os) {
		rcu_update(a->subs_writer, ns,
			   (rcu_free_fn)&free_subscription_map);
	}

	return 0;
}
