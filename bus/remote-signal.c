#include "remote.h"
#include "bus.h"
#include "rcu.h"
#include "lib/log.h"
#include "lib/match.h"
#include "lib/decode.h"

#define NAME_OWNER_CHANGED S("NameOwnerChanged")

///////////////////////////
// Match processing

static int update_name_changed_match(struct remote *r, struct match *m,
				     uint32_t serial, bool add)
{
	struct cmd_name_sub cn;
	cn.add = add;
	cn.serial = serial;
	cn.q = r->qdata;
	if (!slice_eq(match_interface(m), BUS_INTERFACE) ||
	    !path_matches(m, BUS_PATH) ||
	    !member_matches(m, NAME_OWNER_CHANGED)) {
		return STS_NOT_SUPPORTED;
	} else {
		msgq_send(r->busq, CMD_UPDATE_NAME_SUB, &cn, sizeof(cn), NULL);
		return 0;
	}
}

static int send_match_update(struct remote *r, struct msgq *to, struct match *m,
			     uint32_t serial, bool add)
{
	struct cmd_update_sub c;
	c.add = add;
	c.serial = serial;
	c.remote = r;
	c.s.m = *m;
	c.s.remote_id = r->id;
	if (msgq_send(to, CMD_UPDATE_SUB, &c, sizeof(c), &gc_update_sub)) {
		return STS_REMOTE_FAILED;
	}
	ref_paged_data(c.s.m.base);
	return 0;
}

static int update_unique_match(struct remote *r, struct match *m,
			       uint32_t serial, bool add)
{
	int err;
	struct rcu *d = rcu_lock(r->handle);
	struct remote *to = lookup_unique_name(d, match_sender(m));
	if (!to) {
		err = STS_NO_REMOTE;
	} else {
		err = send_match_update(r, to->qcontrol, m, serial, add);
	}
	rcu_unlock(r->handle);
	return err;
}

static int update_bus_match(struct remote *r, struct match *m, uint32_t serial,
			    bool add)
{
	struct rcu *d = rcu_lock(r->handle);
	struct bus_name *n = lookup_bus_name(d, match_sender(m));
	if (!n) {
		rcu_unlock(r->handle);
		return STS_NO_REMOTE;
	}

	// send to the current owner if we can
	if (n->owner) {
		send_match_update(r, n->owner->qcontrol, m, serial, add);
	}

	// and register for name change events so we can track the name
	int cnt = add ? r->bus_name_match_num++ : --r->bus_name_match_num;
	if (cnt == 0) {
		struct cmd_name_sub cn;
		cn.add = add;
		cn.q = r->qcontrol;
		cn.serial = 0;
		msgq_send(r->busq, CMD_UPDATE_NAME_SUB, &cn, sizeof(cn), NULL);
	}

	rcu_unlock(r->handle);
	return 0;
}

void update_bus_matches(struct remote *r, slice_t sender)
{
	struct rcu *d = rcu_lock(r->handle);
	struct bus_name *n = lookup_bus_name(d, sender);
	if (!n->owner) {
		// the name has already been released again
		goto end;
	}

	struct msgq *q = n->owner->qcontrol;

	for (int i = 0; i < r->match_num; i++) {
		struct match *m = &r->matches[i];
		if (slice_eq(match_sender(m), sender)) {
			send_match_update(r, q, m, 0, true);
		}
	}

end:
	rcu_unlock(r->handle);
}

static int update_match(struct remote *r, struct match *m, uint32_t serial,
			bool add)
{
	slice_t sender = match_sender(m);

	if (!sender.len) {
		// broadcast
		return send_match_update(r, r->busq, m, serial, add);

	} else if (slice_eq(sender, BUS_DESTINATION)) {
		// name owner changed
		return update_name_changed_match(r, m, serial, add);

	} else if (has_prefix(sender, UNIQUE_ADDR_PREFIX)) {
		// unicast unique
		return update_unique_match(r, m, serial, add);

	} else {
		// named unicast
		return update_bus_match(r, m, serial, add);
	}
}

int add_match(struct remote *r, struct message *msg, struct body b)
{
	if (r->bus_name_match_num == MAX_MATCH_NUM) {
		return STS_OOM;
	}

	int err = 0;
	buf_t buf;
	if (lock_buffer(&r->out, &buf, msg->body_len)) {
		// match string is far too long
		return STS_NOT_SUPPORTED;
	}

	slice_t str;
	if (read_string_msg(&buf, msg, b, &str)) {
		unlock_buffer(&r->out, 0);
		return STS_PARSE_FAILED;
	}

	DLOG("add_match %.*s", str.len, str.p);

	// decode and update the remote
	struct match m;
	if (decode_match(&m, str)) {
		err = STS_NOT_SUPPORTED;
	} else {
		err = update_match(r, &m, msg->serial, true);
	}

	// and add to the list
	if (err) {
		unlock_buffer(&r->out, 0);
	} else {
		ref_paged_data(m.base);
		r->matches[r->match_num++] = m;
		unlock_buffer(&r->out, str.len);
	}
	return err;
}

static struct match *find_match(struct remote *r, slice_t str)
{
	for (int i = 0; i < r->bus_name_match_num; i++) {
		if (slice_eq(match_string(&r->matches[i]), str)) {
			return &r->matches[i];
		}
	}
	return NULL;
}

int rm_match(struct remote *r, struct message *msg, struct body body)
{
	buf_t buf;
	if (lock_buffer(&r->out, &buf, msg->body_len)) {
		// match string is far too long
		return STS_NOT_SUPPORTED;
	}
	slice_t str;
	if (read_string_msg(&buf, msg, body, &str)) {
		unlock_buffer(&r->out, 0);
		return STS_PARSE_FAILED;
	}

	DLOG("remove_match %.*s", str.len, str.p);

	// find the match
	struct match *m = find_match(r, str);
	unlock_buffer(&r->out, 0);
	if (!m) {
		return STS_NOT_FOUND;
	}

	// update the remote
	int err = update_match(r, m, msg->serial, false);

	// and remove from the list
	memmove(m, m + 1, (char *)&r->matches[r->match_num] - (char *)m);
	r->match_num--;
	deref_paged_data(m->base);
	return err;
}

void remove_all_matches(struct remote *r)
{
	for (int i = 0; i < r->match_num; i++) {
		update_match(r, &r->matches[i], 0, false);
		deref_paged_data(r->matches[i].base);
	}
	r->match_num = 0;
}

int add_subscription(struct remote *r, struct subscription *s)
{
	if (r->sub_num == MAX_MATCH_NUM) {
		return STS_OOM;
	}
	int idx = find_sub(r->subs, r->sub_num, s);
	if (idx >= 0) {
		// this shouldn't happen as the subscription is keyed off the
		// string pointer
		assert(0);
		return STS_OOM;
	}
	idx = -(idx + 1);
	memmove(r->subs + idx + 1, r->subs + idx,
		(r->sub_num - idx) * sizeof(r->subs[0]));
	r->subs[idx] = *s;
	r->sub_num++;
	return 0;
}

int rm_subscription(struct remote *r, struct subscription *s)
{
	int idx = find_sub(r->subs, r->sub_num, s);
	if (idx < 0) {
		return STS_NOT_FOUND;
	}
	r->sub_num--;
	memmove(r->subs + idx, r->subs + idx + 1,
		(r->sub_num - idx) * sizeof(r->subs[0]));
	return 0;
}

void broadcast_subs(struct remote *r, struct rcu *d, struct subscription *subs,
		    int n, struct message *m, struct body b)
{
	subs_for_interface(&subs, &n, m->interface);

	for (int i = 0; i < n; i++) {
		struct subscription *s = &subs[i];
		// interface & sender have already been checked
		if (member_matches(&s->m, m->member) &&
		    path_matches(&s->m, m->path)) {
			struct remote *to = lookup_remote(d, s->remote_id);
			if (to) {
				send_to(r, to, m, b);
			}
		}
	}
}

int broadcast(struct remote *r, struct message *m, struct body b)
{
	struct rcu *d = rcu_lock(r->handle);

	// lookup subscriptions in the global broadcast list
	broadcast_subs(r, d, d->bcast_v, d->bcast_n, m, b);

	// lookup subscriptions in the local list
	broadcast_subs(r, d, r->subs, r->sub_num, m, b);

	rcu_unlock(r->handle);
	return 0;
}
