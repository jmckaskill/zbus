#include "remote.h"
#include "lib/log.h"
#include "page.h"
#include "messages.h"
#include "bus.h"
#include "rcu.h"
#include "lib/decode.h"
#include "lib/encode.h"

#define METHOD_GET_ID S("GetId") // 5
#define METHOD_HELLO S("Hello") // 5
#define METHOD_ADD_MATCH S("AddMatch") // 8
#define METHOD_LIST_NAMES S("ListNames") // 9
#define METHOD_REQUEST_NAME S("RequestName") // 11
#define METHOD_RELEASE_NAME S("ReleaseName") // 11
#define METHOD_REMOVE_MATCH S("RemoveMatch") // 11
#define METHOD_NAME_HAS_OWNER S("NameHasOwner") // 12
#define METHOD_GET_NAME_OWNER S("GetNameOwner") // 12
#define METHOD_LIST_QUEUED_OWNERS S("ListQueuedOwners") // 16
#define METHOD_START_SERVICE S("StartServiceByName") // 18
#define METHOD_LIST_ACTIVATABLE_NAMES S("ListActivatableNames") // 20
#define METHOD_GET_UNIX_USER S("GetConnectionUnixUser") // 21
#define METHOD_GET_ADT S("GetAdtAuditSessionData") // 22
#define METHOD_GET_CREDENTIALS S("GetConnectionCredentials") // 24
#define METHOD_GET_UNIX_PROCESS_ID S("GetConnectionUnixProcessID") // 26
#define METHOD_UPDATE_ENVIRONMENT S("UpdateActivationEnvironment") // 27
#define METHOD_GET_SELINUX S("GetConnectionSELinuxSEcurityContext") // 35

#define METHOD_BECOME_MONITOR S("BecomeMonitor")

#define METHOD_PING S("Ping")

////////////////////////////////////
// RequestName & ReleaseName

static int request_name(struct remote *r, struct message *m, struct body b,
			bool add)
{
	slice_t name;
	buf_t buf = lock_short_buffer(&r->out);

	if (read_string_msg(&buf, m, b, &name)) {
		unlock_buffer(&r->out, 0);
		return STS_PARSE_FAILED;
	}

	DLOG("remote requesting %.*s", name.len, name.p);

	// send the request off and wait for the response
	struct cmd_name *c = msg_allocate(r->busq);
	if (c) {
		c->hdr.data = name;
		c->add = add;
		c->remote = r;
		c->serial = m->serial;
		msg_release(r->busq, CMD_UPDATE_NAME, c);
		unlock_buffer(&r->out, name.len);
		return 0;
	} else {
		unlock_buffer(&r->out, 0);
		return STS_REMOTE_FAILED;
	}
}

int reply_errcode(struct remote *r, struct rep_errcode *c)
{
	if (c->errcode == DBUS_REQUEST_NAME_NOT_ALLOWED) {
		return loopback_error(r, c->serial, STS_NOT_ALLOWED);
	}
	return loopback_uint32(r, c->serial, c->errcode);
}

/////////////////////////////
// ListNames

static int bufsz_list_names(struct rcu *d)
{
	int bufsz = BUFSZ_REPLY + BUFSZ_ARRAY;

	for (int i = 0; i < d->names_n; i++) {
		if (d->names_v[i].owner) {
			bufsz += d->names_v[i].name.len + BUFSZ_STRING;
		}
	}

	for (int i = 0; i < d->remotes_n; i++) {
		bufsz += d->remotes_v[i].owner->addr.len + BUFSZ_STRING;
	}

	return bufsz;
}

static int encode_list_names(buf_t *buf, struct message *m, struct rcu *d)
{
	struct builder b = start_message(buf, m);
	struct array_data ad = start_array(&b);

	// get bus names that have owners
	for (int i = 0; i < d->names_n; i++) {
		if (d->names_v[i].owner) {
			start_array_entry(&b, &ad);
			append_string(&b, d->names_v[i].name);
		}
	}

	// get unique names
	for (int i = 0; i < d->remotes_n; i++) {
		start_array_entry(&b, &ad);
		append_string(&b, d->remotes_v[i].owner->addr);
	}

	end_array(&b, ad);
	return end_message(buf, b);
}

static int list_names(struct remote *r, struct message *m)
{
	struct message o;
	init_message(&o, MSG_REPLY, next_serial());
	o.reply_serial = m->serial;
	o.sender = BUS_DESTINATION;
	o.signature = "as";

	struct rcu *d = rcu_lock(r->handle);
	int bufsz = bufsz_list_names(d);

	buf_t buf;
	if (lock_buffer(&r->out, &buf, bufsz)) {
		goto error_unlock_rcu;
	}

	if (encode_list_names(&buf, &o, d) || send_loopback(r, to_slice(buf))) {
		goto error_unlock_buffer;
	}

	unlock_buffer(&r->out, buf.len);
	rcu_unlock(r->handle);
	return 0;

error_unlock_buffer:
	unlock_buffer(&r->out, 0);
error_unlock_rcu:
	rcu_unlock(r->handle);
	return STS_SEND_FAILED;
}

///////////////////////////////
// GetNameOwner & NameHasOwner

static struct remote *parse_and_lookup_name(struct page_buffer *p,
					    struct rcu *d, struct message *m,
					    struct body b)
{
	buf_t s = lock_short_buffer(p);
	struct remote *ret = NULL;
	slice_t name;

	if (!read_string_msg(&s, m, b, &name)) {
		ret = lookup_name(d, name);
	}

	unlock_buffer(p, 0);
	return ret;
}

static int get_name_owner(struct remote *r, struct message *m, struct body b)
{
	int err = STS_NAME_HAS_NO_OWNER;

	struct rcu *d = rcu_lock(r->handle);
	struct remote *tgt = parse_and_lookup_name(&r->out, d, m, b);
	if (tgt) {
		err = loopback_string(r, m->reply_serial, tgt->addr);
	}
	rcu_unlock(r->handle);

	return err;
}

static int name_has_owner(struct remote *r, struct message *m, struct body b)
{
	struct rcu *d = rcu_lock(r->handle);
	struct remote *tgt = parse_and_lookup_name(&r->out, d, m, b);
	int err = loopback_bool(r, m->reply_serial, tgt != NULL);
	rcu_unlock(r->handle);
	return err;
}

int unicast(struct remote *r, struct message *m, struct body b)
{
	struct rcu *d = rcu_lock(r->handle);
	struct remote *tgt = lookup_name(d, m->destination);

	int err = STS_NO_REMOTE;
	if (tgt) {
		err = send_to(r, tgt, m, b);
	}

	rcu_unlock(r->handle);
	return err;
}

/////////////////////////
// Bus Interfaces

int bus_interface(struct remote *r, struct message *m, struct body b)
{
	// use the member length as a quick static hash
	switch (m->member.len) {
	case 5:
		if (slice_eq(m->member, METHOD_GET_ID)) {
		} else if (slice_eq(m->member, METHOD_HELLO)) {
			return loopback_string(r, m->serial, r->addr);
		}
		break;
	case 8:
		if (slice_eq(m->member, METHOD_ADD_MATCH)) {
			return add_match(r, m, b);
		}
		break;
	case 9:
		if (slice_eq(m->member, METHOD_LIST_NAMES)) {
			return list_names(r, m);
		}
		break;
	case 11:
		if (slice_eq(m->member, METHOD_REMOVE_MATCH)) {
			return rm_match(r, m, b);
		} else if (slice_eq(m->member, METHOD_REQUEST_NAME)) {
			return request_name(r, m, b, true);
		} else if (slice_eq(m->member, METHOD_RELEASE_NAME)) {
			return request_name(r, m, b, false);
		}
		break;
	case 12:
		if (slice_eq(m->member, METHOD_GET_NAME_OWNER)) {
			return get_name_owner(r, m, b);
		} else if (slice_eq(m->member, METHOD_NAME_HAS_OWNER)) {
			return name_has_owner(r, m, b);
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

		if (slice_eq(m->member, METHOD_LIST_ACTIVATABLE_NAMES)) {
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

	return STS_NOT_FOUND;
}

int monitoring_interface(struct remote *r, struct message *m, struct body b)
{
	if (slice_eq(m->member, METHOD_BECOME_MONITOR)) {
		return loopback_empty(r, m->serial);
	}
	return STS_NOT_FOUND;
}

int peer_interface(struct remote *r, struct message *m, struct body b)
{
	if (slice_eq(m->member, METHOD_PING)) {
		return loopback_empty(r, m->serial);
	}
	return STS_NOT_FOUND;
}