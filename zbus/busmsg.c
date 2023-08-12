#include "busmsg.h"
#include "tx.h"
#include "rx.h"
#include "dbus/encode.h"

static const char *errors[] = {
	[ERR_INTERNAL] = "\043org.freedesktop.DBus.Error.Internal",
	[ERR_OOM] = "\046org.freedesktop.DBus.Error.OutOfMemory",
	[ERR_NOT_ALLOWED] = "\047org.freedesktop.DBus.Error.AccessDenied",
	[ERR_NOT_FOUND] = "\043org.freedesktop.DBus.Error.NotFound",
	[ERR_NOT_SUPPORTED] = "\047org.freedesktop.DBUs.Error.NotSupported",
	[ERR_NO_REMOTE] = "\043org.freedesktop.DBus.Error.NoRemote",
	[ERR_REMOTE_FAILED] =
		"\056org.freedesktop.DBus.Error.RemoteNotResponsive",
	[ERR_NAME_HAS_NO_OWNER] =
		"\051org.freedesktop.DBus.Error.NameHasNoOwner",
	[ERR_BAD_ARGUMENT] = "\046org.freedesktop.DBus.Error.BadArgument",
	[ERR_LAUNCH_FAILED] = "\047org.freedesktop.DBus.Error.LaunchFailed",
	[ERR_TIMED_OUT] = "\043org.freedesktop.DBus.Error.TimedOut",
	[ERR_DISCONNECT] = "\045org.freedesktop.DBus.Error.Disconnect",
};

int reply_error(struct rx *r, uint32_t serial, int err)
{
	if (err < 0 || err > sizeof(errors) / sizeof(errors[0]) ||
	    !errors[err]) {
		err = ERR_INTERNAL;
	}

	const str8_t *error = (const str8_t *)errors[err];
	assert(error->len == strlen(error->p));

	struct txmsg m;
	init_message(&m.m, MSG_ERROR, NO_REPLY_SERIAL);
	m.m.reply_serial = serial;
	m.m.error = error;

	int sz = write_header(r->txbuf, TX_BUFSZ, &m.m, 0);
	return send_data(r->tx, false, &m, r->txbuf, sz);
}

static int _reply_uint32(struct rx *r, uint32_t serial, const char *sig,
			 uint32_t value)
{
	struct txmsg m;
	init_message(&m.m, MSG_REPLY, NO_REPLY_SERIAL);
	m.m.reply_serial = serial;
	m.m.signature = sig;

	struct builder b = start_message(r->txbuf, TX_BUFSZ, &m.m);
	_append4(&b, value, *sig);
	int sz = end_message(b);
	return send_data(r->tx, false, &m, r->txbuf, sz);
}

int reply_uint32(struct rx *r, uint32_t serial, uint32_t value)
{
	return _reply_uint32(r, serial, "u", value);
}

int reply_bool(struct rx *r, uint32_t serial, bool value)
{
	return _reply_uint32(r, serial, "b", value);
}

int reply_string(struct rx *r, uint32_t serial, const str8_t *str)
{
	struct txmsg m;
	init_message(&m.m, MSG_REPLY, NO_REPLY_SERIAL);
	m.m.reply_serial = serial;
	m.m.signature = "s";

	struct builder b = start_message(r->txbuf, TX_BUFSZ, &m.m);
	append_string8(&b, str);
	int sz = end_message(b);
	return send_data(r->tx, false, &m, r->txbuf, sz);
}

int reply_id_address(struct rx *r, uint32_t serial, int id)
{
	struct txmsg m;
	init_message(&m.m, MSG_REPLY, NO_REPLY_SERIAL);
	m.m.reply_serial = serial;
	m.m.signature = "s";

	struct builder b = start_message(r->txbuf, TX_BUFSZ, &m.m);
	append_id_address(&b, id);
	int sz = end_message(b);
	return send_data(r->tx, false, &m, r->txbuf, sz);
}

int reply_empty(struct rx *r, uint32_t serial)
{
	struct txmsg m;
	init_message(&m.m, MSG_REPLY, NO_REPLY_SERIAL);
	m.m.reply_serial = serial;

	int sz = write_header(r->txbuf, TX_BUFSZ, &m.m, 0);
	return send_data(r->tx, false, &m, r->txbuf, sz);
}
