#include "busmsg.h"
#include "tx.h"
#include "lib/encode.h"

#define X(X)                     \
	{                        \
		X, sizeof(X) - 1 \
	}

static const slice_t error_names[] = {
	[-(ERR_INTERNAL + 1)] = X("org.freedesktop.DBus.Error.Internal"),
	[-(ERR_OOM + 1)] = X("org.freedesktop.DBus.Error.OutOfMemory"),
	[-(ERR_NOT_ALLOWED + 1)] = X("org.freedesktop.DBus.Error.AccessDenied"),
	[-(ERR_NOT_FOUND + 1)] = X("org.freedesktop.DBus.Error.NotFound"),
	[-(ERR_NOT_SUPPORTED + 1)] =
		X("org.freedesktop.DBUs.Error.NotSupported"),
	[-(ERR_NO_REMOTE + 1)] = X("org.freedesktop.DBus.Error.NoRemote"),
	[-(ERR_REMOTE_FAILED + 1)] =
		X("org.freedesktop.DBus.Error.RemoteNotResponsive"),
	[-(ERR_NAME_HAS_NO_OWNER + 1)] =
		X("org.freedesktop.DBus.Error.NameHasNoOwner"),
	[-(ERR_BAD_ARGUMENT + 1)] = X("org.freedesktop.DBus.Error.BadArgument"),
	[-(ERR_LAUNCH_FAILED + 1)] =
		X("org.freedesktop.DBus.Error.LaunchFailed"),
	[-(ERR_TIMED_OUT + 1)] = X("org.freedesktop.DBus.Error.TimedOut"),
};

#undef X

int reply_error(struct tx *to, uint32_t request_serial, int errcode)
{
	int idx = -(errcode + 1);
	if (idx < 0 || idx > sizeof(error_names) / sizeof(error_names[0])) {
		return -1;
	}

	char buf[256];
	struct message m;
	init_message(&m, MSG_ERROR, NO_REPLY_SERIAL);
	m.flags = FLAG_NO_REPLY_EXPECTED;
	m.reply_serial = request_serial;
	m.error = error_names[idx];

	int sz = write_header(buf, sizeof(buf), &m, 0);
	return sz < 0 || send_data(to, true, buf, sz);
}

static int _reply_uint32(struct tx *to, uint32_t request_serial,
			 const char *sig, uint32_t value)
{
	struct message m;
	init_message(&m, MSG_REPLY, NO_REPLY_SERIAL);
	m.flags = FLAG_NO_REPLY_EXPECTED;
	m.reply_serial = request_serial;
	m.signature = sig;

	char buf[256];
	struct builder b = start_message(buf, sizeof(buf), &m);
	_append4(&b, value, *sig);
	int sz = end_message(b);
	return sz < 0 ? ERR_OOM : send_data(to, true, buf, sz);
}

int reply_uint32(struct tx *to, uint32_t request_serial, uint32_t value)
{
	return _reply_uint32(to, request_serial, "u", value);
}

int reply_bool(struct tx *to, uint32_t request_serial, bool value)
{
	return _reply_uint32(to, request_serial, "b", value);
}

int reply_string(struct tx *to, uint32_t request_serial, slice_t str)
{
	struct message m;
	init_message(&m, MSG_REPLY, NO_REPLY_SERIAL);
	m.flags = FLAG_NO_REPLY_EXPECTED;
	m.reply_serial = request_serial;
	m.signature = "s";

	char buf[256];
	struct builder b = start_message(buf, sizeof(buf), &m);
	append_string(&b, str);
	int sz = end_message(b);
	return sz < 0 ? ERR_OOM : send_data(to, true, buf, sz);
}

int reply_empty(struct tx *to, uint32_t request_serial)
{
	struct message m;
	init_message(&m, MSG_REPLY, NO_REPLY_SERIAL);
	m.flags = FLAG_NO_REPLY_EXPECTED;
	m.reply_serial = request_serial;

	char buf[256];
	int sz = write_header(buf, sizeof(buf), &m, 0);
	return sz < 0 ? ERR_OOM : send_data(to, true, buf, sz);
}
