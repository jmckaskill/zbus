#pragma once
#include "msgq.h"
#include "subs.h"

struct remote;
struct bus;

enum msgq_type {
	MSG_DATA, // remote to remote data, struct msg_data
	MSG_FILE, // remote to remote data, struct msg_file
	MSG_SHUTDOWN, // bus to remote control, no data
	MSG_DISCONNECTED, // remote to bus, struct cmd_remote
	CMD_REGISTER, // remote to bus, struct cmd_remote
	REP_REGISTER, // bus to remote control, no data
	CMD_UPDATE_NAME, // remote to bus, struct cmd_name
	REP_UPDATE_NAME, // bus to remote control, struct rep_errcode
	CMD_UPDATE_NAME_SUB, // remote to bus, struct cmd_name_sub
	REP_UPDATE_NAME_SUB, // bus to remote control/data, struct rep_errcode
	MSG_NAME, // bus to remote(s) control/data, struct msg_name
	CMD_UPDATE_SUB, // remote to bus/remote control, struct cmd_update_sub
	REP_UPDATE_SUB, // bus/remote to remote control, struct rep_errcode
};

struct msg_data {
	slice_t data;
};

void gc_msg_data(void *);
static_assert(sizeof(struct msg_data) <= MSGQ_DATA_SIZE, "");

struct msg_file {
	intptr_t file;
};

void gc_msg_file(void *);
static_assert(sizeof(struct msg_file) <= MSGQ_DATA_SIZE, "");

struct cmd_remote {
	struct remote *remote;
};

static_assert(sizeof(struct cmd_remote) <= MSGQ_DATA_SIZE, "");

struct cmd_name {
	struct remote *remote;
	slice_t name;
	uint32_t serial;
	bool add;
};

void gc_cmd_name(void *);
static_assert(sizeof(struct cmd_name) <= MSGQ_DATA_SIZE, "");

#define DBUS_REQUEST_NAME_NOT_ALLOWED -1
#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER 1
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE 2
#define DBUS_REQUEST_NAME_REPLY_EXISTS 3
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER 4
#define DBUS_RELEASE_NAME_REPLY_RELEASED 1
#define DBUS_RELEASE_NAME_REPLY_NON_EXISTENT 2
#define DBUS_RELEASE_NAME_REPLY_NOT_OWNER 3

struct rep_errcode {
	uint32_t serial;
	int errcode;
};

static_assert(sizeof(struct rep_errcode) <= MSGQ_DATA_SIZE, "");

struct cmd_update_sub {
	struct subscription s;
	uint32_t serial;
	bool add;

	// Only for use by the bus thread. Other remotes should lookup the
	// remote using the remote_id as the remote may have disconnected in the
	// interim.
	struct remote *remote;
};

static_assert(sizeof(struct cmd_update_sub) <= MSGQ_DATA_SIZE, "");
void gc_update_sub(void *);

struct cmd_name_sub {
	struct msgq *q;
	uint32_t serial;
	bool add;
};

static_assert(sizeof(struct cmd_name_sub) <= MSGQ_DATA_SIZE, "");

struct msg_name {
	slice_t name;
	int old_owner;
	int new_owner;
};

void gc_name(void *);
static_assert(sizeof(struct msg_name) <= MSGQ_DATA_SIZE, "");
