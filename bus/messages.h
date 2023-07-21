#pragma once
#include "msgq.h"

struct remote;
struct bus;

#define MSG_DATA 0
#define MSG_FILE 1
#define MSG_SHUTDOWN 2
#define MSG_AUTHENTICATED 3
#define MSG_DISCONNECTED 4
#define CMD_REQUEST_NAME 5
#define REP_REQUEST_NAME 6
#define CMD_RELEASE_NAME 7
#define REP_RELEASE_NAME 8

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

// used for MSG_AUTHENTICATED and MSG_DISCONNECTED
struct msg_remote {
	struct remote *remote;
};

static_assert(sizeof(struct msg_remote) <= MSGQ_DATA_SIZE, "");

// used for both CMD_REQUEST_NAME & CMD_RELEASE_NAME
struct cmd_name {
	struct remote *remote;
	slice_t name;
	uint32_t reply_serial;
};

struct cmd_name make_cmd_name(struct remote *r, slice_t name, uint32_t reply);
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

struct rep_name {
	uint32_t reply_serial;
	int errcode;
};

static_assert(sizeof(struct rep_name) <= MSGQ_DATA_SIZE, "");
