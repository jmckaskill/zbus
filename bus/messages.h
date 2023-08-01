#pragma once
#include "msgq.h"
#include "subs.h"

struct remote;
struct bus;

enum {
	MSG_INVALID = 0,
	MSG_DATA,
	MSG_FILE,
	MSG_DISCONNECTED,
	CMD_REGISTER,
	REP_REGISTER,
	CMD_UPDATE_NAME,
	REP_UPDATE_NAME,
	MSG_NAME,
	CMD_UPDATE_NAME_SUB,
	REP_UPDATE_NAME_SUB,
	CMD_UPDATE_UCAST_SUB,
	REP_UPDATE_UCAST_SUB,
	CMD_UPDATE_BCAST_SUB,
	REP_UPDATE_BCAST_SUB,
};

extern msg_type_t msg_data_vt;
struct msg_data {
	struct msg_header hdr;
	slice_t data;
};

extern msg_type_t msg_file_vt;
struct msg_file {
	struct msg_header hdr;
	intptr_t fd;
};

extern msg_type_t msg_disconnected_vt;
struct msg_disconnected {
	struct msg_header hdr;
	struct remote *remote;
};

extern msg_type_t cmd_register_vt;
struct cmd_register {
	struct msg_header hdr;
	struct remote *remote;
};

extern msg_type_t rep_register_vt;
// no data

extern msg_type_t cmd_update_name_vt;
struct cmd_update_name {
	struct msg_header hdr;
	slice_t name;
	struct remote *remote;
	uint32_t serial;
	bool add;
};

extern msg_type_t cmd_update_name_sub_vt;
struct cmd_update_name_sub {
	struct msg_header hdr;
	struct remote *remote;
	uint32_t serial;
	bool add;
};

extern msg_type_t cmd_update_ucast_sub_vt;
struct cmd_update_ucast_sub {
	struct msg_header hdr;
	struct ucast_sub sub;
	uint32_t serial;
	bool add;
};

extern msg_type_t cmd_update_bcast_sub_vt;
struct cmd_update_bcast_sub {
	struct msg_header hdr;
	struct bcast_sub sub;
	uint32_t serial;
	bool add;
};

extern msg_type_t msg_name_vt;
struct msg_name {
	struct msg_header hdr;
	slice_t name;
	int old_owner;
	int new_owner;
};

extern msg_type_t rep_update_name_vt;
extern msg_type_t rep_update_name_sub_vt;
extern msg_type_t rep_update_ucast_sub_vt;
extern msg_type_t rep_update_bcast_sub_vt;
struct rep_errcode {
	struct msg_header hdr;
	uint32_t serial;
	int errcode;
};

#define DBUS_REQUEST_NAME_NOT_ALLOWED -1
#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER 1
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE 2
#define DBUS_REQUEST_NAME_REPLY_EXISTS 3
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER 4
#define DBUS_RELEASE_NAME_REPLY_RELEASED 1
#define DBUS_RELEASE_NAME_REPLY_NON_EXISTENT 2
#define DBUS_RELEASE_NAME_REPLY_NOT_OWNER 3
