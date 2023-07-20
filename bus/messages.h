#pragma once
#include "msgq.h"

struct remote;
struct bus;

#define MSG_SEND_DATA 0
#define MSG_SEND_FILE 1
#define MSG_SHUTDOWN 2
#define MSG_AUTHENTICATED 3
#define MSG_DISCONNECTED 4
#define CMD_REQUEST_NAME 5
#define REP_REQUEST_NAME 6
#define CMD_RELEASE_NAME 7
#define REP_RELEASE_NAME 8

struct msg_send_data {
	slice_t data;
};

void gc_send_data(void *);
static_assert(sizeof(struct msg_send_data) <= MSGQ_DATA_SIZE, "");

struct msg_send_file {
	intptr_t file;
};

void gc_send_file(void *);
static_assert(sizeof(struct msg_send_file) <= MSGQ_DATA_SIZE, "");

struct msg_authenticated {
	struct remote *remote;
};

static_assert(sizeof(struct msg_authenticated) <= MSGQ_DATA_SIZE, "");

struct msg_disconnected {
	struct remote *remote;
};

static_assert(sizeof(struct msg_disconnected) <= MSGQ_DATA_SIZE, "");

struct cmd_request_name {
	struct remote *remote;
	slice_t name;
};

void gc_request_name(void *);
static_assert(sizeof(struct cmd_request_name) <= MSGQ_DATA_SIZE, "");

struct rep_request_name {
};

static_assert(sizeof(struct rep_request_name) <= MSGQ_DATA_SIZE, "");

struct cmd_release_name {
	struct remote *remote;
	slice_t name;
};

void gc_release_name(void *);
static_assert(sizeof(struct cmd_release_name) <= MSGQ_DATA_SIZE, "");

struct rep_release_name {
};

static_assert(sizeof(struct rep_release_name) <= MSGQ_DATA_SIZE, "");
