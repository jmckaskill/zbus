#pragma once
#include "tx.h"
#include "dbus/encode.h"

// general errors that any function can return
#define ERR_INTERNAL 1
#define ERR_OOM 2
#define ERR_NOT_ALLOWED 3
#define ERR_BAD_ARGUMENT 4
#define ERR_NOT_FOUND 5
#define ERR_NOT_SUPPORTED 6
#define ERR_NO_REMOTE 7
#define ERR_REMOTE_FAILED 8
#define ERR_NAME_HAS_NO_OWNER 9
#define ERR_WRONG_METHOD 10
#define ERR_LAUNCH_FAILED 11
#define ERR_TIMED_OUT 12
#define ERR_DISCONNECT 13

struct rx;

int reply_error(struct rx *r, uint32_t serial, int errcode);
int reply_uint32(struct rx *r, uint32_t serial, uint32_t value);
int reply_bool(struct rx *r, uint32_t serial, bool value);
int reply_string(struct rx *r, uint32_t serial, const str8_t *str);
int reply_id_address(struct rx *r, uint32_t serial, int id);
int reply_empty(struct rx *r, uint32_t serial);
