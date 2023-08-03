#pragma once
#include "tx.h"
#include "lib/encode.h"

// general errors that any function can return
#define ERR_INTERNAL -1
#define ERR_OOM -2
#define ERR_NOT_ALLOWED -3
#define ERR_BAD_ARGUMENT -4
#define ERR_NOT_FOUND -5
#define ERR_NOT_SUPPORTED -6
#define ERR_NO_REMOTE -7
#define ERR_REMOTE_FAILED -8
#define ERR_NAME_HAS_NO_OWNER -9
#define ERR_WRONG_METHOD -10
#define ERR_LAUNCH_FAILED -11
#define ERR_TIMED_OUT -12

int reply_error(struct tx *to, uint32_t request_serial, int errcode);
int reply_uint32(struct tx *to, uint32_t request_serial, uint32_t value);
int reply_bool(struct tx *to, uint32_t request_serial, bool value);
int reply_string(struct tx *to, uint32_t request_serial, slice_t str);
int reply_empty(struct tx *to, uint32_t request_serial);
