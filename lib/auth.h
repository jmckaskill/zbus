#pragma once
#include "str.h"
#include <stdint.h>

#define AUTH_ERROR -1
#define AUTH_OK 0
#define AUTH_READ_MORE 1

// returns -ve on error
// 0 or need more data
// +ve - number of leading bytes in the buffer to skip. We do this so that the
// calling code can maintain buffer alignment. serial should be initially set to
// 0
int step_server_auth(buf_t *in, buf_t *out, slice_t busid, slice_t unique_addr,
		     uint32_t *pserial);
