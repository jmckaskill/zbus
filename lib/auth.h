#pragma once
#include "str.h"

#define AUTH_ERROR -1
#define AUTH_READ_MORE 0

// returns -ve on error
// 0 or need more data
// +ve - number of leading bytes in the buffer to skip. We do this so that the
// calling code can maintain buffer alignment. state should be initially set to
// 0
int step_server_auth(str_t *in, str_t *out, slice_t busid, slice_t unique_addr,
		     int *pstate);

