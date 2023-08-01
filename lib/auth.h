#pragma once
#include "slice.h"
#include <stdint.h>

#define AUTH_ERROR -1
#define AUTH_OK 0
#define AUTH_READ_MORE 1

// returns error codes above. State should be initially set to 0. Returns serial
// of hello message in pserial.
int step_server_auth(int *pstate, slice_t *pin, char *out, size_t *poutsz,
		     slice_t busid, uint32_t *pserial);

int step_client_auth(int *pstate, slice_t *pin, char *out, size_t *poutsz,
		     slice_t uid, uint32_t *pserial);
