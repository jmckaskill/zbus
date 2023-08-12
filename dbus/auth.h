#pragma once
#include <stdint.h>
#include <stdlib.h>

#define AUTH_ERROR -1
#define AUTH_OK 0
#define AUTH_READ_MORE 1

// returns error codes above. State should be initially set to 0. Returns serial
// of hello message in pserial.
int step_server_auth(int *pstate, char **pin, int insz, char **pout, int outsz,
		     const char *busid, uint32_t *pserial);

int step_client_auth(int *pstate, char **pin, int insz, char **pout, int outsz,
		     const char *uid, uint32_t *pserial);
