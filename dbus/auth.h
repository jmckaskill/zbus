#pragma once
#include <stdint.h>
#include <stdlib.h>

#define AUTH_FINISHED 0
#define AUTH_READ_MORE -1
#define AUTH_SEND_MORE -2
#define AUTH_ERROR -3

// returns error codes above. State should be initially set to 0.
int step_server_auth(int *pstate, char **pin, char *inend, char **pout,
		     char *outend, const char *busid, uint32_t *pserial);

// Client auth assume the auth handshake will succeed and sends the entire
// conversation in the initial send. This allows a client to send the auth and
// messages all in one send. However it may fail if the server doesn't like the
// handshake.

// returns # of bytes written or -ve on error
int write_client_auth(char *buf, size_t bufsz, const char *uid,
		      uint32_t serial);

// returns error codes above or # of bytes read on success. State should
// initially be set to 0.
int read_client_auth(char *in, size_t sz);
