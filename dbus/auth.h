#pragma once
#include <stdint.h>
#include <stdlib.h>

// returns one of the ZB_STREAM_* error codes. State should be initially set to
// 0.
ZB_EXTERN int zb_step_server_auth(int *pstate, char **pin, char *inend, char **pout,
			char *outend, const char *busid, uint32_t *pserial);

// Client auth assume the auth handshake will succeed and sends the entire
// conversation in the initial send. This allows a client to send the auth and
// messages all in one send. However it may fail if the server doesn't like the
// handshake.

// returns # of bytes written or -ve on error
ZB_EXTERN int zb_encode_auth_request(char *buf, size_t bufsz, const char *uid,
			   uint32_t serial);

// returns ZB_STREAM_* error code above or # of bytes read on success
ZB_EXTERN int zb_decode_auth_reply(char *in, size_t sz);
