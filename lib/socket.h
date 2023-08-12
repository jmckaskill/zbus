#pragma once
#include "threads.h"
#include <stdlib.h>
#include <stdbool.h>

struct rxconn;
struct txconn;

// starts a synchronous receive
// returns
// +ve - number of bytes read
// 0 - EOF
// -ve - error
int block_recv1(struct rxconn *c, char *p, int n);
int block_recv2(struct rxconn *c, char *p1, int n1, char *p2, int n2);

// start an async send that may finish synchronously if async == true
// returns
// +ve - number of bytes sent
// 0 - send scheduled
// -ve - error
int start_send1(struct txconn *c, char *p, int n);
int start_send3(struct txconn *c, char *p1, int n1, char *p2, int n2, char *p3,
		int n3);

// waits for the send to finish, unlocks lk while blocked
// returns
// +ve - number of bytes sent
// 0 - no data sent, but file is ready to send more
// -ve - error
int finish_send(struct txconn *c, mtx_t *lk);

// called from the rx thread when we want to shut down the socket and cancels
// any blocking sends on other threads. Must be serialized externally with calls
// to start_send and finish_send
void cancel_send(struct txconn *c);

// close_rx is always called before close_tx
void close_rx(struct rxconn *c);
void close_tx(struct txconn *c);

#include "socket-win32.h"
#include "socket-posix.h"
