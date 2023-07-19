#pragma once
#include "msgq.h"
#include "rcu.h"

#define MSG_SHUTDOWN (MSGQ_TYPE_DATA | 0)
#define MSG_AUTHENTICATED (MSGQ_TYPE_DATA | 1)
#define MSG_DISCONNECTED (MSGQ_TYPE_DATA | 2)

#define MSG_SEND_DATA (MSGQ_TYPE_PAGED | 0)
#define MSG_SEND_FILE (MSGQ_TYPE_FILE | 0)

struct msg_authenticated {
	int id;
};

struct msg_disconnected {
	struct remote *r;
};
