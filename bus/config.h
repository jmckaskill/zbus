#pragma once

#ifndef _WIN32
#define _GNU_SOURCE
#include <signal.h>
#define MSGQ_SIG_CONSUMER (SIGRTMIN)
#define MSGQ_SIG_PRODUCER (SIGRTMIN + 1)
#endif

#define MAX_NAME_NUM 4
#define MAX_MATCH_NUM 16
#define CACHE_LINE_SIZE 64
#define MSGQ_SIZE 256
#define PAGE_SIZE (64 * 1024)
// #define PAGE_SIZE 512
#define BUS_MAX_MSG_SIZE (256 * 1024)
#define MAX_NUM_PAGES ((BUS_MAX_MSG_SIZE / PAGE_SIZE) + 1)

#define container_of(ptr, type, member)                            \
	({                                                         \
		const typeof(((type *)0)->member) *__mptr = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); \
	})

typedef void (*destructor_fn)(void *);
