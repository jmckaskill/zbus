#pragma once

#define CACHE_LINE_SIZE 64
#define MSGQ_SIZE 256
#define PAGE_SIZE (64 * 1024)
#define MAX_MSG_PAGES 4
#define MAX_MSG_SIZE (MAX_MSG_PAGES * PAGE_SIZE)

#define CACHE_ALIGNED __attribute__((aligned(CACHE_LINE_SIZE)))
#define PAGE_ALIGNED __attribute__((aligned(PAGE_SIZE)))

#define container_of(ptr, type, member)                            \
	({                                                         \
		const typeof(((type *)0)->member) *__mptr = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); \
	})
