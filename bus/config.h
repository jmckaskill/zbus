#pragma once

#define _GNU_SOURCE
// enough space to copy a field 256, field length/headers 8 and 8 byte padding 8
#define MULTIPART_WORKING_SPACE (256 + 8 + 8)

#define CACHE_LINE_SIZE 64
#define MSGQ_SIZE 256
#define PAGE_SIZE (64 * 1024)
// #define PAGE_SIZE 512
#define BUS_MAX_MSG_SIZE (256 * 1024)
#define MAX_NUM_PAGES \
	(1 + (BUS_MAX_MSG_SIZE / (PAGE_SIZE - MULTIPART_WORKING_SPACE)))

#define container_of(ptr, type, member)                            \
	({                                                         \
		const typeof(((type *)0)->member) *__mptr = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); \
	})

typedef void (*destructor_fn)(void *);
