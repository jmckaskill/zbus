#pragma once
#include "config.h"
#include "lib/str.h"
#include "lib/types.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdalign.h>
#include <stdbool.h>

struct page {
	alignas(PAGE_SIZE) atomic_int refcnt;
	struct page *next;
	alignas(CACHE_LINE_SIZE) char data[PAGE_SIZE - CACHE_LINE_SIZE - 8];
	// pad the last part of the page so a slice pointing to data within the
	// page always aligns down to the page base and doesn't point to the
	// next page even if the slice length is 0
	char _pad[8];
};

static_assert(sizeof(struct page) == PAGE_SIZE, "padding");

#define ALIGN_PTR_DOWN(TYPE, PTR, BOUNDARY) \
	((TYPE)(((uintptr_t)(PTR)) & (~((((uintptr_t)(BOUNDARY)) - 1)))))

// create a new page with an initial ref count
struct page *new_page(int refcnt);

// ref or deref the whole page
void ref_page(struct page *pg, int num);
void deref_page(struct page *pg, int num);

static inline struct page *get_page(const char *s)
{
	return (struct page *)((uintptr_t)s & ((PAGE_SIZE)-1U));
}

// ref or deref the page via pointers into data in the page
static inline void ref_paged_data(const char *s)
{
	ref_page(get_page(s), 1);
}
static inline void deref_paged_data(const char *s)
{
	deref_page(get_page(s), 1);
}

//////////////////////////////////
// page_buffer provides a buffer service using struct page

struct page_buffer {
	struct page *pg;
	int used;
	bool locked;
};

#define MAX_BUFFER_SIZE sizeof(((struct page *)0)->data)

extern void init_buffer(struct page_buffer *b);
extern void destroy_buffer(struct page_buffer *b);
extern int lock_buffer(struct page_buffer *b, buf_t *s, int minsz);
static buf_t lock_short_buffer(struct page_buffer *b);
static void unlock_buffer(struct page_buffer *b, int used);
extern slice_t dup_in_buffer(struct page_buffer *b, slice_t s);

///////////////////////////////////
// inline implementations

static inline buf_t lock_short_buffer(struct page_buffer *b)
{
	// short buffer shouldn't fail
	// enough room for a max length encoded 256B bus name
	buf_t buf;
	int err = lock_buffer(b, &buf, 264);
	assert(err == 0);
	return buf;
}

static inline void unlock_buffer(struct page_buffer *b, int keep)
{
	assert(b->locked);
	b->locked = false;
	b->used += ALIGN_UINT_UP(keep, 8);
}
