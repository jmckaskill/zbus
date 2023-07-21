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

#define GET_PAGE(P) ALIGN_PTR_DOWN(struct page *, P, PAGE_SIZE)

// create a new page with an initial ref count
struct page *new_page(int refcnt);

// ref or deref the whole page
void ref_page(struct page *pg, int num);
void deref_page(struct page *pg, int num);

// ref or deref the page via pointers into data in the page
void ref_paged_data(const char *p, int num);
void deref_paged_data(const char *p, int num);

//////////////////////////////////
// page_buffer provides a buffer service using struct page

struct page_buffer {
	struct page *pg;
	int used;
	bool locked;
};

#define MAX_BUFFER_SIZE sizeof(((struct page *)0)->data)

extern int lock_buffer(struct page_buffer *b, str_t *s, int minsz);
static str_t lock_short_buffer(struct page_buffer *b);
static void unlock_buffer(struct page_buffer *b, int used);

///////////////////////////////////
// inline implementations

static inline str_t lock_short_buffer(struct page_buffer *b)
{
	// short buffer shouldn't fail
	// enough room for a max length encoded 256B bus name
	str_t buf;
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
