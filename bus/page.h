#pragma once
#include "config.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>

struct page {
	atomic_int refcnt PAGE_ALIGNED;
	char data[PAGE_SIZE - CACHE_LINE_SIZE] CACHE_ALIGNED;
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
