#include "page.h"
#include <stdlib.h>

struct page *new_page(int refcnt)
{
	struct page *pg = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
	if (pg) {
		pg->refcnt = refcnt;
		pg->next = NULL;
	}
	return pg;
}

void ref_page(struct page *pg, int num)
{
	atomic_fetch_add_explicit(&pg->refcnt, num, memory_order_relaxed);
}

void deref_page(struct page *pg, int num)
{
	if (pg && atomic_fetch_sub_explicit(&pg->refcnt, num,
					    memory_order_acq_rel) == num) {
		free(pg);
	}
}

void init_buffer(struct page_buffer *b)
{
	memset(b, 0, sizeof(*b));
}

void destroy_buffer(struct page_buffer *b)
{
	deref_page(b->pg, 1);
}

slice_t dup_in_buffer(struct page_buffer *b, slice_t src)
{
	assert(src.len < MAX_BUFFER_SIZE);
	buf_t str = lock_short_buffer(b);
	buf_add(&str, src);
	slice_t ret = to_slice(str);
	unlock_buffer(b, ret.len);
	return ret;
}

int lock_buffer(struct page_buffer *b, buf_t *pbuf, int minsz)
{
	assert(!b->locked);
	if (b->locked || minsz > sizeof(b->pg->data)) {
		return -1;
	}
	b->locked = true;
	if (!b->pg || b->used + minsz >= sizeof(b->pg->data)) {
		deref_page(b->pg, 1);
		b->pg = new_page(1);
		b->used = 0;
	}
	pbuf->p = b->pg->data + b->used;
	pbuf->len = 0;
	pbuf->cap = sizeof(b->pg->data) - b->used;
	return 0;
}
