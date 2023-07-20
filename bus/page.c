#include "page.h"
#include <stdlib.h>

struct page *new_page(int refcnt)
{
	struct page *pg = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
	if (pg) {
		pg->refcnt = refcnt;
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

void ref_paged_data(const char *p, int num)
{
	struct page *pg = GET_PAGE(p);
	ref_page(pg, num);
}

void deref_paged_data(const char *p, int num)
{
	struct page *pg = GET_PAGE(p);
	deref_page(pg, num);
}
