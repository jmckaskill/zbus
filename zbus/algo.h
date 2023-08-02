#pragma once
#include "dmem/log.h"
#include "dmem/common.h"
#include "lib/slice.h"

struct circ_list {
	struct circ_list *next, *prev;
};

static inline void circ_init(struct circ_list *item)
{
	item->next = NULL;
	item->prev = NULL;
}

static inline void circ_clear(struct circ_list *head)
{
	head->next = head;
	head->prev = head;
}

static inline void circ_add(struct circ_list *item, struct circ_list *head)
{
	item->prev = head->prev;
	item->next = head;
	item->prev->next = item;
	head->prev = item;
}

static inline void circ_remove(struct circ_list *item)
{
	item->next->prev = item->prev;
	item->prev->next = item->next;
	item->next = NULL;
	item->prev = NULL;
}

// Finds an element in a sorted array
// returns +ve index if the key is found
// returns -ve -(index+1) of where a new key should be inserted
// ie return 0 indicates the value is in index 0
// return -1 indicates the value should be inserted into index 0
// return n-1 indicates the value is the last element
// return -(n+1) indicates the value should be inserted at the end
// cmp takes the key as the first parameter and the array
// element as the second and returns -ve if the key is smaller, 0 the same, or
// bigger than the element.
int lower_bound(const void *key, const void *base, int nel, size_t width,
		int (*cmp)(const void *, const void *));
