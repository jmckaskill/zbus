#pragma once
#include "config.h"
#include "lib/match.h"

struct ucast_sub {
	struct match m;
	int remote_id;
};

struct subset {
	struct ucast_sub subs[MAX_MATCH_NUM];
	int num;
};

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

// returns the index of an existing subscription or -(n+1) location of where to
// insert if not found
int find_sub(struct ucast_sub *subs, int num, struct ucast_sub *s);

// filters the subs and num arguments to the subset that match a given interface
void subs_for_interface(struct ucast_sub **subs, int *pnum, slice_t iface);
