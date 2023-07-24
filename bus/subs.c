#include "subs.h"
#include <stddef.h>

struct subkey {
	slice_t interface;
	const char *base;
};

static int compare_sub(const void *key, const void *element)
{
	const struct subkey *k = key;
	const struct subscription *s = element;
	int dsz = k->interface.len - s->m.interface_len;
	if (dsz) {
		return dsz;
	}
	const char *subp = s->m.base + s->m.interface_off;
	int cmp = memcmp(k->interface.p, subp, k->interface.len);
	if (cmp) {
		return cmp;
	}
	return (int)(ptrdiff_t)(k->base - s->m.base);
}

int lower_bound(const void *key, const void *base, int nel, size_t width,
		int (*cmp)(const void *, const void *))
{
	int low = 0;
	int high = nel;
	while (low < high) {
		int mid = low + (high - low) / 2;
		int sign = cmp(key, (char *)base + (mid * width));
		if (sign < 0) {
			high = mid;
		} else if (sign > 0) {
			low = mid + 1;
		} else {
			return mid;
		}
	}
	return -(low + 1);
}

int find_sub(struct subscription *subs, int num, struct subscription *s)
{
	struct subkey key;
	key.interface = match_interface(&s->m);
	key.base = s->m.base;
	return lower_bound(&key, subs, num, sizeof(*subs), &compare_sub);
}

void subs_for_interface(struct subscription **psubs, int *pnum,
			slice_t interface)
{
	struct subscription *v = *psubs;
	int n = *pnum;

	// subscriptions are sorted by (interface,base)
	// We find the lower bound of (interface,NULL) and see how many have
	// matching interface values.
	struct subkey key;
	key.interface = interface;
	key.base = NULL;
	int i = -(lower_bound(&key, v, n, sizeof(*v), &compare_sub) + 1);

	// we shouldn't get any exact matches with base == NULL
	assert(i >= 0);

	// now look through the list from our lower_bound counting how many
	// match
	int start = i;
	while (i < n && slice_eq(interface, match_interface(&v[i].m))) {
		i++;
	}
	*pnum = i - start;
	*psubs = v + start;
}
