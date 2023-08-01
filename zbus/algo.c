#include "algo.h"

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
