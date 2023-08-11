#include "vector.h"
#include "lib/log.h"
#include <string.h>

struct vector *edit_vector(struct rcu_object **objs, const struct vector *ob,
			   int idx, int num)
{
	const struct void_vector *ov = (struct void_vector *)ob;
	int n = vector_len(ob);
	size_t esz = sizeof(ov->v[0]);

	assert(0 <= idx && idx <= n);

	if (ob) {
		static_assert(offsetof(struct vector, rcu) == 0, "");
		rcu_register_gc(objs, (rcu_fn)&free, &ob->rcu);
	}

	assert(n + num >= 0);
	if (n + num <= 0) {
		return NULL;
	}

	struct void_vector *nv = fmalloc(sizeof(*nv) + (n + num) * esz);
	if (num > 0) {
		memcpy((void *)(nv->v), ov->v, idx * esz);
		memset((void *)(nv->v + idx), 0, num * esz);
		memcpy((void *)(nv->v + idx + num), ov->v + idx,
		       (n - idx) * esz);
	} else {
		int rm = -num;
		memcpy((void *)(nv->v), ov->v, idx * esz);
		memcpy((void *)(nv->v + idx), ov->v + idx + rm,
		       (n - idx - rm) * esz);
	}
	nv->h._len = n + num;
	return &nv->h;
}

int lower_bound(const struct vector *m, const void *key, vec_cmp_fn cmp)
{
	struct void_vector *b = (struct void_vector *)m;
	int low = 0;
	int high = vector_len(m);
	while (low < high) {
		int mid = low + (high - low) / 2;
		int sign = cmp(key, b->v[mid]);
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
