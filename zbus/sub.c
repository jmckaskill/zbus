#include "sub.h"
#include "algo.h"
#include "busmsg.h"
#include "dmem/common.h"

static int insert_compare(const void *key, const void *element)
{
	const struct subscription *k = key;
	const struct subscription *e = *(struct subscription **)element;

	// sort by interface length
	int dsz = k->match.interface_len - e->match.interface_len;
	if (dsz) {
		return dsz;
	}

	// then interface string
	int cmp = memcmp(k->match.base + k->match.interface_off,
			 e->match.base + e->match.interface_off,
			 k->match.interface_len);
	if (cmp) {
		return cmp;
	}

	// then tx pointer
	int diff = (int)(k->tx - e->tx);
	if (diff) {
		return diff;
	}

	// then the full match string length
	dsz = k->match.str_len - e->match.str_len;
	if (dsz) {
		return dsz;
	}

	// then the match string itself
	return memcmp(k->match.base, e->match.base, k->match.str_len);
}

static int find_compare(const void *key, const void *element)
{
	const slice_t *k = key;
	const struct subscription *e = *(struct subscription **)element;
	int dsz = k->len - e->match.interface_len;
	if (dsz) {
		return dsz;
	}
	return memcmp(k->p, e->match.base + e->match.interface_off, k->len);
}

static void free_sub(struct subscription *s)
{
	if (s) {
		deref_tx(s->tx);
		free(s);
	}
}

void free_subscription_map(struct subscription_map *m)
{
	if (m) {
		for (int i = 0; i < m->len; i++) {
			free_sub(m->v[i]);
		}
		free(m);
	}
}

static int add_subscription(struct rcu_writer *w,
			    struct subscription_map **pmap,
			    const struct match *match, struct tx *tx,
			    struct circ_list *owner)
{
	struct subscription key;
	key.match = *match;
	key.tx = tx;

	struct subscription_map *old = *pmap;
	size_t esz = sizeof(old->v[0]);
	int n = old ? old->len : 0;
	int idx = lower_bound(&key, old->v, n, esz, &insert_compare);

	if (idx >= 0) {
		// subscription is already in the list. Increment the count.
		// This field is only used by add/rm subscription under the
		// write lock so we don't need to publish a new RCU data.
		struct subscription *s = old->v[idx];
		s->count++;
		return 0;
	}
	idx = -(idx + 1);

	struct subscription_map *m = malloc(sizeof(*m) + (n + 1) * esz);
	struct subscription *s = malloc(sizeof(*s) + match->str_len);
	if (!m || !s) {
		free(m);
		free(s);
		return ERR_OOM;
	}
	// copy the match across
	s->match = *match;
	memcpy(s->mstr, match->base, match->str_len);
	s->match.base = s->mstr;
	s->tx = tx;
	ref_tx(s->tx);
	s->count = 1;
	circ_add(&s->owner, owner);

	// copy the subscriptions across
	m->len = n + 1;
	memcpy(m->v, old->v, idx * esz);
	m->v[idx] = s;
	memcpy(m->v + idx + 1, old->v + idx, (n - idx) * esz);

	// collect the old list
	rcu_collect(w, old, &free);
	*pmap = m;
	return 0;
}

static int rm_subscription(struct rcu_writer *w, struct subscription_map **pmap,
			   const struct match *match, struct tx *tx)
{
	struct subscription key;
	key.match = *match;
	key.tx = tx;

	struct subscription_map *old = *pmap;
	size_t esz = sizeof(old->v[0]);
	int n = old ? old->len : 0;
	int idx = lower_bound(&key, old->v, n, esz, &insert_compare);
	if (idx < 0) {
		return ERR_NOT_FOUND;
	}

	struct subscription *s = old->v[idx];
	if (--s->count > 0) {
		// Ref count is only used in add/rm functions within write lock.
		// So safe to modify directly without duplicating the data.
		return 0;
	}

	struct subscription_map *m = malloc(sizeof(*m) + (n - 1) * esz);
	if (!m) {
		return ERR_OOM;
	}
	m->len = n - 1;
	memcpy(m->v, old->v, idx * esz);
	memcpy(m->v + idx, old->v + idx + 1, (n - idx - 1) * esz);

	circ_remove(&s->owner);
	rcu_collect(w, s, (rcu_free_fn)&free_sub);
	rcu_collect(w, old, (rcu_free_fn)&free);
	*pmap = m;
	return 0;
}

int addrm_subscription(struct rcu_writer *w, struct subscription_map **pmap,
		       bool add, const struct match *m, struct tx *tx,
		       struct circ_list *o)
{
	if (add) {
		return add_subscription(w, pmap, m, tx, o);
	} else {
		return rm_subscription(w, pmap, m, tx);
	}
}

int find_subscriptions(struct subscription_map *m, slice_t iface,
		       struct subscription ***pfirst)
{
	int n = m ? m->len : 0;
	int idx = lower_bound(&iface, m->v, n, sizeof(m->v[0]), &find_compare);
	if (idx < 0) {
		return 0;
	}
	*pfirst = &m->v[idx];
	int j = 0;
	while (idx + j < n && !find_compare(&iface, &m->v[idx + j])) {
		j++;
	}
	return j;
}
