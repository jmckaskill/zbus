#include "sub.h"
#include "busmsg.h"
#include "lib/algo.h"
#include "lib/log.h"

struct subkey {
	int txid;
	const char *mstr;
	uint16_t len;
};

static int cmp_subkey_subscription(const void *key, const void *element)
{
	const struct subkey *k = key;
	const struct subscription *s = element;

	// sort by tx id then full match string

	int diff = k->txid - s->tx->id;
	if (diff) {
		return diff;
	}
	diff = k->len - s->m.len;
	return diff ? diff : memcmp(k->mstr, s->mstr, k->len);
}

void collect_subscription(struct rcu_object **objs,
			  const struct subscription *s)
{
	rcu_register_gc(objs, (rcu_fn)&free, &s->h.rcu);
}

struct subscription *new_subscription(const char *mstr, struct zb_matcher m)
{
	struct subscription *s = fmalloc(sizeof(*s) + m.len);
	memset(s, 0, sizeof(*s));
	s->m = m;
	memcpy(s->mstr, mstr, m.len);
	s->mstr[m.len] = 0;
	return s;
}

struct submap *add_subscription(struct rcu_object **objs,
				const struct submap *om, struct tx *tx,
				const char *str, struct zb_matcher match,
				uint32_t serial)
{
	int idx = bsearch_subscription(om, tx, str, match);
	if (idx < 0) {
		// new subscription
		idx = -(idx + 1);
	} else {
		// subscription is already in the list. Add a duplicate before
		// the existing item.
	}

	struct submap *nm = edit_submap(objs, om, idx, 1);
	struct subscription *s = new_subscription(str, match);
	s->tx = tx;
	s->serial = serial;
	nm->v[idx] = s;
	return nm;
}

struct submap *rm_subscription(struct rcu_object **objs,
			       const struct submap *om, int idx)
{
	const struct subscription *os = om->v[idx];
	struct submap *nm = edit_submap(objs, om, idx, -1);
	collect_subscription(objs, os);
	return nm;
}

int bsearch_subscription(const struct submap *s, struct tx *tx, const char *str,
			 struct zb_matcher m)
{
	struct subkey key;
	key.txid = tx->id;
	key.mstr = str;
	key.len = m.len;

	return lower_bound(&s->hdr, &key, &cmp_subkey_subscription);
}