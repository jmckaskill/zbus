#include "addr.h"
#include "sub.h"
#include "rcu.h"
#include "busmsg.h"
#include "dmem/common.h"
#include <limits.h>
#include <string.h>

struct address *update_address(struct rcu_writer *w, struct address_map **pmap,
			       int idx)
{
	struct address_map *old = *pmap;
	struct address *oa = old->v[idx];
	int n = old->len;
	size_t esz = sizeof(old->v[0]);

	struct address_map *m = malloc(sizeof(*m) + n * esz);
	struct address *a = malloc(sizeof(*a) + oa->name.len);
	if (!m || !a) {
		free(m);
		free(a);
		return NULL;
	}

	// copy the address info across and fix up pointers
	memcpy(a, oa, sizeof(*a) + oa->name.len);
	if (a->owner_list.next) {
		a->owner_list.prev->next = &a->owner_list;
		a->owner_list.next->prev = &a->owner_list;
	}

	// copy the map data across, replacing the address of interest
	m->len = old->len;
	memcpy(m->v, old->v, n * esz);
	m->v[idx] = a;

	// just a shallow free not deep (free_address) as we've copied all the
	// contents to the new structs
	rcu_collect(w, oa, &free);
	rcu_collect(w, old, &free);
	*pmap = m;
	return a;
}

struct address *add_address(struct rcu_writer *w, struct address_map **pmap,
			    int idx, slice_t name)
{
	struct address_map *old = *pmap;
	int n = old ? old->len : 0;
	size_t esz = sizeof(old->v[0]);

	if (idx < 0 || idx > n) {
		return NULL;
	}

	struct address_map *m = malloc(sizeof(*m) + (n + 1) * esz);
	struct address *a = malloc(sizeof(*a) + name.len);
	struct rcu_writer *subw = new_rcu_writer();
	struct rcu_reader *subr = new_rcu_reader(subw);
	if (!m || !a || !subw || !subr) {
		free_rcu_reader(subw, subr);
		free_rcu_writer(subw);
		free(m);
		free(a);
		return NULL;
	}

	// setup the new address
	a->subs_reader = subr;
	a->subs_writer = subw;
	a->tx = NULL;
	circ_init(&a->owner_list);
	a->owner_id = -1;
	a->autostart = NULL;
	memcpy(&a->name.p, name.p, name.len);
	a->name.len = name.len;

	// copy the old map data across, inserting the new record
	m->len = n + 1;
	memcpy(m->v, old->v, idx * esz);
	m->v[idx] = a;
	memcpy(m->v + idx + 1, old->v + idx, (n - idx) * esz);

	*pmap = m;
	rcu_collect(w, old, &free);

	return a;
}

struct autostart *new_autostart(void)
{
	struct autostart *a = malloc(sizeof(*a));
	if (!a || cnd_init(&a->wait)) {
		free(a);
		return NULL;
	}
	a->last_launch = (time_t)0;
	a->waiters = 0;
	return a;
}

void free_autostart(struct autostart *a)
{
	if (a) {
		cnd_destroy(&a->wait);
		free(a);
	}
}

static void free_address(struct address *a)
{
	if (a) {
		free_autostart(a->autostart);
		free_rcu_reader(a->subs_writer, a->subs_reader);
		free_rcu_writer(a->subs_writer);
		deref_tx(a->tx);
		circ_remove(&a->owner_list);
		free(a);
	}
}

void free_address_map(struct address_map *m)
{
	if (m) {
		for (int i = 0; i < m->len; i++) {
			free_address(m->v[i]);
		}
		free(m);
	}
}

int remove_address(struct rcu_writer *w, struct address_map **pmap, int idx)
{
	struct address_map *old = *pmap;
	if (!old || idx < 0) {
		return ERR_NO_REMOTE;
	}
	int n = old->len;
	size_t esz = sizeof(old->v[0]);

	struct address *a = old->v[idx];
	struct address_map *m = malloc(sizeof(*m) + (n - 1) * esz);
	if (!m) {
		return ERR_OOM;
	}

	// clean up the address record
	rcu_collect(w, a, (rcu_free_fn)&free_address);

	// copy the old map data across, removing the record
	m->len = n - 1;
	memcpy(m->v, old->v, idx * esz);
	memcpy(m->v + idx, old->v + idx + 1, (n - idx - 1) * esz);
	*pmap = m;
	rcu_collect(w, old, &free);

	return 0;
}

static int compare_id(const void *key, const void *element)
{
	int id = (int)(uintptr_t)key;
	const struct address *addr = *(struct address **)element;
	return id - addr->owner_id;
}

int find_unique_address(struct address_map *m, int id)
{
	return lower_bound((void *)(uintptr_t)id, m->v, m ? m->len : 0,
			   sizeof(m->v[0]), &compare_id);
}

static int compare_name(const void *key, const void *element)
{
	slice_t k = *(slice_t *)key;
	const struct address *addr = *(struct address **)element;
	int dsz = k.len - addr->name.len;
	return dsz ? dsz : memcmp(k.p, addr->name.p, k.len);
}

int find_named_address(struct address_map *m, slice_t name)
{
	return lower_bound(&name, m->v, m ? m->len : 0, sizeof(m->v[0]),
			   &compare_name);
}

size_t id_to_address(char *buf, int id)
{
	assert(id >= 0);
	size_t pfxlen = strlen(UNIQ_ADDR_PREFIX);
	memcpy(buf, UNIQ_ADDR_PREFIX, pfxlen);
	char *p = buf + UNIQ_ADDR_MAXLEN;
	do {
		*(--p) = (id % 10) + '0';
		id /= 10;
	} while (id);
	size_t n = buf + UNIQ_ADDR_MAXLEN - p;
	memmove(buf + pfxlen, p, n);
	return pfxlen + n;
}

int address_to_id(slice_t s)
{
	const char *p = s.p + strlen(UNIQ_ADDR_PREFIX);
	int len = s.len - strlen(UNIQ_ADDR_PREFIX);
	int id = 0;
	for (int i = 0; i < len; i++) {
		char start = (i || len == 1) ? '0' : '1';
		if (p[i] < start || p[i] > '9' || id >= (INT_MAX / 10)) {
			return -1;
		}
		id = (id * 10) | (p[i] - '0');
	}
	return id;
}
