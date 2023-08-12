#pragma once
#include "rcu.h"
#include "lib/algo.h"
#include <stdatomic.h>

struct vector {
	struct rcu_object rcu;
	int _len;
};

struct void_vector {
	struct vector h;
	const void *v[1];
};

static int vector_len(const struct vector *m);
static void free_vector(struct vector *m);

// edit_vector is called when you want to edit a vector. It returns a new
// vector that can then be modified and released. After committing the change
// the old vector must be committed. To insert items, use a positive insert. To
// edit but not add/remove any items use an insert of 0. To remove items use a
// negative insert.
struct vector *edit_vector(struct rcu_object **objs, const struct vector *om,
			   int idx, int insert);

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
typedef int (*vec_cmp_fn)(const void *key, const void *element);
int lower_bound(const struct vector *m, const void *key, vec_cmp_fn cmp);

//////////////////////////
// inline implementations

static inline int vector_len(const struct vector *m)
{
	return m ? m->_len : 0;
}
static inline void free_vector(struct vector *m)
{
	free(m);
}
