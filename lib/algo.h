#pragma once
#include <stddef.h>

#ifndef container_of
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr)-offsetof(type, member)))
#endif

#ifdef _MSC_VER
#include <intrin.h>
static inline int x_ffs(unsigned long u)
{
	unsigned long idx;
	return _BitScanForward(&idx, u) ? (idx + 1) : 0;
}
#else
#define x_ffs __builtin_ffs
#endif
