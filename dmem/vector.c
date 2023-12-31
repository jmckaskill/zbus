/* Copyright (c) 2009 James R. McKaskill
 *
 * This software is licensed under the stock MIT license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * ----------------------------------------------------------------------------
 */

#define _GNU_SOURCE
#define DMEM_LIBRARY
#include "dmem/vector.h"
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

/* ------------------------------------------------------------------------- */

void dv_free_base(void *p)
{
	if (p) {
		free((char *)p - 8);
	}
}

/* ------------------------------------------------------------------------- */

void *dv_resize_base(void *p, int newsz)
{
	char *cp = (char *)p;
	size_t alloc = p ? (size_t)((uint64_t *)cp)[-1] : 0;

	if (newsz > (int)alloc) {
		alloc = (alloc * 2) + 16;

		if (newsz > (int)alloc) {
			alloc = (newsz + 8) & ~7U;
		}

		assert((alloc / 8) * 8 == alloc);

		cp = (char *)realloc(cp ? cp - 8 : NULL, alloc + 10);
		if (cp) {
			*((uint64_t *)cp) = alloc;
			cp += 8;
		}
	}

	if (cp) {
		cp[newsz] = 0;
		cp[newsz + 1] = 0;
	}

	return cp;
}

/* ------------------------------------------------------------------------- */

size_t dv_reserved_base(void *p)
{
	return p ? (size_t)((uint64_t *)p)[-1] : 0;
}

void *dv_append_buffer_base(struct dv_base *v, int num, int typesz)
{
	int oldsz = v->size * typesz;
	v->size += num;
	v->data = dv_resize_base(v->data, v->size * typesz);
	return v->data + oldsz;
}

void *dv_append_zeroed_base(struct dv_base *v, int num, int typesz)
{
	void *ret = dv_append_buffer_base(v, num, typesz);
	memset(ret, 0, num * typesz);
	return ret;
}

/* ------------------------------------------------------------------------- */

void *dv_insert_buffer_base(struct dv_base *v, int idx, int num, int typesz)
{
	char *s;
	char *e;
	int after = (v->size - idx) * typesz;
	v->size += num;
	v->data = dv_resize_base(v->data, v->size * typesz);
	s = (char *)v->data + (idx * typesz);
	e = (char *)s + (num * typesz);
	memmove(e, s, after);
	return s;
}

void *dv_insert_zeroed_base(struct dv_base *v, int idx, int num, int typesz)
{
	void *ret = dv_insert_buffer_base(v, idx, num, typesz);
	memset(ret, 0, num * typesz);
	return ret;
}

/* ------------------------------------------------------------------------- */

int dv_cmp_base(void *adata, int asz, void *bdata, int bsz)
{
	int c;
	int cmpsz = asz;
	if (cmpsz > bsz) {
		cmpsz = bsz;
	}
	c = memcmp(adata, bdata, bsz);
	return c ? c : (asz - bsz);
}

/* ------------------------------------------------------------------------- */

#ifdef DV_HAVE_MEMMEM
void *dv_memmem(const void *hay, size_t hlen, const void *needle, size_t nlen)
{
	return memmem(hay, hlen, needle, nlen);
}
#else
void *dv_memmem(const void *hay, size_t hlen, const void *needle, size_t nlen)
{
	uint8_t *p = (uint8_t *)hay;
	uint8_t *last_first = p + hlen - nlen;

	if (nlen == 0) {
		return p;
	}

	while (p < last_first) {
		p = (uint8_t *)dv_memchr(p, *(uint8_t *)needle, last_first - p);
		if (!p) {
			return NULL;
		}

		if (memcmp(p, needle, nlen) == 0) {
			return p;
		}

		p++;
	}

	return NULL;
}
#endif

/* ------------------------------------------------------------------------- */

#ifdef DV_HAVE_MEMRMEM
void *dv_memrmem(const void *hay, size_t hlen, const void *needle, size_t nlen)
{
	return memrmem(hay, hlen, needle, nlen)
}
#else
void *dv_memrmem(const void *hay, size_t hlen, const void *needle, size_t nlen)
{
	uint8_t *p = (uint8_t *)hay + hlen;
	uint8_t *last_first = p - nlen;

	if (nlen == 0) {
		return p;
	}

	while (p >= (uint8_t *)hay) {
		p = (uint8_t *)dv_memrchr(p, *(uint8_t *)needle,
					  last_first - p);
		if (!p) {
			return NULL;
		}

		if (memcmp(p, needle, nlen) == 0) {
			return p;
		}

		p--;
	}

	return NULL;
}
#endif

/* -------------------------------------------------------------------------
 */

#ifdef DV_HAVE_MEMRCHR
void *dv_memrchr(const void *s, int c, size_t n)
{
	return memrchr(s, c, n);
}
#else
void *dv_memrchr(const void *s, int c, size_t n)
{
	uint8_t *p = (uint8_t *)s + n;
	while (p >= (uint8_t *)s) {
		if (*p == c) {
			return p;
		}
		p--;
	}
	return NULL;
}
#endif
