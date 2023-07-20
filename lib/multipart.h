#pragma once

#include "str.h"
#include <stdint.h>

// enough space to copy a field 256, field length/headers 8 and 8 byte padding 8
#define MULTIPART_WORKING_SPACE (256 + 8 + 8)

struct multipart {
	const char *sig;
	str_t *p; // current part
	char *p_next; // next data byte in current part
	char *p_end; // end of current part
	uint32_t m_off; // offset within message
	uint32_t m_end; // offset where the iterator ends
	// if m_off < m_end then p_next < p_end
	// even if p_next is the start of a part
};

// init_multipart initializes a multipart iterator. parts contains an array of
// buffer segments which add up to at least len bytes. Each part must be 8 byte
// aligned. This allows the parsing to be simpler as small aligned reads (<= 8
// bytes) don't cross part boundaries. parse_message shifts data down to ensure
// this prerequisite.
static void init_multipart(struct multipart *mi, str_t *parts, uint32_t len,
			   const char *signature);

// defragment takes a source set of fragmented data and moves len bytes into the
// working space of dst. It then returns the next src part updating it to remove
// copied data.
extern str_t *defragment(char *buf, str_t *src, uint32_t len);

// parse_multipart_string parses a encoded string which may be split across
// multiple parts. If a string is split across multiple parts it will defragment
// it into the tail working space of the current part. Returns non-zero on
// error. The defragmented string is stored in pslice.
extern int parse_multipart_string(struct multipart *mi, slice_t *pslice);

// parse_multipart_signature is similar to parse_multipart_string but for
// signature types.
extern int parse_multipart_signature(struct multipart *mi, const char **psig);

// skip_multipart_value skips over an encoded value which may be split
// across multipart parts. Returns non-zero on error.
extern int skip_multipart_value(struct multipart *mi);

// skip_multipart_bytes skips forward len bytes skipping to new parts as needed.
// This does not return an error instead the caller should check m_off > m_len
// before calling.
extern void skip_multipart_bytes(struct multipart *mi, uint32_t len);

static uint32_t padding_2(uint32_t off);
static uint32_t padding_4(uint32_t off);
static uint32_t padding_8(uint32_t off);

///////////////////////////
// Inline functions

static inline void init_multipart(struct multipart *mi, str_t *parts,
				  uint32_t len, const char *signature)
{
#ifndef NDEBUG
	uint32_t left = len;
	str_t *p = parts;
	while (left > p->len) {
		// each part except the last must be 8 byte aligned
		assert(p->len > 0 && (p->len & 7) == 0);
		p++;
	}
	assert(p->p);
#endif
	mi->sig = signature;
	mi->p = parts;
	mi->p_next = parts->p;
	mi->p_end = parts->p + parts->len;
	mi->m_off = 0;
	mi->m_end = len;
}

static inline uint32_t padding_2(uint32_t off)
{
	return off & 1;
}

static inline uint32_t padding_4(uint32_t off)
{
	return (4 - (off & 3)) & 3;
}

static inline uint32_t padding_8(uint32_t off)
{
	return (8 - (off & 7)) & 7;
}
