#pragma once

#include "types.h"
#include "str8.h"
#include <stdlib.h>

/////////////////////
// raw data decoding

ZB_INLINE void zb_init_iterator(struct zb_iterator *ii, const char *sig,
				char *data, size_t sz);

ZB_INLINE int zb_get_iter_error(struct zb_iterator *p);
ZB_INLINE void zb_set_iter_error(struct zb_iterator *p);

// check zb_get_iter_error before using any of these values
ZB_EXTERN uint8_t zb_parse_byte(struct zb_iterator *p);
ZB_EXTERN bool zb_parse_bool(struct zb_iterator *p);
ZB_EXTERN int16_t zb_parse_i16(struct zb_iterator *p);
ZB_EXTERN uint16_t zb_parse_u16(struct zb_iterator *p);
ZB_EXTERN int32_t zb_parse_i32(struct zb_iterator *p);
ZB_EXTERN uint32_t zb_parse_u32(struct zb_iterator *p);
ZB_EXTERN int64_t zb_parse_i64(struct zb_iterator *p);
ZB_EXTERN uint64_t zb_parse_u64(struct zb_iterator *p);
ZB_EXTERN double zb_parse_double(struct zb_iterator *p);
ZB_EXTERN char *zb_parse_string(struct zb_iterator *p, size_t *psz);
ZB_EXTERN char *zb_parse_path(struct zb_iterator *p, size_t *psz);
ZB_EXTERN const zb_str8 *zb_parse_str8(struct zb_iterator *p);
ZB_EXTERN const char *zb_parse_signature(struct zb_iterator *p);
ZB_EXTERN void zb_parse_variant(struct zb_iterator *p, struct zb_variant *pv);
ZB_EXTERN void zb_enter_struct(struct zb_iterator *p);
ZB_EXTERN void zb_exit_struct(struct zb_iterator *p);
ZB_EXTERN void zb_enter_dict_entry(struct zb_iterator *p);
ZB_EXTERN void zb_exit_dict_entry(struct zb_iterator *p);

ZB_EXTERN void zb_enter_array(struct zb_iterator *p, struct zb_scope *s);
ZB_EXTERN void zb_exit_array(struct zb_iterator *p, struct zb_scope *s);
ZB_EXTERN bool zb_array_has_more(struct zb_iterator *p, struct zb_scope *s);

// zb_skip skips over a complete value optionally returning an iterator to the
// data. It does not validate the data.
ZB_EXTERN void zb_skip(struct zb_iterator *p, struct zb_iterator *pval);

ZB_EXTERN int zb_skip_signature(const char **psig);
ZB_INLINE int zb_cmp_signature(const char *sig, const char *test);

//////////////////////////////////////
// message decoding

// buffer must be at least ZB_MIN_MSG_SIZE long
// returns non-zero on invalid message header
// returns zero on success and sets phdr and pbody to the header and body sizes
// returns number of bytes in header or message
ZB_EXTERN int zb_parse_size(char *p, size_t *phdr, size_t *pbody);

// buffer needs to be at least as long as the hdr size returned
// by zb_parse_size
// returns non-zero on error
ZB_EXTERN int zb_parse_header(struct zb_message *msg, char *p);

////////////////////////////////////////
// inline implementations

ZB_INLINE void zb_init_iterator(struct zb_iterator *ii, const char *sig,
				char *p, size_t sz)
{
	assert(sz < ZB_MAX_MSG_SIZE);
	ii->base = p;
	ii->next = 0;
	ii->end = (uint32_t)sz;
	ii->nextsig = sig;
}

ZB_INLINE int zb_get_iter_error(struct zb_iterator *p)
{
	return p->next > p->end;
}

ZB_INLINE void zb_set_iter_error(struct zb_iterator *p)
{
	p->next = p->end + 1;
}

ZB_INLINE int zb_cmp_signature(const char *sig, const char *test)
{
	// depending on where it's come from sig may contain arguments
	// after the one we're interested in. As long as test is a complete
	// type, which it should be as the programmer provided it, we just
	// need to test up to strlen(test)
	return strncmp(sig, test, strlen(test));
}