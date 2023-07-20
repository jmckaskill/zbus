#include "multipart.h"
#include "types.h"
#include "parse.h"

void skip_multipart_bytes(struct multipart *mi, uint32_t len)
{
	mi->m_off += len;
	assert(mi->m_off <= mi->m_end);
	for (;;) {
		mi->p_next += len;
		if (mi->p_next < mi->p_end) {
			// next data is in this part
			return;
		} else if (mi->m_off == mi->m_end) {
			// hit the end of the message
			return;
		}

		// consume the overflow bytes in the next part
		len = mi->p_next - mi->p_end;
		mi->p++;
		mi->p_next = mi->p->p;
		mi->p_end = mi->p->p + mi->p->len;
	}
}

str_t *defragment(char *buf, str_t *src, uint32_t len)
{
	// copy complete parts
	while (len >= src->len) {
		memcpy(buf, src->p, src->len);
		buf += src->len;
		len -= src->len;
		src->len = 0;
		src++;
	}
	// copy partial part
	memcpy(buf, src->p, len);
	src->p += len;
	src->len -= len;
	src->cap -= len;
	return src;
}

static char *compact_data(struct multipart *mi, uint32_t len)
{
	char *ret = mi->p_next;
	mi->m_off += len;
	mi->p_next += len;

	if (mi->p_next >= mi->p_end && mi->m_off < mi->m_end) {
		uint32_t need = mi->p_next - mi->p_end;
		str_t *p = mi->p;
		if (need > p->cap - p->len) {
			return NULL;
		}
		str_t *n = defragment(p->p + p->len, p + 1, need);
		p->len += need;
		mi->p = n;
		mi->p_next = n->p;
		mi->p_end = n->p + n->len;
	}

	return ret;
}

int parse_multipart_string(struct multipart *mi, slice_t *pslice)
{
	uint32_t pad = padding_4(mi->m_off);
	if (mi->m_off + pad + 4 > mi->m_end || *mi->sig != TYPE_STRING) {
		return -1;
	}
	if (pad) {
		skip_multipart_bytes(mi, pad);
	}
	uint32_t len = read_native_4(mi->p_next);
	if (len > MAX_ARRAY_SIZE || mi->m_off + 4 + len + 1 > mi->m_end) {
		return -1;
	}
	char *p = compact_data(mi, 4 + len + 1);
	pslice->p = p + 4;
	pslice->len = len;
	mi->sig++;
	return check_string(*pslice);
}

int parse_multipart_signature(struct multipart *mi, const char **psig)
{
	if (mi->m_off + 1 > mi->m_end || *mi->sig != TYPE_SIGNATURE) {
		return -1;
	}
	uint8_t len = *(uint8_t *)(mi->p_next);
	if (mi->m_off + 1 + len + 1 > mi->m_end) {
		return -1;
	}
	char *p = compact_data(mi, 1 + len + 1);
	*psig = p + 1;
	mi->sig++;
	return check_string(make_slice2(p + 1, len));
}

static uint32_t array_padding(uint32_t off, char type)
{
	switch (type) {
	case TYPE_INT16:
	case TYPE_UINT16:
		return padding_2(off);

	case TYPE_INT32:
	case TYPE_UINT32:
	case TYPE_BOOL:
	case TYPE_ARRAY:
	case TYPE_STRING:
		return padding_4(off);

	case TYPE_INT64:
	case TYPE_UINT64:
	case TYPE_DOUBLE:
	case TYPE_DICT_BEGIN:
	case TYPE_STRUCT_BEGIN:
		return padding_8(off);

	case TYPE_BYTE:
	case TYPE_SIGNATURE:
	case TYPE_VARIANT:
	default:
		return 0;
	}
}

int skip_multipart_value(struct multipart *mi)
{
	// We're about to filter out this data, so we don't need to validate it.
	// Instead we're just trying to skip over the data assuming it's valid.
	// If the data is invalid then we just need to not crash.
	const char *stack[MAX_TYPE_DEPTH];
	int stackn = 0;

	const char *sig = mi->sig;

	for (;;) {
		switch (*(sig++)) {
		case '\0':
			if (stackn) {
				// we've reached the end of the variant
				sig = stack[--stackn];
				continue;
			}
			mi->sig = sig;
			return 0;

		case TYPE_BYTE:
			if (mi->m_off >= mi->m_end) {
				return -1;
			}
			skip_multipart_bytes(mi, 1);
			break;

		case TYPE_INT16:
		case TYPE_UINT16: {
			unsigned skip = 2 + padding_2(mi->m_off);
			if (mi->m_off + skip > mi->m_end) {
				return -1;
			}
			skip_multipart_bytes(mi, skip);
			break;
		}

		case TYPE_BOOL:
		case TYPE_INT32:
		case TYPE_UINT32: {
			unsigned skip = 4 + padding_4(mi->m_off);
			if (mi->m_off + skip > mi->m_end) {
				return -1;
			}
			skip_multipart_bytes(mi, skip);
			break;
		}

		case TYPE_INT64:
		case TYPE_UINT64:
		case TYPE_DOUBLE: {
			unsigned skip = 8 + padding_8(mi->m_off);
			if (mi->m_off + skip > mi->m_end) {
				return -1;
			}
			skip_multipart_bytes(mi, skip);
			break;
		}

		case TYPE_STRING:
		case TYPE_PATH: {
			unsigned pad = padding_4(mi->m_off);
			if (mi->m_off + pad + 4 > mi->m_end) {
				return -1;
			}
			skip_multipart_bytes(mi, pad);
			uint32_t len = read_native_4(mi->p_next);
			if (len > MAX_ARRAY_SIZE ||
			    mi->m_off + 4 + len + 1 > mi->m_end) {
				return -1;
			}
			skip_multipart_bytes(mi, 4 + len + 1);
			break;
		}

		case TYPE_SIGNATURE: {
			if (mi->m_off >= mi->m_end) {
				return -1;
			}
			uint8_t len = *(uint8_t *)mi->p_next;
			if (mi->m_off + 1 + len > mi->m_end) {
				return -1;
			}
			skip_multipart_bytes(mi, 1 + len + 1);
			break;
		}

		case TYPE_ARRAY: {
			char type = *sig;
			unsigned pad1 = padding_4(mi->m_off);
			if (mi->m_off + pad1 + 4 > mi->m_end ||
			    skip_signature(&sig, true)) {
				return -1;
			}
			skip_multipart_bytes(mi, pad1);
			uint32_t len = read_native_4(mi->p_next);
			uint32_t pad2 = array_padding(mi->m_off + 4, type);
			if (len > MAX_ARRAY_SIZE ||
			    mi->m_off + 4 + pad2 + len > mi->m_end) {
				return -1;
			}
			skip_multipart_bytes(mi, 4 + pad2 + len);
			break;
		}

		case TYPE_STRUCT_BEGIN: {
			unsigned pad = padding_8(mi->m_off);
			if (mi->m_off + pad > mi->m_end) {
				skip_multipart_bytes(mi, pad);
			}
			break;
		}

		case TYPE_STRUCT_END:
			break;

		case TYPE_VARIANT: {
			// A nested variant could legitimitely exist
			// within a struct within the header field. Need
			// to save the current signature to a stack.
			const char **psig = &stack[stackn++];
			if (psig == stack + sizeof(stack)) {
				return -1;
			}
			// save the current signature to the stack and
			// get the new one from the data
			*psig = sig;
			mi->sig = "g";
			if (parse_multipart_signature(mi, &sig)) {
				return -1;
			}
			break;
		}

		case TYPE_DICT_BEGIN:
		case TYPE_DICT_END:
			// dict can not exist outside an array
		default:
			return -1;
		}
	}
}

#if 0 
ndef NDEBUG
#define BUFSZ (16 + MULTIPART_WORKING_SPACE)
void TEST_multipart()
{
	char buf1[BUFSZ] = { 0, 1, 2,  3,  4,  5,  6,  7,
			     8, 9, 10, 11, 12, 13, 14, 15 };
	char buf2[BUFSZ] = { 15, 14, 13, 12, 11, 10, 9, 8,
			     7,	 6,  5,	 4,  3,	 2,  1, 0 };

	str_t s[2];
	s[0].p = buf1;
	s[0].len = 16;
	s[0].cap = sizeof(buf1);
	s[1].p = buf2;
	s[1].len = 16;
	s[1].cap = sizeof(buf2);
}
#endif
