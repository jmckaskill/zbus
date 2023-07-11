#include "parse.h"
#include <string.h>

const char null_string_bytes[] = {0};
struct string null_string = {null_string_bytes,0};

int parse_byte(struct parser *p, uint8_t *pv) {
    const char *n = p->n + 1;
    if (n > p->e) {
        return -1;
    }
    *pv = *(uint8_t*)p->n;
    p->n = n;
    return 0;
}

int parse_bool(struct parser *p, bool *pv) {
    const char *n = ALIGN_PTR_UP(const char*, p->n, 4);
    const char *e = n + 4;
    if (e > p->e) {
        return -1;
    }
    uint32_t u = *(uint32_t*)n;
    if (u > 1) {
        return -1;
    }
    *pv = (u != 0);
    p->n = e;
    return 0;
}

int parse_uint16(struct parser *p, uint16_t *pv) {
    const char *n = ALIGN_PTR_UP(const char*, p->n, 2);
    const char *e = n + 2;
    if (e > p->e) {
        return -1;
    }
    *pv = *(uint16_t*)n;
    p->n = e;
    return 0;
}

int parse_uint32(struct parser *p, uint32_t *pv) {
    const char *n = ALIGN_PTR_UP(const char*, p->n, 4);
    const char *e = n + 4;
    if (e > p->e) {
        return -1;
    }
    *pv = *(uint32_t*)n;
    p->n = e;
    return 0;
}

int parse_uint64(struct parser *p, uint64_t *pv) {
    const char *n = ALIGN_PTR_UP(const char*, p->n, 8);
    const char *e = n + 8;
    if (e > p->e) {
        return -1;
    }
    *pv = *(uint64_t*)n;
    p->n = e;
    return 0;
}

static int parse_string_bytes(struct parser *p, struct string *pv, unsigned len) {
    const char *n = p->n;
    const char *e = n + len + 1;
    if (e > p->e) {
        return -1;
    }
    // make sure there are no nul bytes in the string and that it is nul terminated
    if (memchr(n, len, 0) || n[len]) {
        return -1;
    }
    p->n = e;
    pv->p = n;
    pv->len = (unsigned) len;
    return 0;
}

int parse_signature(struct parser *p, struct string *pv) {
    uint8_t len;
    return parse_byte(p, &len) || parse_string_bytes(p, pv, len);
}

int parse_string(struct parser *p, struct string *pv) {
    uint32_t len;
    return parse_uint32(p, &len) || parse_string_bytes(p, pv, len);
}

int parse_path(struct parser *p, struct string *pv) {
    if (parse_string(p, pv) || pv->len > 255) {
        return -1;
    }
    const char *s = pv->p;
    if (*(s++) != '/') {
        // path must begin with / and can not be the empty string
        return -1;
    }
    if (!*s) {
        // trailing / only allowed if the path is "/"
        return 0;
    }
    const char *segment = s;
    for (;;) {
        // only [A-Z][a-z][0-9]_ are allowed
        // / and \0 are not allowed as the first char of a segment
        // this rejects multiple / in sequence and a trailing / respectively
        if (('A' <= *s && *s <= 'Z') || ('a' <= *s && *s <= 'z') || ('0' <= *s && *s <= '9') || *s == '_') {
            s++;
        } else if (s > segment && *s == '/') {
            segment = ++s;
        } else if (s > segment && *s == '\0') {
            return 0;
        } else {
            return -1;
        }
    }
}

int parse_variant(struct parser *p, struct parser *pdata, struct string *psig) {
    if (parse_signature(p, psig)) {
        return -1;
    }
    const char *sig = psig->p;
    pdata->n = p->n;
    if (skip_value(p, &sig) || *sig) {
        return -1;
    }
    pdata->e = p->n;
    return 0;
}

int parse_array(struct parser *p, struct parser *pdata, const char *sig) {
    // get the array bytes
    uint32_t len;
    if (parse_uint32(p, &len)) {
        return -1;
    }
    const char *n;
    // need to parse the signature to determine the alignment of the array data
    switch (*sig) {
    case TYPE_BYTE:
    case TYPE_SIGNATURE:
    case TYPE_VARIANT:
        n = p->n;
        break;
    case TYPE_INT16:
    case TYPE_UINT16:
        n = ALIGN_PTR_UP(const char*, p->n, 2);
        break;
    case TYPE_BOOL:
    case TYPE_INT32:
    case TYPE_UINT32:
    case TYPE_STRING:
    case TYPE_PATH:
    case TYPE_ARRAY:
        n = ALIGN_PTR_UP(const char*, p->n, 4);
        break;
    case TYPE_INT64:
    case TYPE_UINT64:
    case TYPE_DOUBLE:
    case TYPE_DICT_BEGIN:
    case TYPE_STRUCT_BEGIN:
        n = ALIGN_PTR_UP(const char*, p->n, 8);
        break;
    default:
        return -1;    
    }

    if (n + len > p->e) {
        return -1;
    }
    pdata->n = n;
    pdata->e = n + len;
    p->n = pdata->e;
    return 0;
}

int skip_signature(const char **psig) {
    const char *sig = *psig;
    switch (*(sig++)) {
    case TYPE_BYTE:
    case TYPE_BOOL:
    case TYPE_INT16:
    case TYPE_UINT16:
    case TYPE_INT32:
    case TYPE_UINT32:
    case TYPE_INT64:
    case TYPE_UINT64:
    case TYPE_DOUBLE:
    case TYPE_STRING:
    case TYPE_PATH:
    case TYPE_SIGNATURE:
    case TYPE_VARIANT:
        break;
    case TYPE_ARRAY:
        if (skip_signature(&sig)) {
            return -1;
        }
        break;
    case TYPE_DICT_BEGIN:
        if (skip_signature(&sig) || skip_signature(&sig)) {
            return -1;
        }
        if (*(sig++) != TYPE_DICT_END) {
            return -1;
        }
        break;
    case TYPE_STRUCT_BEGIN:
        do {
            if (skip_signature(&sig)) {
                return -1;
            }
        } while (*sig != TYPE_STRUCT_END);
        sig++;
        break;
    default:
        return -1;
    }

    *psig = sig;
    return 0;
}

int skip_value(struct parser *p, const char **psig) {
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    struct string str;
    struct parser data;
    switch (*((*psig)++)) {
    case TYPE_BYTE:
        return parse_byte(p, &u8);
    case TYPE_INT16:
    case TYPE_UINT16:
        return parse_uint16(p, &u16);
    case TYPE_BOOL:
    case TYPE_INT32:
    case TYPE_UINT32:
        return parse_uint32(p, &u32);
    case TYPE_INT64:
    case TYPE_UINT64:
    case TYPE_DOUBLE:
        return parse_uint64(p, &u64);
    case TYPE_STRING:
    case TYPE_PATH:
        return parse_string(p, &str);
    case TYPE_SIGNATURE:
        return parse_signature(p, &str);
    case TYPE_VARIANT:
        return parse_variant(p, &data, &str);
    case TYPE_ARRAY: 
        return parse_array(p, &data, *psig) || skip_signature(psig);
    case TYPE_STRUCT_BEGIN:
        p->n = ALIGN_PTR_UP(const char*, p->n, 8);
        if (p->n > p->e) {
            return -1;
        }
        do {
            if (skip_value(p, psig)) {
                return -1;
            }
        } while (**psig != TYPE_STRUCT_END);
        (*psig)++;
        return 0;

    case TYPE_DICT_BEGIN:
        // Can only occur as an array element. So there is never a need
        // to skip just a dict entry.
    default:
        return -1;
    }
}
