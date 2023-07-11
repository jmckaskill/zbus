#include "message.h"
#include "parse.h"
#include <assert.h>
#include <stdlib.h>

union endian_test {
    uint16_t u;
    uint8_t b[2];
};

static union endian_test g_native_endian = {0x426C}; // "Bl"

uint8_t native_endian() {
    return g_native_endian.b[0];
}

static_assert(sizeof(struct msg_header) == 16, "invalid packing");


const char *message_data(const struct msg_header *h) {
    return ((const char*)(h+1)) + ALIGN_UINT_UP(h->header_len, 8);
}

int raw_message_length(const struct msg_header *h) {
    if (h->endian != native_endian()) {
        return -1;
    }
    unsigned len = sizeof(struct msg_header) 
                 + ALIGN_UINT_UP(h->header_len, 8)
                 + h->body_len;
    if (len > MAX_MESSAGE_SIZE) {
        return -1;
    }
    return (int) len;
}

int check_member(const char *p) {
    if (!*p) {
        return -1;
    }
    const char *begin = p;
    while (*p) {
        // must be composed of [A-Z][a-z][0-9]_ and must not start with a digit
        if (('A' <= *p && *p <= 'Z')
        || ('a' <= *p && *p <= 'z')
        || *p == '_'
        || (p > begin && '0' <= *p && *p <= '9')) {
            p++;
        } else {
            return -1;
        }
    }
    return p - begin > 255;
}

static int check_name(const char *p, size_t maxsz) {
    int have_dot = 0;
    const char *begin = p;
    const char *segment = p;
    for (;;) {
        // must be composed of [A-Z][a-z][0-9]_ and must not start with a digit
        // segments can not be zero length ie no two dots in a row nor a leading dot
        // the name as a whole must comprise at least two segments ie have a dot
        // and must not be longer than the requested size
        if (('A' <= *p && *p <= 'Z')
        || ('a' <= *p && *p <= 'z')
        || *p == '_'
        || (p > segment && '0' <= *p && *p <= '9')) {
            p++;
        } else if (p > segment && *p == '.') {
            segment = ++p;
            have_dot = 1;
        } else if (p > segment && have_dot && *p == '\0' && p - begin <= maxsz) {
            return 0;
        } else {
            return -1;
        }
    }
}

int check_unique_address(const char *p) {
    return *p != ':' || check_name(p+1, 254);
}

int check_address(const char *p) {
    return check_unique_address(p) && check_known_address(p);
}

int check_interface(const char *p) {
    return check_name(p, 255);
}

int parse_header_fields(struct msg_fields *f, const struct msg_header *h) {
    f->reply_serial = -1;
    f->fdnum = 0;
    f->path = null_string;
    f->interface = null_string;
    f->member = null_string;
    f->error = null_string;
    f->destination = null_string;
    f->sender = null_string;
    f->signature = null_string;

    struct parser p;
    init_parser(&p, (char*)(h+1), h->header_len);
    while (parser_len(&p)) {
        uint8_t type;
        struct parser data;
        struct string sig;
        uint32_t serial;
        if (parse_struct_begin(&p) || parse_byte(&p, &type) || parse_variant(&p, &data, &sig)) {
            return -1;
        }
        switch (type) {
        case HEADER_PATH:
            if (sig.p[0] != TYPE_PATH || parse_path(&data, &f->path)) {
                return -1;
            }
            break;
        case HEADER_INTERFACE:
            if (sig.p[0] != TYPE_STRING || parse_string(&data, &f->interface) || check_interface(f->interface.p)) {
                return -1;
            }
            break;
        case HEADER_MEMBER:
            if (sig.p[0] != TYPE_STRING || parse_string(&data, &f->member) || check_member(f->member.p)) {
                return -1;
            }
            break;
        case HEADER_ERROR_NAME:
            if (sig.p[0] != TYPE_STRING || parse_string(&data, &f->error) || check_error_name(f->error.p)) {
                return -1;
            }
            break;
        case HEADER_DESTINATION:
            if (sig.p[0] != TYPE_STRING || parse_string(&data, &f->destination) || check_address(f->destination.p)) {
                return -1;
            }
            break;
        case HEADER_SENDER:
            if (sig.p[0] != TYPE_STRING || parse_string(&data, &f->sender) || check_unique_address(f->sender.p)) {
                return -1;
            }
            break;
        case HEADER_SIGNATURE:
            if (sig.p[0] != TYPE_SIGNATURE || parse_signature(&data, &f->signature)) {
                return -1;
            }
            break;
        case HEADER_REPLY_SERIAL:
            if (sig.p[0] != TYPE_UINT32 || parse_uint32(&data, &serial)) {
                return -1;
            }
            f->reply_serial = serial;
            break;
        case HEADER_UNIX_FDS:
            if (sig.p[0] != TYPE_UINT32 || parse_uint32(&data, &f->fdnum)) {
                return -1;
            }
            break;
        }
    }
    
    return 0;
}
