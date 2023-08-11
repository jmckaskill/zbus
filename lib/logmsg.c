#include "logmsg.h"

void log_message(struct logbuf *b, const struct message *m)
{
	log_uint(b, "type", m->type);
	log_hex(b, "serial", m->serial);
	if (m->flags) {
		log_hex(b, "flags", m->flags);
	}
	if (m->sender) {
		log_string8(b, "src", m->sender);
	}
	if (m->destination) {
		log_string8(b, "dst", m->destination);
	}
	if (m->path) {
		log_string8(b, "path", m->path);
	}
	if (m->interface) {
		log_string8(b, "iface", m->interface);
	}
	if (m->member) {
		log_string8(b, "member", m->member);
	}
	if (m->reply_serial) {
		log_hex(b, "reply", m->reply_serial);
	}
	if (m->error) {
		log_string8(b, "error", m->error);
	}
	if (m->fdnum) {
		log_uint(b, "fdnum", m->fdnum);
	}
	if (*m->signature) {
		log_cstring(b, "sig", m->signature);
	}
}
