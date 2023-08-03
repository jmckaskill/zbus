#include "log.h"

void log_message(struct logbuf *b, const struct message *m)
{
	log_uint(b, "type", m->type);
	log_hex(b, "serial", m->serial);
	if (m->flags) {
		log_hex(b, "flags", m->flags);
	}
	if (m->sender.len) {
		log_slice(b, "src", m->sender);
	}
	if (m->destination.len) {
		log_slice(b, "dst", m->destination);
	}
	if (m->path.len) {
		log_slice(b, "path", m->path);
	}
	if (m->interface.len) {
		log_slice(b, "iface", m->interface);
	}
	if (m->member.len) {
		log_slice(b, "member", m->member);
	}
	if (m->reply_serial) {
		log_hex(b, "reply", m->reply_serial);
	}
	if (m->error.len) {
		log_slice(b, "error", m->error);
	}
	if (m->fdnum) {
		log_uint(b, "fdnum", m->fdnum);
	}
	if (*m->signature) {
		log_cstring(b, "sig", m->signature);
	}
}
