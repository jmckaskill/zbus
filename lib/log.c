#include "log.h"

void log_message(const struct message *m)
{
	log_uint("type", m->type);
	log_hex("serial", m->serial);
	if (m->flags) {
		log_hex("flags", m->flags);
	}
	if (m->sender.len) {
		log_slice("src", m->sender);
	}
	if (m->destination.len) {
		log_slice("dst", m->destination);
	}
	if (m->path.len) {
		log_slice("path", m->path);
	}
	if (m->interface.len) {
		log_slice("iface", m->interface);
	}
	if (m->member.len) {
		log_slice("member", m->member);
	}
	if (m->reply_serial) {
		log_hex("reply", m->reply_serial);
	}
	if (m->error.len) {
		log_slice("error", m->error);
	}
	if (m->fdnum) {
		log_uint("fdnum", m->fdnum);
	}
	if (*m->signature) {
		log_cstring("sig", m->signature);
	}
}
