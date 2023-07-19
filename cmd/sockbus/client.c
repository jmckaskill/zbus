#include "lib/bus.h"
#include "lib/message.h"
#include "lib/str.h"
#include "lib/log.h"
#include <sys/un.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <stddef.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>

static const char *busdir = "/run/user/1000/dbus-2";
static int last_serial;

static int usage()
{
	fprintf(stderr, "sockbus [opts] destination\n");
	fprintf(stderr, "  -v         verbose logging\n");
	fprintf(stderr, "  -d dir     bus directory\n");
	return 2;
}

int main(int argc, char *argv[])
{
	for (;;) {
		int i = getopt(argc, argv, "hvd:");
		if (i < 0) {
			break;
		}
		switch (i) {
		case 'v':
			verbose = 1;
			break;
		case 'd':
			busdir = optarg;
			break;
		case 'h':
		case '?':
			return usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		fprintf(stderr, "missing arguments\n");
		return usage();
	}

	slice_t destination = make_slice(argv[0]);

	char addr[256];
	int fd = bind_unique_address(busdir, -1, -1, -1, addr, sizeof(addr));

	if (fd < 0) {
		return 5;
	}

	struct message req;
	init_message(&req, MSG_METHOD, ++last_serial);
	req.sender = make_slice(addr);
	req.interface = make_slice("org.freedesktop.DBus.Peer");
	req.path = make_slice("/");
	req.member = make_slice("Ping");

	char buf[1024];
	int sz = end_message(start_message(&req, buf, sizeof(buf)));

	if (sz < 0 || blocking_send(fd, busdir, destination, buf, sz, NULL)) {
		return 5;
	}

	struct message reply;
	struct iterator body;
	do {
		if (recv_message(fd, buf, sizeof(buf), &req, &body, NULL)) {
			return 5;
		}
	} while (!is_reply(&req, &reply));

	dlog("have response %d %s", req.serial, req.error.p);

	close(fd);

	str_t s = MAKE_STR(buf);
	str_add(&s, busdir);
	str_add(&s, "/");
	if (!str_add(&s, addr)) {
		unlink(s.p);
	}

	return 0;
}
