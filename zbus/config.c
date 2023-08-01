#define _GNU_SOURCE
#include "config.h"
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

struct readbuf {
	size_t off;
	size_t have;
	char buf[256];
};

static int get_line(struct readbuf *b, int fd, slice_t *pline)
{
	if (b->have == SIZE_MAX) {
		return 1;
	}
	for (;;) {
		slice_t rest;
		slice_t in = make_slice(b->buf + b->off, b->have - b->off);
		if (!split_slice(in, '\n', pline, &rest)) {
			b->off = rest.p - b->buf;
			return 0;
		}

		if (b->off == b->have) {
			// overlong line
			return -1;
		}

		// compress
		if (b->off) {
			memmove(b->buf, b->buf + b->off, b->have - b->off);
			b->have -= b->off;
			b->off = 0;
		}

		// and read some more
		int r = read(fd, b->buf + b->have, sizeof(b->buf) - b->have);
		if (r < 0 && errno == EINTR) {
			continue;
		} else if (r < 0) {
			return -1;
		} else if (r == 0 && in.len) {
			// No trailing newline. Take the rest of the buffer as
			// the line.
			b->have = SIZE_MAX;
			b->off = b->have;
			*pline = in;
			return 0;
		} else if (r == 0) {
			return 1;
		}

		// Have more data. Let's reparse
		b->have += r;
	}
}

static bool is_space(char ch)
{
	return ch == ' ' || ch == '\t' || ch == '\r';
}

static slice_t trim_left_space(slice_t s)
{
	while (s.len && is_space(s.p[0])) {
		s.p++;
		s.len--;
	}
	return s;
}

static slice_t trim_right_space(slice_t s)
{
	while (s.len && is_space(s.p[s.len - 1])) {
		s.len--;
	}
	return s;
}

static slice_t trim_space(slice_t s)
{
	return trim_left_space(trim_right_space(s));
}

struct config_item {
	struct {
		char len;
		char p[255];
	} section;
};

static int get_config_item(struct readbuf *b, int fd, struct config_item *ci)
{
}

static int parse_config(struct bus *b, int fd, slice_t name)
{
	struct readbuf buf;
	buf.have = 0;
	buf.off = 0;
}

int load_config(struct bus *b, const char *dir)
{
	int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0) {
		start_error("failed to open config directory", errno);
		log_cstring("dir", dir);
		finish_log();
		return -1;
	}

	DIR *d = fdopendir(dfd);
	if (!d) {
		close(dfd);
		return -1;
	}

	int err = 0;
	struct dirent *e;
	while (!err && (e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.' || e->d_type == DT_DIR) {
			continue;
		}
		slice_t fn = cstr_slice(e->d_name);
		if (!slice_has_suffix(fn, S(".service"))) {
			continue;
		}
		slice_t name = make_slice(fn.p, fn.len - strlen(".service"));
		int fd = openat(dfd, fn.p, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			start_error("failed to open config file", errno);
			log_cstring("dir", dir);
			log_slice("file", fn);
			finish_log();
			continue;
		}

		err = parse_config(b, fd, name);
		close(fd);
	}

	closedir(d);
	return err;
}
