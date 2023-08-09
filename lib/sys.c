#define _GNU_SOURCE
#include "sys.h"
#include "log.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

int sys_slurp(const char *filename, char **pbuf, size_t *psz)
{
	char *buf = NULL;
	int fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ERROR("failed to open config file,filename:%s,errno:%m",
		      filename);
		goto error;
	}
	struct stat st;
	if (fstat(fd, &st)) {
		ERROR("failed to stat config file,filename:%s,errno:%m",
		      filename);
		goto error;
	}
	if (st.st_size > INT_MAX) {
		ERROR("file too large,filename:%s", filename);
		goto error;
	}
	buf = malloc(st.st_size + 1);
	if (!buf) {
		ERROR("failed to allocate buffer for config data,filename:%s",
		      filename);
		goto error;
	}
	int n = read(fd, buf, st.st_size);
	if (n < 0) {
		ERROR("read error,filename:%s,errno:%m", filename);
		goto error;
	} else if (n != st.st_size) {
		ERROR("short read,filename:%s,have:%d,expected:%d", filename, n,
		      (int)st.st_size);
		goto error;
	}

	buf[st.st_size] = 0;
	close(fd);
	*psz = st.st_size;
	*pbuf = buf;
	return 0;

error:
	free(buf);
	close(fd);
	return -1;
}

//////////////////////////
// Directory handling

#define MAX_FILENAME_LEN 256

struct sysdir {
	DIR *dir;
	size_t dlen;
	char path[0];
};

int sys_opendir(struct sysdir **pdir, const char *pn)
{
	size_t len = strlen(pn);
	if (!len) {
		return -1;
	}
	DIR *dir = opendir(pn);
	if (!dir) {
		return -1;
	}
	struct sysdir *d = fmalloc(sizeof(*d) + len + 1 + MAX_FILENAME_LEN + 1);
	d->dir = dir;
	if (pn[len - 1] == '/') {
		len--;
	}
	memcpy(d->path, pn, len);
	d->path[len++] = '/';
	d->dlen = len;
	*pdir = d;
	return 0;
}

const char *sys_nextfile(struct sysdir *d)
{
	struct dirent *e;
	while ((e = readdir(d->dir)) != NULL) {
		if (e->d_type == DT_DIR) {
			continue;
		}
		size_t len = strlen(e->d_name);
		if (len > MAX_FILENAME_LEN) {
			ERROR("filename too long:dir:%.*s,file:%s",
			      (int)d->dlen, d->path, e->d_name);
			return NULL;
		}
		memcpy(d->path + d->dlen, e->d_name, len);
		d->path[d->dlen + len] = 0;
		return d->path;
	}
	return NULL;
}

void sys_closedir(struct sysdir *d)
{
	if (d) {
		closedir(d->dir);
		free(d);
	}
}
