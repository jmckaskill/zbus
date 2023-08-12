#include "file.h"

#ifdef _WIN32
#include "log.h"
#include "print.h"
#include "windows.h"
#include <stdint.h>
#include <assert.h>
#include <limits.h>

union cw {
	char c[1];
	wchar_t w[1];
};

int sys_slurp(const char *filename, char **pbuf, size_t *psz)
{
	size_t len8 = strlen(filename);
	union cw *buf = fmalloc(sizeof(*buf) + UTF16_SPACE(len8));
	wchar_t *end = utf8_to_utf16(buf->w, filename, len8);
	*end = 0;
	HANDLE h = CreateFileW(buf->w, GENERIC_READ, FILE_SHARE_READ, NULL,
			       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		ERROR("failed to open file,file:%s,errno:%m", filename);
		goto error;
	}
	DWORD szhigh;
	DWORD sz = GetFileSize(h, &szhigh);
	if (szhigh || sz == INVALID_FILE_SIZE) {
		ERROR("file is too large,file:%s,errno:%m", filename);
		goto error;
	}
	union cw *newbuf = realloc(buf, sz + 1);
	if (!newbuf) {
		ERROR("failed to allocate buffer for file,file:%s,errno:%m",
		      filename);
		goto error;
	}
	buf = newbuf;
	DWORD read;
	if (!ReadFile(h, buf->c, sz, &read, NULL) || read != sz) {
		ERROR("failed to read file,file:%s,errno:%m");
		goto error;
	}
	CloseHandle(h);
	buf->c[sz] = 0;
	*pbuf = buf->c;
	*psz = sz;
	return 0;

error:
	free(buf);
	CloseHandle(h);
	return -1;
}

struct sysdir {
	HANDLE find;
	bool just_opened;
	size_t dirlen;
	union cw path;
};

int sys_opendir(struct sysdir **pd, const char *path)
{
	size_t dlen8 = strlen(path);
	struct sysdir *d =
		fmalloc(sizeof(*d) + UTF16_SPACE(dlen8) + 2 + (2 * MAX_PATH));
	wchar_t *w = utf8_to_utf16(d->path.w, path, dlen8);
	*w++ = L'\\';
	*w++ = L'*';
	*w++ = L'\0';

	WIN32_FIND_DATAW fd;
	d->find = FindFirstFileW(d->path.w, &fd);
	if (d->find == INVALID_HANDLE_VALUE) {
		ERROR("failed to open directory,dir:%s,errno:%m", path);
		free(d);
		return -1;
	}

	static_assert(sizeof(fd.cFileName) <= 2 * MAX_PATH, "");

	d->just_opened = true;
	memcpy(d->path.c, path, dlen8);
	d->path.c[dlen8] = '\\';
	d->dirlen = dlen8 + 1;
	char *c = utf16_to_utf8(d->path.c + d->dirlen, fd.cFileName,
				wcslen(fd.cFileName));
	*c = 0;
	return 0;
}

const char *sys_nextfile(struct sysdir *d)
{
	if (d->just_opened) {
		d->just_opened = false;
		return d->path.c;
	}
	WIN32_FIND_DATAW fd;
	if (!FindNextFileW(d->find, &fd)) {
		return NULL;
	}
	char *c = utf16_to_utf8(d->path.c + d->dirlen, fd.cFileName,
				wcslen(fd.cFileName));
	*c = 0;
	return d->path.c;
}

void sys_closedir(struct sysdir *d)
{
	if (d) {
		FindClose(d->find);
		free(d);
	}
}

#endif
