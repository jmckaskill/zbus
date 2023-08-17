#include "pipe.windows.h"
#include "windows.h"
#include <stdatomic.h>
#include <stdint.h>

union header {
	struct count_len {
		uint32_t counter;
		uint32_t length;
	} u32;
	uint64_t u64;
};

int create_win_pipename(struct winmmap *m, const char *name)
{
	SetLastError(0);
	HANDLE h = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
				      PAGE_READWRITE, 0, 256, name);
	if (h == INVALID_HANDLE_VALUE || h == NULL) {
		return MAP_WIN_ERROR;
	}
	int ret = (GetLastError() == ERROR_ALREADY_EXISTS) ? MAP_WIN_OK :
							     MAP_WIN_CREATED;
	void *ptr = MapViewOfFile(h, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 256);
	if (!ptr) {
		DWORD err = GetLastError();
		CloseHandle(h);
		SetLastError(err);
		return MAP_WIN_ERROR;
	}
	m->handle = h;
	m->data = ptr;
	m->sz = 256;
	return ret;
}

int open_win_pipename(struct winmmap *m, const char *name)
{
	HANDLE h = OpenFileMappingA(FILE_MAP_READ, FALSE, name);
	if (h == INVALID_HANDLE_VALUE || h == NULL) {
		return -1;
	}
	void *ptr = MapViewOfFile(h, FILE_MAP_READ, 0, 0, 256);
	if (!ptr) {
		DWORD err = GetLastError();
		CloseHandle(h);
		SetLastError(err);
		return -1;
	}
	m->handle = h;
	m->data = ptr;
	m->sz = 256;
	return 0;
}

void unmap_win_pipename(struct winmmap *m)
{
	UnmapViewOfFile(m->data);
	CloseHandle(m->handle);
}

int read_win_pipename(const struct winmmap *m, char *buf, size_t bufsz)
{
	_Atomic(uint64_t) *phdr = m->data;
	union header h;
	h.u64 = atomic_load_explicit(phdr, memory_order_acquire);
	if (sizeof(h) + h.u32.length > m->sz || h.u32.length + 1 > bufsz) {
		return -1;
	}
	memcpy(buf, (void *)(phdr + 1), h.u32.length);
	uint64_t after = atomic_load_explicit(phdr, memory_order_acquire);
	if (after != h.u64) {
		return -1;
	}
	buf[h.u32.length] = 0;
	return h.u32.length;
}

int write_win_pipename(const struct winmmap *m, const char *pipename)
{
	_Atomic(uint64_t) *phdr = m->data;
	union header h;

	size_t len = strlen(pipename);
	if (sizeof(*phdr) + len + 1 > m->sz) {
		return -1;
	}

	h.u64 = atomic_exchange_explicit(phdr, 0, memory_order_acq_rel);
	h.u32.length = (uint32_t)len;
	h.u32.counter++;
	memcpy((void *)(phdr + 1), pipename, len + 1);
	atomic_store_explicit(phdr, h.u64, memory_order_release);
	return 0;
}
