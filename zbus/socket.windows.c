#include "socket.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sddl.h>
#include <stdlib.h>
#include <stdatomic.h>

static int read_pipename(const char *shmname, char *buf, size_t bufsz)
{
	int ret = -1;
	void *ptr = NULL;
	HANDLE h = OpenFileMappingA(FILE_MAP_READ, FALSE, shmname);
	if (h == INVALID_HANDLE_VALUE || h == NULL) {
		return -1;
	}
	ptr = MapViewOfFile(h, FILE_MAP_READ, 0, 0, 256);
	if (!ptr) {
		goto out;
	}

	_Atomic(uint64_t) *phdr = ptr;
	uint64_t hdr = atomic_load_explicit(phdr, memory_order_acquire);
	uint32_t len = (uint32_t)(hdr >> 32);
	if (sizeof(hdr) + len > 256 || len + 1 > bufsz) {
		goto out;
	}
	memcpy(buf, (void *)(phdr + 1), len);
	buf[len] = 0;
	uint64_t after = atomic_load_explicit(phdr, memory_order_acquire);
	if (after != hdr) {
		// name is in process of being updated
		ret = 0;
		goto out;
	}
	ret = (int)len;

out:
	if (ptr) {
		UnmapViewOfFile(ptr);
	}
	CloseHandle(h);
	return ret;
}

static HANDLE open_named_pipe(const char *mapname)
{
	char pipename[256];
	int sz = read_pipename(mapname, pipename, sizeof(pipename));
	if (sz < 0) {
		return INVALID_HANDLE_VALUE;
	} else if (!sz) {
		// shared memory was being updated, let's try again
		Sleep(50);
		sz = read_pipename(mapname, pipename, sizeof(pipename));
		if (sz <= 0) {
			return INVALID_HANDLE_VALUE;
		}
	}

	// Now connect, WaitNamedPipe acts like a condition variable. It doesn't
	// guarantee that CreateFile will succeed.
	for (;;) {
		HANDLE h = CreateFileA(pipename, GENERIC_READ | GENERIC_WRITE,
				       0, NULL, OPEN_EXISTING, 0, NULL);
		if (h != INVALID_HANDLE_VALUE) {
			return h;
		} else if (GetLastError() != ERROR_PIPE_BUSY) {
			return INVALID_HANDLE_VALUE;
		}

		if (!WaitNamedPipeA(pipename, NMPWAIT_USE_DEFAULT_WAIT)) {
			return INVALID_HANDLE_VALUE;
		}
	}
}

static HANDLE open_tcp(int family, const char *host, const char *port)
{
	WSADATA wsadata;
	if (!WSAStartup(MAKEWORD(2, 2), &wsadata)) {
		return INVALID_HANDLE_VALUE;
	}

	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (getaddrinfo(host, port, &hints, &res)) {
		return INVALID_HANDLE_VALUE;
	}

	for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
		SOCKET fd = WSASocketW(
			ai->ai_family, ai->ai_socktype, ai->ai_protocol, NULL,
			0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
		if (fd == INVALID_SOCKET) {
			continue;
		}
		if (connect(fd, ai->ai_addr, (int)ai->ai_addrlen)) {
			closesocket(fd);
			continue;
		}
		freeaddrinfo(res);
		return (HANDLE)fd;
	}

	freeaddrinfo(res);
	return INVALID_HANDLE_VALUE;
}

int zb_connect(zb_handle_t *pfd, const char *address)
{
	size_t len = strlen(address);
	char *addr = memcpy(malloc(len + 1), address, len + 1);
	int err = -1;

	char *p = addr;
	for (;;) {
		const char *type, *host, *port;
		int n = zb_parse_address(p, &type, &host, &port);
		if (n < 0) {
			goto out;
		}
		p += n;

		// Want to find the first address that we understand and can
		// connect with.
		HANDLE fd = INVALID_HANDLE_VALUE;
		if (!strcmp(type, "winpipe")) {
			fd = open_named_pipe(host);
		} else if (!strcmp(type, "tcp")) {
			fd = open_tcp(AF_UNSPEC, host, port);
		} else if (!strcmp(type, "tcp4")) {
			fd = open_tcp(AF_INET, host, port);
		} else if (!strcmp(type, "tcp6")) {
			fd = open_tcp(AF_INET6, host, port);
		}

		if (fd != INVALID_HANDLE_VALUE) {
			*pfd = fd;
			err = 0;
			goto out;
		}
	}

out:
	free(addr);
	return err;
}

void zb_close(zb_handle_t fd)
{
	CloseHandle(fd);
}

int zb_send(zb_handle_t fd, const void *buf, size_t sz)
{
	DWORD n;
	return WriteFile(fd, buf, (DWORD)sz, &n, NULL) ? n : -1;
}

int zb_recv(zb_handle_t fd, void *buf, size_t sz)
{
	DWORD n;
	if (ReadFile((HANDLE)fd, buf, (DWORD)sz, &n, NULL)) {
		return n;
	} else if (GetLastError() == ERROR_HANDLE_EOF) {
		return 0;
	} else {
		return -1;
	}
}

char *zb_userid(char *buf, size_t sz)
{
	char *sid = NULL;
	TOKEN_USER *u = NULL;
	HANDLE tok = INVALID_HANDLE_VALUE;
	char *ret = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tok)) {
		goto out;
	}

	DWORD osz;
	if (GetTokenInformation(tok, TokenUser, NULL, 0, &osz) ||
	    GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		goto out;
	}

	u = malloc(osz);
	if (!GetTokenInformation(tok, TokenUser, u, osz, &osz)) {
		goto out;
	}

	if (!ConvertSidToStringSidA(u->User.Sid, &sid)) {
		goto out;
	}

	size_t len = strlen(sid);
	if (len + 1 > sz) {
		goto out;
	}
	memcpy(buf, sid, len + 1);
	ret = buf;

out:
	LocalFree(sid);
	free(u);
	CloseHandle(tok);

	return ret;
}

#endif
