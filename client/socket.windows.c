#include "socket.h"

#ifdef _WIN32
#include "lib/windows.h"
#include "lib/log.h"
#include "lib/print.h"
#include "lib/pipe.windows.h"
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

int sys_send(fd_t fd, const char *buf, int sz)
{
	DWORD n;
	return WriteFile((HANDLE)fd, buf, sz, &n, NULL) ? n : -1;
}

int sys_recv(fd_t fd, char *buf, int sz)
{
	DWORD n;
	if (ReadFile((HANDLE)fd, buf, sz, &n, NULL)) {
		struct logbuf b;
		if (start_debug(&b, "read")) {
			log_int(&b, "fd", (unsigned)fd);
			log_bytes(&b, "data", buf, n);
			finish_log(&b);
		}
		return n;
	} else if (GetLastError() == ERROR_HANDLE_EOF) {
		ERROR("recv early EOF,fd:%u", (unsigned)fd);
		return 0;
	} else {
		ERROR("recv,errno:%m,fd:%u", (unsigned)fd);
		return -1;
	}
}

void sys_close(fd_t fd)
{
	CloseHandle((HANDLE)fd);
}

int sys_open(fd_t *pfd, const char *mapname)
{
	struct winmmap map;
	wchar_t *wmapname = utf16dup(mapname);
	int err = open_win_pipename(&map, wmapname);
	free(wmapname);
	if (err) {
		return -1;
	}
	char pipename[256];
	int sz = read_win_pipename(&map, pipename, sizeof(pipename));
	unmap_win_pipename(&map);
	if (sz <= 0) {
		return -1;
	}

	for (;;) {
		HANDLE h = CreateFileA(pipename, GENERIC_READ | GENERIC_WRITE,
				       0, NULL, OPEN_EXISTING, 0, NULL);
		if (h != INVALID_HANDLE_VALUE) {
			*pfd = (uintptr_t)h;
			return 0;
		} else if (GetLastError() != ERROR_PIPE_BUSY) {
			return -1;
		}

		if (!WaitNamedPipeA(pipename, NMPWAIT_USE_DEFAULT_WAIT)) {
			return -1;
		}
	}
}

char *sys_userid(char *buf, size_t sz)
{
	HANDLE tok;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tok)) {
		FATAL("failed to open token,errno:%m");
	}

	DWORD osz;
	if (GetTokenInformation(tok, TokenUser, NULL, 0, &osz) ||
	    GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		FATAL("failed to get sid,errno:%m");
	}

	TOKEN_USER *u = fmalloc(osz);
	if (!GetTokenInformation(tok, TokenUser, u, osz, &osz)) {
		FATAL("failed to get sid,errno:%m");
	}

	char *sid;
	if (!ConvertSidToStringSidA(u->User.Sid, &sid)) {
		FATAL("failed to convert sid to string,errno:%m");
	}

	size_t len = strlen(sid);
	if (len + 1 > sz) {
		FATAL("SID too long for buffer,sid:%s", sid);
	}
	memcpy(buf, sid, len + 1);
	LocalFree(sid);
	free(u);
	CloseHandle(tok);

	return buf;
}

#endif
