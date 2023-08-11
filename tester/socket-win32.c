#include "socket.h"

#ifdef _WIN32
#include "lib/windows.h"
#include "lib/log.h"
#include "lib/print.h"
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

int sys_open(fd_t *pfd, const char *sockpn)
{
	static const wchar_t pfx[] = L"\\.\\pipe\\";
	size_t len = strlen(sockpn);
	wchar_t *fn = fmalloc(sizeof(pfx) + UTF16_SPACE(len) + 2);
	memcpy(fn, pfx, sizeof(pfx));
	wchar_t *nul = utf8_to_utf16(fn + wcslen(pfx), sockpn, len);
	*nul = L'\0';
	for (;;) {
		HANDLE h = CreateFileW(fn, GENERIC_READ | GENERIC_WRITE, 0,
				       NULL, OPEN_EXISTING, 0, NULL);
		if (h != INVALID_HANDLE_VALUE) {
			*pfd = h;
			return 0;
		} else if (GetLastError() != ERROR_PIPE_BUSY) {
			return -1;
		}

		if (!WaitNamedPipeW(fn, NMPWAIT_USE_DEFAULT_WAIT)) {
			return -1;
		}
	}
}

char *sys_userid(char *buf, size_t sz)
{
	HANDLE tok;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY_SOURCE, TRUE,
			     &tok)) {
		FATAL("failed to open token,errno:%m");
	}

	TOKEN_OWNER o;
	DWORD osz;
	if (!GetTokenInformation(tok, TokenOwner, &o, sizeof(o), &osz) ||
	    osz != sizeof(o)) {
		FATAL("failed to get sid,errno:%m");
	}

	char *sid;
	if (!ConvertSidToStringSidA(o.Owner, &sid)) {
		FATAL("failed to convert sid to string,errno:%m");
	}

	size_t len = strlen(buf);
	if (len + 1 > sz) {
		FATAL("SID too long for buffer,sid:%s", sid);
	}
	memcpy(buf, sid, len + 1);
	LocalFree(sid);
	CloseHandle(tok);

	return buf;
}

#endif
