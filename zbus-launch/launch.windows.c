#define _CRT_SECURE_NO_DEPRECATE
#include "config.h"
#include "lib/windows.h"
#include "lib/log.h"
#include "lib/print.h"
#include "lib/pipe.windows.h"
#include "vendor/getopt-master/wgetopt.h"
#include <stdio.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>

#if HAVE_WCSDUP
#define x_wcsdup wcsdup
#else
#define x_wcsdup _wcsdup
#endif

static int usage()
{
	fputs("usage: zbus-launch [-c command] shm-name\n", stderr);
	return 2;
}

int wmain(int argc, wchar_t *wargv[])
{
	wchar_t *command = x_wcsdup(L"zbus.exe -autoexit=true");
	int i;
	while ((i = wgetopt(argc, wargv, L"c:h")) > 0) {
		switch (i) {
		case L'c':
			command = optarg;
			break;
		case L'h':
		case L'?':
			return usage();
		}
	}

	argc -= optind;
	wargv += optind;
	if (argc != 1) {
		fputs("incorrect arguments\n", stderr);
		return usage();
	}

	const wchar_t *shmfn = wargv[0];

	struct winmmap map;
	int err = create_win_pipename(&map, shmfn);
	if (err == MAP_WIN_CREATED) {
		// we created the mapping, let's launch the daemon

		PROCESS_INFORMATION pi;
		STARTUPINFOW si;
		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdInput = INVALID_HANDLE_VALUE;
		si.hStdOutput = INVALID_HANDLE_VALUE;
		si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
		if (!CreateProcessW(NULL, command, NULL /*proc attributes*/,
				    NULL /*thread attributes*/,
				    TRUE /*inherit*/, DETACHED_PROCESS,
				    NULL /*environ*/, NULL /*cwd*/, &si, &pi)) {
			ERROR("create process,errno:%m");
		}
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	for (int i = 0; i < 20; i++) {
		char buf[256];
		int sz = read_win_pipename(&map, buf, sizeof(buf) - 1);
		if (sz > 0) {
			// daemon is up and running
			buf[sz] = '\n';
			fwrite(buf, 1, sz + 1, stdout);
			fflush(stdout);
			return 0;
		}
		// either the daemon is starting up or another launcher
		// is handling it. Spinwait for the daemon to come up.
		Sleep(100);
	}

	ERROR("timeout waiting for daemon to launch");
	return 1;
}
