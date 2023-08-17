#define _CRT_SECURE_NO_DEPRECATE
#include "config.h"
#include "lib/windows.h"
#include "lib/log.h"
#include "lib/print.h"
#include "lib/pipe.windows.h"
#include "vendor/getopt-master/getopt.h"
#include <stdio.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>

#ifdef HAVE_WCSDUP
#define x_wcsdup wcsdup
#else
#define x_wcsdup _wcsdup
#endif

static int usage()
{
	fputs("usage: zbus-launch [-c command] shm-name\n", stderr);
	return 2;
}

int main(void)
{
	char **argv;
	int argc = utf8argv(GetCommandLineW(), &argv);
	char *command = strdup("zbus.exe -autoexit=true");
	int i;
	while ((i = getopt(argc, argv, "c:h")) > 0) {
		switch (i) {
		case 'c':
			command = optarg;
			break;
		case 'h':
		case '?':
			return usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc != 1) {
		fputs("incorrect arguments\n", stderr);
		return usage();
	}

	const char *shmfn = argv[0];

	struct winmmap map;
	int err = create_win_pipename(&map, shmfn);
	if (err == MAP_WIN_CREATED) {
		// we created the mapping, let's launch the daemon

		PROCESS_INFORMATION pi;
		STARTUPINFOA si;
		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdInput = INVALID_HANDLE_VALUE;
		si.hStdOutput = INVALID_HANDLE_VALUE;
		si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
		if (!CreateProcessA(NULL, command, NULL /*proc attributes*/,
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
