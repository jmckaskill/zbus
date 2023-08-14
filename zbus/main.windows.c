#include "config.h"
#include "bus.h"
#include "lib/windows.h"
#include "lib/log.h"
#include "lib/print.h"
#include "lib/pipe.windows.h"
#include <stdatomic.h>
#include <stdio.h>

#if ENABLE_AUTOSTART
int sys_launch(struct bus *bus, const str8_t *name, char *exec)
{
	return -1;
}
#endif

static int create_pipe(HANDLE *phandle, const char *pipename, bool first)
{
	*phandle = CreateNamedPipeA(
		pipename,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
			(first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
			PIPE_REJECT_REMOTE_CLIENTS,
		PIPE_UNLIMITED_INSTANCES, 1024 * 1024, 1024 * 1024,
		0 /*default timeout*/, NULL);
	return *phandle == INVALID_HANDLE_VALUE || *phandle == NULL;
}

static wchar_t *load_pipe_name(const char *sockpn)
{
	static const wchar_t pfx[] = L"\\\\.\\pipe\\";
	static const size_t pfxlen = sizeof(pfx) - 1;
	size_t pnlen = strlen(sockpn);
	wchar_t *ret = fmalloc(sizeof(pfx) + UTF16_SPACE(pnlen) + 2);
	memcpy(ret, pfx, sizeof(pfx));
	wchar_t *nul = utf8_to_utf16(ret + wcslen(pfx), sockpn, pnlen);
	*nul = L'\0';
	return ret;
}

static atomic_int g_num_threads;

static DWORD WINAPI rx_thread(void *udata)
{
	struct rx *r = udata;
	run_rx(r);
	atomic_fetch_sub_explicit(&g_num_threads, 1, memory_order_release);
	return 0;
}

static void start_remote_thread(struct bus *b, HANDLE pipe, int id)
{
	LOG("have connection,fd:%u,id:%d", (unsigned)(uintptr_t)pipe, id);
	struct rx *rx = new_rx(b, id);
	win_init_rxconn(&rx->conn, pipe);
	win_init_txconn(&rx->tx->conn, pipe);

	atomic_fetch_add_explicit(&g_num_threads, 1, memory_order_relaxed);
	HANDLE thrd = CreateThread(NULL, 0, &rx_thread, rx, 0, NULL);
	if (thrd == INVALID_HANDLE_VALUE) {
		FATAL("failed to launch rx thread");
	}
	CloseHandle(thrd);
}

static void autoexit_check()
{
	if (atomic_load_explicit(&g_num_threads, memory_order_acquire) == 0) {
		VERBOSE("autoexit");
		exit(0);
	}
}

static void run_bus(struct bus *b, HANDLE hpipe, const char *pipename,
		    bool autoexit)
{
	OVERLAPPED ol;
	memset(&ol, 0, sizeof(ol));
	ol.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	int next_id = 1;
	DWORD timeout = autoexit ? 5000 : INFINITE;

	for (;;) {
		if (ConnectNamedPipe(hpipe, &ol)) {
			VERBOSE("synchronous connect pipe,pipe:%s", pipename);
		} else if (GetLastError() == ERROR_IO_PENDING) {
			VERBOSE("waiting for connection,pipe:%s", pipename);
			while (WaitForSingleObject(ol.hEvent, timeout) ==
			       WAIT_TIMEOUT) {
				autoexit_check();
			}
		} else {
			FATAL("connect named pipe,errno:%m,pipe:%s", pipename);
		}

		HANDLE hnext;
		if (create_pipe(&hnext, pipename, false)) {
			FATAL("failed to create named pipe,errno:%m");
		}
		start_remote_thread(b, hpipe, next_id++);
		hpipe = hnext;
	}
}

static void add_default_config(struct config_arguments *args)
{
	static const wchar_t filename[] = L"zbus.ini";
	wchar_t buf[MAX_PATH];
	DWORD sz = GetModuleFileNameW(NULL, buf, sizeof(buf) - 1);
	buf[sz] = 0;
	wchar_t *slash = wcsrchr(buf, L'\\');
	if (slash == NULL || sz + sizeof(filename) > sizeof(buf)) {
		FATAL("failed to determine default config path");
	}
	memcpy(slash + 1, filename, sizeof(filename));
	args->v[args->num].key = "include";
	args->v[args->num].klen = strlen("include");
	args->v[args->num++].value = utf8dup(buf);
	VERBOSE("loading default config,path:%S", buf);
}

static int usage(void)
{
	fputs("usage: zbus [config] [--] [config-files]\n", stderr);
	fputs("\tCommand line config can be any of:\n", stderr);
	fputs("\t\t--key=value\n", stderr);
	fputs("\t\t--key value\n", stderr);
	fputs("\t\t-key=value\n", stderr);
	fputs("\t\t-key value\n", stderr);
	fputs("\t\t/key=value\n", stderr);
	fputs("\t\t/key value\n", stderr);
	fputs("\tAny arguments not prefixed with '-' or after '--' will be treated as config files\n",
	      stderr);
	return 2;
}

int wmain(int argc, wchar_t *wargv[])
{
	char **argv = utf8argv(argc, wargv);
	struct config_arguments args;
	args.num = 0;

	add_default_config(&args);

	bool more_options = true;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h") ||
		    !strcmp(argv[i], "/?") || !strcmp(argv[i], "/h")) {
			return usage();
		} else if (args.num == MAX_ARGUMENTS) {
			fputs("too many arguments", stderr);
			return 2;
		}
		if (!strcmp(argv[i], "--")) {
			more_options = false;
		} else if (more_options &&
			   (argv[i][0] == '-' || argv[i][0] == '/')) {
			char *key = argv[i] + 1;
			if (key[-1] == '-' && key[0] == '-') {
				// allow -foo=bar or --foo=bar
				key++;
			}
			size_t klen = strlen(key);
			char *eq = memchr(key, '=', klen);
			char *value;
			if (eq) {
				// --foo=bar or -foo=bar
				klen = eq - key;
				value = eq + 1;
			} else if (i == argc - 1) {
				fputs("expected argument\n", stderr);
				return 2;
			} else {
				// --foo bar or -foo bar
				value = argv[++i];
			}
			args.v[args.num].key = key;
			args.v[args.num].klen = klen;
			args.v[args.num++].value = value;
		} else {
			args.v[args.num].key = "include";
			args.v[args.num].klen = strlen("include");
			args.v[args.num++].value = argv[i];
		}
	}

	struct bus b;
	if (init_bus(&b) || load_config(&b, &args)) {
		return 1;
	}

	const struct rcu_data *d = rcu_root(b.rcu);
	const struct config *c = d->config;

	if (!c->listenpn) {
		ERROR("no shm name specified in config");
		return 1;
	}

	VERBOSE("bind,shm:%s", c->listenpn);
	wchar_t *mapname = utf16dup(c->listenpn);
	struct winmmap m;
	if (create_win_pipename(&m, mapname) < 0) {
		FATAL("failed to create pipename mapping,errno:%m,name:%S",
		      mapname);
	}
	free(mapname);

	char pipename[256];
	static const char pfx[] = "\\\\.\\pipe\\";
	memcpy(pipename, pfx, strlen(pfx));
	memcpy(pipename + strlen(pfx), b.busid.p, b.busid.len);
	pipename[strlen(pfx) + b.busid.len] = 0;

	HANDLE hpipe;
	if (create_pipe(&hpipe, pipename, true)) {
		FATAL("failed to create first named pipe,pipe:%s,errno:%m",
		      pipename);
	}

	if (write_win_pipename(&m, pipename)) {
		FATAL("failed to write pipename mapping");
	}

	run_bus(&b, hpipe, pipename, c->autoexit);

	return 0;
}
