#include "config.h"
#include "bus.h"
#include "lib/windows.h"
#include "lib/log.h"
#include "lib/print.h"
#include "lib/pipe.windows.h"
#include <stdatomic.h>
#include <stdio.h>

#if CAN_AUTOSTART
static mtx_t g_child_lk;
// count is increased by sys_launch within bus lock
// count is decreased by child_watcher
static DWORD g_nchild;
static HANDLE g_child_handles[MAXIMUM_WAIT_OBJECTS];
static zb_str8 *g_child_names[MAXIMUM_WAIT_OBJECTS];

struct child_info {
	struct child_info *prev;
};

static DWORD WINAPI child_watcher(void *udata)
{
	struct bus *b = udata;
	for (;;) {
		mtx_lock(&g_child_lk);
		DWORD num = g_nchild;
		mtx_unlock(&g_child_lk);

		DWORD n = WaitForMultipleObjects(num, g_child_handles, FALSE,
						 INFINITE);
		if (n > num) {
			FATAL("child watcher wait failed,errno:%m");
			return 1;
		}
		if (n == 0) {
			// wakeup from sys_launch that the number of children
			// has changed
			continue;
		}
		CloseHandle(g_child_handles[n]);
		zb_str8 *name = g_child_names[n];

		mtx_lock(&g_child_lk);
		memmove(g_child_names + n, g_child_names + n + 1,
			(g_nchild - n - 1) * sizeof(g_child_names[0]));
		memmove(g_child_handles + n, g_child_handles + n + 1,
			(g_nchild - n - 1) * sizeof(g_child_handles[0]));
		g_nchild--;
		mtx_unlock(&g_child_lk);

		service_exited(b, name);
		free(name);
	}
}

static int start_childwatcher(struct bus *b)
{
	mtx_init(&g_child_lk, mtx_plain);
	g_child_handles[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
	g_nchild = 1;
	HANDLE h = CreateThread(NULL, 0, &child_watcher, b, 0, NULL);
	CloseHandle(h);
	return h == INVALID_HANDLE_VALUE;
}

int sys_launch(struct bus *bus, const struct address *addr)
{
	BOOL ok = FALSE;
	wchar_t *wexec = utf16dup(addr->cfg->exec);
	zb_str8 *namedup = fmalloc(sizeof(*namedup) + addr->name.len);
	zb_copy_str8(namedup, &addr->name);

	mtx_lock(&g_child_lk);
	bool overflow = (g_nchild == MAXIMUM_WAIT_OBJECTS);
	mtx_unlock(&g_child_lk);
	if (overflow) {
		goto out;
	}

	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = INVALID_HANDLE_VALUE;
	si.hStdOutput = INVALID_HANDLE_VALUE;
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	ok = CreateProcessW(NULL, wexec, NULL, NULL, TRUE, DETACHED_PROCESS,
			    NULL, NULL, &si, &pi);
	if (!ok) {
		goto out;
	}
	CloseHandle(pi.hThread);

	// add child to list for the child watcher
	mtx_lock(&g_child_lk);
	g_child_handles[g_nchild] = pi.hProcess;
	g_child_names[g_nchild++] = namedup;
	namedup = NULL;
	mtx_unlock(&g_child_lk);

	// wake up the child_watcher so it can grab the new list
	SetEvent(g_child_handles[0]);

out:
	free(wexec);
	free(namedup);
	return !ok;
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
	if (args.num + argc >= MAX_ARGUMENTS) {
		fputs("too many arguments\n", stderr);
		return 2;
	}

	if (parse_argv(&args, argc, argv)) {
		return usage();
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

#if CAN_AUTOSTART
	if (start_childwatcher(&b)) {
		FATAL("failed to start child watcher thread,errno:%m");
	}
#endif

	if (d->config->type) {
		wchar_t *type = utf16dup(d->config->type);
		SetEnvironmentVariableW(L"DBUS_STARTER_BUS_TYPE", type);
		free(type);
	}

	if (d->config->address) {
		wchar_t *addr = utf16dup(d->config->address);
		SetEnvironmentVariableW(L"DBUS_STARTER_ADDRESS", addr);
		free(addr);
	}

	if (write_win_pipename(&m, pipename)) {
		FATAL("failed to write pipename mapping");
	}

	run_bus(&b, hpipe, pipename, c->autoexit);

	return 0;
}
