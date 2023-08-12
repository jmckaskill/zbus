#include "config.h"

#ifdef _WIN32
#include "bus.h"
#include "lib/windows.h"
#include "lib/log.h"
#include "lib/print.h"

#pragma comment(lib, "advapi32.lib")

#define SVC_NAME L"ZBUS"

static SERVICE_STATUS_HANDLE g_service;

static void WINAPI SvcControl(DWORD control)
{
	SERVICE_STATUS st;
	memset(&st, 0, sizeof(st));

	switch (control) {
	case SERVICE_CONTROL_STOP:
		SetServiceStatus(g_service, &st);
		break;
	case SERVICE_CONTROL_INTERROGATE:
		break;
	default:
		break;
	}
}

static void WINAPI SvcMain(DWORD argv, const wchar_t *argc[])
{
	static const wchar_t logfn[] = L"zbus-log.txt";
	wchar_t path[MAX_PATH + sizeof(logfn) + 1];
	size_t len = GetTempPathW(MAX_PATH, path);
	memcpy(&path[len], logfn, sizeof(logfn));

	HANDLE log_fd = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
				    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (log_fd == INVALID_HANDLE_VALUE) {
		FATAL("unable to open log file,errno:%m");
	}
	SetFilePointer(log_fd, 0, NULL, FILE_END);
	g_log_fd = (intptr_t)log_fd;
	g_log_type = LOG_JSON;

	g_service = RegisterServiceCtrlHandlerW(SVC_NAME, &SvcControl);
	if (!g_service) {
		FATAL("failed to register service handler,errno:%m");
	}
}

static int install()
{
	wchar_t path[1 + MAX_PATH + sizeof("\" launcher")];
	path[0] = L'\"';
	size_t len = GetModuleFileNameW(NULL, path + 1, MAX_PATH);
	if (!len) {
		FATAL("failed to get exe location,errno:%m");
	}
	memcpy(path + 1 + len, L"\" launcher", sizeof(L"\" launcher"));

	SC_HANDLE sc = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!sc) {
		FATAL("failed to open service manager,errno:%m");
	}

	SC_HANDLE svc = CreateServiceW(sc, SVC_NAME, L"ZBUS Bus Daemon",
				       SERVICE_ALL_ACCESS,
				       SERVICE_WIN32_OWN_PROCESS,
				       SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
				       path, NULL, NULL, NULL,
				       NULL /*LocalSystem Account*/, L"");

	if (!svc) {
		FATAL("failed to install service,errno:%m");
	}

	LOG("installed service");

	CloseServiceHandle(svc);
	CloseServiceHandle(sc);
	return 0;
}

#if HAVE_AUTOLAUNCH
int sys_launch(struct bus *bus, const str8_t *name, char *exec)
{
	return -1;
}
#endif

static wchar_t *load_pipe_name(const str8_t *sockpn)
{
	static const wchar_t pfx[] = L"\\\\.\\pipe\\";
	static const size_t pfxlen = sizeof(pfx) - 1;
	wchar_t *ret = fmalloc(sizeof(pfx) + UTF16_SPACE(sockpn->len) + 2);
	memcpy(ret, pfx, sizeof(pfx));
	wchar_t *nul = utf8_to_utf16(ret + wcslen(pfx), sockpn->p, sockpn->len);
	*nul = L'\0';
	return ret;
}

static DWORD WINAPI rx_thread(void *udata)
{
	struct rx *r = udata;
	return run_rx(r);
}

static void start_remote_thread(struct bus *b, HANDLE pipe, int id)
{
	LOG("have connection,fd:%u,id:%d", (unsigned)(uintptr_t)pipe, id);
	struct rx *rx = new_rx(b, id);
	win_init_rxconn(&rx->conn, pipe);
	win_init_txconn(&rx->tx->conn, pipe);

	HANDLE thrd = CreateThread(NULL, 0, &rx_thread, rx, 0, NULL);
	if (thrd == INVALID_HANDLE_VALUE) {
		FATAL("failed to launch rx thread");
	}
	CloseHandle(thrd);
}

static void run_bus(const wchar_t *fn16)
{
	size_t len16 = wcslen(fn16);
	char *fn8 = fmalloc(UTF8_SPACE(len16) + 1);
	char *nul = utf16_to_utf8(fn8, fn16, len16);
	*nul = 0;

	struct config_arguments args;
	args.num = 1;
	args.v[0].cmdline = NULL;
	args.v[0].file = fn8;

	struct bus bus;
	if (init_bus(&bus) || load_config(&bus, &args)) {
		FATAL("failed to setup bus");
	}

	const struct rcu_data *d = rcu_root(bus.rcu);
	const struct config *c = d->config;
	wchar_t *pipename = load_pipe_name(c->sockpn);

	SECURITY_ATTRIBUTES sec;
	memset(&sec, 0, sizeof(sec));
	sec.nLength = sizeof(sec);
	sec.bInheritHandle = FALSE;

	OVERLAPPED ol;
	memset(&ol, 0, sizeof(ol));
	ol.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	int next_id = 1;

	for (;;) {
		HANDLE h = CreateNamedPipeW(
			pipename, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
			1 * 1024 * 1024, 1 * 1024 * 1024, 0, &sec);
		if (h == INVALID_HANDLE_VALUE) {
			FATAL("failed to create named pipe server,errno:%m");
		}

		if (ConnectNamedPipe(h, &ol)) {
			start_remote_thread(&bus, h, next_id++);
		} else if (GetLastError() == ERROR_IO_PENDING) {
			LOG("waiting for connection,pipe:%S", pipename);
			WaitForSingleObject(ol.hEvent, INFINITE);
			start_remote_thread(&bus, h, next_id++);
		} else {
			FATAL("connect named pipe,errno:%m");
		}
	}
}

int wmain(int argc, wchar_t *argv[])
{
	LOG("startup");

	if (argc < 2) {
		return 2;
	}

	if (!wcscmp(argv[1], L"install")) {
		return install();
	} else if (!wcscmp(argv[1], L"launcher")) {
		SERVICE_TABLE_ENTRYW dispatch[] = {
			{ SVC_NAME, &SvcMain },
			{ NULL, NULL },
		};

		if (!StartServiceCtrlDispatcherW(dispatch)) {
			FATAL("failed to start service dispatcher,errno:%m");
		}
		return 1;
	} else {
		// running in single bus mode, take the argument as the config
		// file path
		g_enable_security = false;
		g_log_level = LOG_DEBUG;
		run_bus(argv[1]);
		return 0;
	}
}
#endif
