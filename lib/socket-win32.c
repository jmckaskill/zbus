#include "socket-win32.h"

#ifdef _WIN32
void close_rx(struct rxconn *c)
{
	CloseHandle(c->ol.hEvent);
}

void close_tx(struct txconn *c)
{
	CloseHandle(c->ol.hEvent);
	CloseHandle(c->h);
}

int block_recv1(struct rxconn *c, char *p, int n)
{
	DWORD read;
	if (ReadFile(c->h, p, n, &read, &c->ol)) {
		return (int)read;
	}
	switch (GetLastError()) {
	case ERROR_BROKEN_PIPE:
	case ERROR_HANDLE_EOF:
		return 0;
	case ERROR_IO_PENDING:
		break;
	default:
		return -1;
	}

	if (GetOverlappedResult(c->h, &c->ol, &read, TRUE)) {
		return (int)read;
	}
	switch (GetLastError()) {
	case ERROR_BROKEN_PIPE:
	case ERROR_HANDLE_EOF:
		return 0;
	default:
		return -1;
	}
}

int start_send1(struct txconn *c, char *p, int n)
{
	DWORD write;
	if (WriteFile(c->h, p, n, &write, &c->ol)) {
		return (int)write;
	}
	switch (GetLastError()) {
	case ERROR_IO_PENDING:
		return 0;
	default:
		return -1;
	}
}

int finish_send(struct txconn *c, mtx_t *lk)
{
	mtx_unlock(lk);
	DWORD write;
	BOOL res = GetOverlappedResult(c->h, &c->ol, &write, TRUE);
	mtx_lock(lk);
	return res ? (int)write : -1;
}

void cancel_send(struct txconn *c)
{
	CancelIoEx(c->h, &c->ol);
}
#endif
