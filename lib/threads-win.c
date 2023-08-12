#include "threads.h"

#ifdef _WIN32

int x_cnd_timedwait(cnd_t *c, mtx_t *m, const struct timespec *ts)
{
	struct timespec now;
	timespec_get(&now, TIME_UTC);
	time_t secs = ts->tv_sec - now.tv_nsec;
	int nsecs = ts->tv_nsec - now.tv_nsec;
	if (secs < 0 || (secs == 0 && nsecs < 0)) {
		return thrd_timedout;
	}
	DWORD ms = (DWORD)(secs * 1000) + (nsecs / 1000000);
	if (SleepConditionVariableCS(c, m, ms)) {
		return thrd_success;
	}
	if (GetLastError() == ERROR_TIMEOUT) {
		return thrd_timedout;
	}
	return thrd_error;
}

struct winthread_data {
	int (*fn)(void *);
	void *udata;
};

static DWORD WINAPI winthread_start(void *p)
{
	struct winthread_data d = *(struct winthread_data *)p;
	free(p);
	return (DWORD)d.fn(d.udata);
}

int x_thrd_create(thrd_t *t, int (*fn)(void *), void *udata)
{
	struct winthread_data *d = malloc(sizeof(*d));
	d->fn = fn;
	d->udata = udata;
	*t = CreateThread(NULL, 0, &winthread_start, d, 0, NULL);
	return (*t == INVALID_HANDLE_VALUE) ? thrd_error : thrd_success;
}

int x_thrd_join(thrd_t t, int *res)
{
	if (WaitForSingleObject(t, INFINITE) != WAIT_OBJECT_0) {
		return thrd_error;
	}
	if (res) {
		DWORD dwres = INFINITE;
		GetExitCodeThread(t, &dwres);
		*res = dwres;
	}
	CloseHandle(t);
	return thrd_success;
}

int x_thrd_detach(thrd_t t)
{
	CloseHandle(t);
	return thrd_success;
}

#endif
