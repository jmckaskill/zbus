#include "threads.h"

#ifdef _WIN32
#include <stdint.h>

int x_timespec_get(struct timespec *ts, int basis)
{
	uint64_t ms = GetTickCount64();
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
	return basis;
}

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

#endif
