#pragma once
#ifdef _WIN32
#include "lib/windows.h"
#include <assert.h>
#include <time.h>

// Use defines to override these functions
// That way we don't get compile errors if they are provided, but we still use
// our versions for consistency.
#undef mtx_plain
#undef thrd_success
#undef thrd_error
#undef thrd_timeout
#undef TIME_UTC
#define mtx_plain 0
#define thrd_success 0
#define thrd_error -1
#define thrd_timedout -2
#define TIME_UTC 0
#define mtx_t CRITICAL_SECTION
#define cnd_t CONDITION_VARIABLE
#define thrd_t HANDLE
#define mtx_init x_mtx_init
#define mtx_destroy x_mtx_destroy
#define mtx_lock x_mtx_lock
#define mtx_unlock x_mtx_unlock
#define cnd_init x_cnd_init
#define cnd_destroy x_cnd_destroy
#define cnd_signal x_cnd_signal
#define cnd_broadcast x_cnd_broadcast
#define cnd_wait x_cnd_wait
#define cnd_timedwait x_cnd_timedwait
#define timespec_get x_timespec_get

static inline int x_mtx_init(mtx_t *m, int type)
{
	assert(type == mtx_plain);
	InitializeCriticalSection(m);
	return thrd_success;
}

static inline void x_mtx_destroy(mtx_t *m)
{
	DeleteCriticalSection(m);
}

static inline int x_mtx_lock(mtx_t *m)
{
	EnterCriticalSection(m);
	return thrd_success;
}

static inline int x_mtx_unlock(mtx_t *m)
{
	LeaveCriticalSection(m);
	return thrd_success;
}

static inline int x_cnd_init(cnd_t *c)
{
	InitializeConditionVariable(c);
	return thrd_success;
}

static inline void x_cnd_destroy(cnd_t *c)
{
}

static inline int x_cnd_signal(cnd_t *c)
{
	WakeConditionVariable(c);
	return thrd_success;
}

static inline int x_cnd_broadcast(cnd_t *c)
{
	WakeAllConditionVariable(c);
	return thrd_success;
}

static inline int x_cnd_wait(cnd_t *c, mtx_t *m)
{
	return SleepConditionVariableCS(c, m, INFINITE) ? thrd_success :
							  thrd_error;
}

int x_cnd_timedwait(cnd_t *c, mtx_t *m, const struct timespec *ts);

int x_timespec_get(struct timespec *ts, int basis);

#endif