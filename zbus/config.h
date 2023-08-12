#pragma once

#ifdef _WIN32
#define HAVE_SID 1
#define HAVE_LISTENFD 0
#define HAVE_MEMRCHR 0
#define HAVE_ALIGNED_ALLOC 0
#define HAVE_AUTOLAUNCH 1
#define HAVE_READY_FIFO 0
#elif defined __linux__
#define HAVE_PROC_GROUPS 1
#define HAVE_GID 1
#define HAVE_UID 1
#define HAVE_SID 0
#define HAVE_ACCEPT4 1
#define HAVE_LISTENFD 1
#define HAVE_MEMRCHR 1
#define HAVE_ALIGNED_ALLOC 1
#define HAVE_AUTOLAUNCH 1
#define HAVE_READY_FIFO 1
#endif
