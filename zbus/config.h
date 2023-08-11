#pragma once

#ifdef _WIN32
#define HAVE_SID
#undef HAVE_ACCEPT4
#undef HAVE_SOCKFD
#undef HAVE_READY_FIFO
#undef HAVE_MEMRCHR
#define HAVE__STRICMP
#define HAVE__STRDUP
#undef HAVE_ALIGNED_ALLOC
#define HAVE_AUTOLAUNCH
#elif defined __linux__
#define _GNU_SOURCE
#define HAVE_PROC_GROUPS
#define HAVE_GID
#define HAVE_UID
#define HAVE_ACCEPT4
#define HAVE_LISTENFD
#define HAVE_MEMRCHR
#define HAVE_ALIGNED_ALLOC
#define HAVE_AUTOLAUNCH
#define HAVE_READY_FIFO
#endif

