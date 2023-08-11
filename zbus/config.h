#pragma once

#ifdef _WIN32
#define HAVE_SID
#elif defined __linux__
#define HAVE_PROC_GROUPS
#define HAVE_GID
#define HAVE_UID
#define HAVE_ACCEPT4
#endif

#undef HAVE_ACCEPT4
#undef HAVE_SOCKFD
#undef HAVE_READY_FIFO
#undef HAVE_MEMRCHR
#define HAVE__STRICMP
#define HAVE__STRDUP
#undef HAVE_ALIGNED_ALLOC
#define HAVE_AUTOLAUNCH
