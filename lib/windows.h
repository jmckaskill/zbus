#pragma once
#undef ERROR
#include <windows.h>
#undef ERROR
#undef interface
#define ERROR(...) flog(LOG_ERROR, __VA_ARGS__)
