#pragma once

// MSVC doesn't provide a <threads.h> so we provide our own
#ifdef _WIN32
#include "threads.windows.h"
#else
#include <threads.h>
#endif