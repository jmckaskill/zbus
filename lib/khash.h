#pragma once
#include "log.h"

#define kcalloc(N,Z) fcalloc(N,Z)
#define kmalloc(Z) fmalloc(Z)
#define krealloc(P,Z) frealloc(P,Z)

#include "vendor/klib-master/khash.h"
