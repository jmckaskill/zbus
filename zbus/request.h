#pragma once
#include "vector.h"

struct reqmap {
	struct vector hdr;
};

struct request {
	mtx_t lk;
};
